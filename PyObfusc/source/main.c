//
//  main.c
//  PyObfusc
//
//  Created by muken on 2025/12/1.
//

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <cpython/code.h>
#include <opcode.h>
#include "mk_print.h"
#include <openssl/evp.h>
#include <openssl/err.h>

static const char *fixed_runtime_path = FIXED_RUNTIME_PATH;
static const char *version = "v0.1.0";

// WARNING: This is an example key for demonstration only.
// DO NOT use this key in production!
// Generate your own 256-bit (32-byte) key securely.
static const unsigned char AES_KEY[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const unsigned char AES_IV[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} StringSet;

void set_init(StringSet *set) {
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

int set_contains(StringSet *set, const char *path) {
    for (size_t i = 0; i < set->count; ++i) {
        if (strcmp(set->items[i], path) == 0) return 1;
    }
    return 0;
}

void set_add(StringSet *set, const char *path) {
    if (set_contains(set, path)) return;
    if (set->count >= set->capacity) {
        set->capacity = (set->capacity == 0) ? 8 : set->capacity * 2;
        set->items = realloc(set->items, set->capacity * sizeof(char *));
    }
    set->items[set->count++] = strdup(path);
}

void set_free(StringSet *set) {
    for (size_t i = 0; i < set->count; ++i) {
        free(set->items[i]);
    }
    free(set->items);
}

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} StringList;

void list_init(StringList *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void list_push(StringList *list, const char *path) {
    if (list->count >= list->capacity) {
        list->capacity = (list->capacity == 0) ? 8 : list->capacity * 2;
        list->items = realloc(list->items, list->capacity * sizeof(char *));
    }
    list->items[list->count++] = strdup(path);
}

void list_free(StringList *list) {
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i]);
    }
    free(list->items);
}

// collect .py files
void collect_py_files(const char *root, const char *current, StringList *files) {
    DIR *dir = opendir(current);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (strncmp(entry->d_name, ".", 1) == 0) continue;
        if (strstr(entry->d_name, "__pycache__")) continue;

        size_t full_len = strlen(current) + strlen(entry->d_name) + 2;
        char *full_path = malloc(full_len);
        snprintf(full_path, full_len, "%s/%s", current, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                collect_py_files(root, full_path, files);
            } else if (S_ISREG(st.st_mode)) {
                size_t len = strlen(entry->d_name);
                if (len > 3 && strcmp(entry->d_name + len - 3, ".py") == 0) {
                    const char *rel = full_path + strlen(root);
                    if (*rel == '/') rel++;
                    list_push(files, rel);
                }
            }
        }
        free(full_path);
    }
    closedir(dir);
}

// read file
char *read_file(const char *filename) {
    if (!filename) return NULL;
    FILE* fp = fopen(filename, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buffer = (char *)malloc((size_t)size + 1);
    if (!buffer) { fclose(fp); return NULL; }
    if (fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        free(buffer); fclose(fp); return NULL;
    }
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

int run_command(const char *cmd) {
    return system(cmd);
}

void remove_directory(const char *path) {
    size_t cmd_len = strlen(path) + 64;
    char *cmd = (char *)malloc(cmd_len);
    snprintf(cmd, cmd_len, "rm -rf \"%s\"", path);
    system(cmd);
    free(cmd);
}

void mkdir_p(const char *path) {
    char *temp = strdup(path);
    char *p = temp;
    do {
        p = strchr(p + 1, '/');
        if (p) *p = '\0';
        mkdir(temp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (p) *p = '/';
    } while (p);
    free(temp);
}

int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

// AES Encryption with OpenSSL
char *aes_encrypt(const unsigned char *input, size_t input_len, size_t* out_len) {
    if (!input || !out_len) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    size_t max_out_len = input_len + block_size;
    unsigned char *output = (unsigned char *)malloc(max_out_len);
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, (int)input_len)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *out_len = (size_t)ciphertext_len;
    return (char *)output;
}

// Get parent directory of a relative path
char * get_parent_dir_of_file(const char *rel_path) {
    char * dup = strdup(rel_path);
    char * last_slash = strrchr(dup, '/');
    if (!last_slash) {
        free(dup);
        return strdup("");
    }
    *last_slash = '\0';
    char *parent = dirname(dup);
    char *result = strdup(parent);
    free(dup);
    return result;
}

char *concat(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    char *result = malloc(len1 + len2 + 1);
    if (!result) return NULL;
    strcpy(result, s1);
    strcpy(result + len1, s2);
    return result;
}

// frozen
char *make_frozen_filename(const char *filename) {
    if (!filename) return NULL;

    char *temp = concat("<frozen ", filename);
    if (!temp) return NULL;

    char *frozen = concat(temp, ">");
    free(temp);
    return frozen;
}

// ==================== Main ====================
int main(int argc, const char * argv[]) {
    if (argc < 2) {
        fprintf(stderr, "There are too few argv.");
        return 1;
    }
    
    const char *input_path = NULL;
    const char *platform = "mac"; // The default platform is Mac
    // get parameters
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "-p") == 0 && i + 1 < argc) {
            platform = argv[++i];
            if (strcmp(platform, "linux") != 0 && strcmp(platform, "mac") != 0) {
                fprintf(stderr, "❌ Error: Invalid platform '%s'. Use 'mac' or 'linux'.\n", platform);
                return 1;
            }
        } else if (input_path == NULL) {
            input_path = arg;
        } else {
            fprintf(stderr, "❌ Error: Unexpected argument: %s\n", arg);
            return 1;
        }
    }
    
    if (access(input_path, F_OK) != 0) {
        fprintf(stderr, "❌ Input not found: %s\n", input_path);
        return 1;
    }

    char *abs_input = realpath(input_path, NULL);
    if (!abs_input) { perror("realpath"); return 1; }

    char *input_dir_dup = strdup(abs_input);
    char *input_basename = basename(input_dir_dup);

    char *input_parent_dup = strdup(abs_input);
    char *input_parent = dirname(input_parent_dup);

    size_t dist_parent_len = strlen(input_parent) + strlen("/dist") + 1;
    char *dist_parent = (char *)malloc(dist_parent_len);
    snprintf(dist_parent, dist_parent_len, "%s/dist", input_parent);

    printf("🗑️  Removing existing dist directory: %s\n", dist_parent);
    remove_directory(dist_parent);

    struct stat input_stat;
    if (stat(abs_input, &input_stat) != 0) {
        perror("stat input");
        free(abs_input); free(input_dir_dup); free(input_parent_dup);
        free(dist_parent);
        return 1;
    }

    StringList py_files;
    list_init(&py_files);

    int is_single_file = 0;
    char *single_file_path = NULL;

    if (S_ISDIR(input_stat.st_mode)) {
        collect_py_files(abs_input, abs_input, &py_files);
        if (py_files.count == 0) {
            fprintf(stderr, "❌ No .py files found in: %s\n", abs_input);
            goto cleanup_list;
        }
    } else {
        size_t len = strlen(abs_input);
        if (len <= 3 || strcmp(abs_input + len - 3, ".py") != 0) {
            fprintf(stderr, "❌ Not a .py file: %s\n", abs_input);
            goto cleanup_list;
        }
        list_push(&py_files, input_basename);
        is_single_file = 1;
        single_file_path = abs_input;
    }

    char *dist_dir;
    if (is_single_file) {
        dist_dir = dist_parent;
    } else {
        size_t dir_len = strlen(dist_parent) + strlen("/") + strlen(input_basename) + 1;
        dist_dir = (char *)malloc(dir_len);
        snprintf(dist_dir, dir_len, "%s/%s", dist_parent, input_basename);
        mkdir_p(dist_dir);
    }

    StringSet parent_dirs;
    set_init(&parent_dirs);
    for (size_t i = 0; i < py_files.count; ++i) {
        char *parent = get_parent_dir_of_file(py_files.items[i]);
        set_add(&parent_dirs, parent);
        free(parent);
    }

    for (size_t i = 0; i < parent_dirs.count; ++i) {
        const char *rel_parent = parent_dirs.items[i];

        size_t mk_runtime_dir_len = strlen(dist_dir) + 1;
        if (strlen(rel_parent) > 0) mk_runtime_dir_len += strlen(rel_parent) + 1;
        mk_runtime_dir_len += strlen("/mk_runtime");
        char *mk_runtime_dir = (char *)malloc(mk_runtime_dir_len);
        if (strlen(rel_parent) == 0) {
            snprintf(mk_runtime_dir, mk_runtime_dir_len, "%s/mk_runtime", dist_dir);
        } else {
            snprintf(mk_runtime_dir, mk_runtime_dir_len, "%s/%s/mk_runtime", dist_dir, rel_parent);
        }
        
        char *so_path = (char *)malloc(strlen(mk_runtime_dir) + strlen("/mk_runtime.so") + 1);
        snprintf(so_path, strlen(mk_runtime_dir) + strlen("/mk_runtime.so") + 1, "%s/mk_runtime.so", mk_runtime_dir);
        
        if (!file_exists(so_path)) {
            mkdir_p(mk_runtime_dir);
            
            char *runtime_path = strdup(fixed_runtime_path);
            char *dir_name = dirname(runtime_path);
            char *runtime_dir = strdup(dir_name);
            
            dir_name = dirname(runtime_dir);
            char *openssl_root = strdup(dir_name);
            size_t cmd_len = 512;
            char *compile_cmd = (char *)malloc(cmd_len);
            
            if (strcmp(platform, "mac") == 0) {
                snprintf(compile_cmd, cmd_len,
                    "cd \"%s\" && "
                    "clang -shared -fPIC "
                    "-I. "
                    "-I/Library/Frameworks/Python.framework/Versions/3.11/include/python3.11 "
                    "-I\"%s/OpenSSL/openssl-mac/include\" "
                    "-L\"%s/OpenSSL/openssl-mac/lib\" "
                    "-o \"%s/mk_runtime.so\" "
                    "mk_runtime.c "
                    "-lcrypto -undefined dynamic_lookup",
                    runtime_dir,
                    openssl_root,
                    openssl_root,
                    mk_runtime_dir);
            } else if (strcmp(platform, "linux") == 0) {
                snprintf(compile_cmd, cmd_len,
                    "/usr/local/bin/docker run --rm "
                    "-v \"%s:/workspace\" "                           // -v directory where runtime.c
                    "-v \"%s/OpenSSL/openssl-linux:/openssl:ro\" "    // -v linux OpenSSL
                    "-v \"%s:/output\" "                              // -v output directory of mk_runtime.so
                    "mk_python3.11_obfuscated_linux_x86_64 "          // use custom image
                    "gcc -shared -fPIC "
                        "-I/usr/local/include/python3.11 "
                        "-I/openssl/include "
                        "-L/openssl/lib "
                        "-o /output/mk_runtime.so "
                        "/workspace/mk_runtime.c "
                        "-lcrypto",
                    runtime_dir,
                    openssl_root,
                    mk_runtime_dir);
            }
            
            printf("📦 Compiling mk_runtime.so for: %s\n", mk_runtime_dir);
            if (run_command(compile_cmd) != 0) {
                fprintf(stderr, "❌ Failed to compile mk_runtime.so for %s\n", mk_runtime_dir);
                free(compile_cmd); free(runtime_path);
                free(runtime_dir); free(openssl_root);
                continue;
            }
            free(compile_cmd); free(runtime_path);
            free(runtime_dir); free(openssl_root);
            
            size_t init_py_len = strlen(mk_runtime_dir) + strlen("/__init__.py") + 1;
            char *init_py_path = (char *)malloc(init_py_len);
            snprintf(init_py_path, init_py_len, "%s/__init__.py", mk_runtime_dir);
            FILE* init_py = fopen(init_py_path, "w");
            if (init_py) {
                fputs("from .mk_runtime import __run_protected__\n", init_py);
                fclose(init_py);
            }
            free(init_py_path);
        }
        free(so_path);
        free(mk_runtime_dir);
    }

    Py_Initialize();

    for (size_t i = 0; i < py_files.count; ++i) {
        const char *rel_path = py_files.items[i];

        char *input_file;
        if (is_single_file) {
            input_file = strdup(single_file_path);
        } else {
            size_t input_file_len = strlen(abs_input) + strlen(rel_path) + 2;
            input_file = malloc(input_file_len);
            snprintf(input_file, input_file_len, "%s/%s", abs_input, rel_path);
        }

        size_t out_file_len = strlen(dist_dir) + 1 + strlen(rel_path) + 1;
        char *out_file = malloc(out_file_len);
        snprintf(out_file, out_file_len, "%s/%s", dist_dir, rel_path);

        char *out_dir = strdup(out_file);
        char *last_slash = strrchr(out_dir, '/');
        if (last_slash) *last_slash = '\0';
        mkdir_p(out_dir);

        printf("🔒 Encrypting: %s\n", rel_path);

        char *source = read_file(input_file);
        if (!source) {
            fprintf(stderr, "❌ Failed to read: %s\n", input_file);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }
        //
        char *basename_ptr = strrchr(rel_path, '/');
        const char *filename_with_ext = (basename_ptr == NULL) ? rel_path : basename_ptr + 1;
        const char *dot = strrchr(filename_with_ext, '.');
        const char *filename_part;
        if (dot && strcmp(dot, ".py") == 0) {
            size_t len_without_ext = dot - filename_with_ext;
            char *temp = malloc(len_without_ext + 1);
            strncpy(temp, filename_with_ext, len_without_ext);
            temp[len_without_ext] = '\0';
            filename_part = temp;
        } else {
            filename_part = filename_with_ext;
        }
        char *compile_filename = make_frozen_filename(filename_part);
        
        // compile
        PyCodeObject *code = (PyCodeObject *)Py_CompileString(source, compile_filename, Py_file_input);
        free(compile_filename);
        if (!code) {
            PyErr_Print();
            free(source); free(input_file); free(out_file); free(out_dir);
            continue;
        }
        free(source);

        PyObject *orig_code_bytes = PyCode_GetCode(code);
        if (!orig_code_bytes || !PyBytes_Check(orig_code_bytes)) {
            fprintf(stderr, "❌ Failed to get code bytes for %s\n", input_file);
            Py_DECREF(code); free(input_file); free(out_file); free(out_dir);
            continue;
        }

        char *orig_data;
        Py_ssize_t orig_len;
        if (PyBytes_AsStringAndSize(orig_code_bytes, &orig_data, &orig_len) < 0) {
            Py_DECREF(orig_code_bytes); Py_DECREF(code);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }

        Py_ssize_t n_names = PyTuple_Size(code->co_names);
        int mk_enter_idx = -1;
        for (Py_ssize_t j = 0; j < n_names; ++j) {
            PyObject *name = PyTuple_GetItem(code->co_names, j);
            if (PyUnicode_Check(name) && PyUnicode_CompareWithASCIIString(name, "__mk_enter__") == 0) {
                mk_enter_idx = (int)j;
                break;
            }
        }

        PyObject *new_names = NULL;
        if (mk_enter_idx == -1) {
            mk_enter_idx = (int)n_names;
            new_names = PyTuple_New(n_names + 1);
            if (!new_names) {
                fprintf(stderr, "❌ Out of memory (new_names)\n");
                Py_DECREF(orig_code_bytes); Py_DECREF(code);
                free(input_file); free(out_file); free(out_dir);
                continue;
            }
            for (Py_ssize_t j = 0; j < n_names; ++j) {
                PyObject *item = PyTuple_GetItem(code->co_names, j);
                Py_INCREF(item);
                PyTuple_SET_ITEM(new_names, j, item);
            }
            PyObject *mk_enter_str = PyUnicode_FromString("__mk_enter__");
            if (!mk_enter_str) {
                Py_DECREF(new_names); Py_DECREF(orig_code_bytes); Py_DECREF(code);
                free(input_file); free(out_file); free(out_dir);
                continue;
            }
            PyTuple_SET_ITEM(new_names, n_names, mk_enter_str);
        } else {
            new_names = code->co_names;
            Py_INCREF(new_names);
        }

        const int PREFIX_SLOTS = 14;
        Py_ssize_t new_len = orig_len + PREFIX_SLOTS * sizeof(_Py_CODEUNIT);
        _Py_CODEUNIT *new_data = (_Py_CODEUNIT *)calloc(new_len, 1);
        if (!new_data) {
            fprintf(stderr, "❌ Out of memory (new_data)\n");
            Py_DECREF(new_names); Py_DECREF(orig_code_bytes); Py_DECREF(code);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }

        int oparg = (mk_enter_idx << 1) | 1;
        new_data[0]  = (LOAD_GLOBAL) | (oparg << 8);
        new_data[6]  = (PRECALL)     | (0 << 8);
        new_data[8]  = (CALL)        | (0 << 8);
        new_data[13] = POP_TOP;

        memcpy(&new_data[PREFIX_SLOTS], orig_data, orig_len);

        PyObject *new_code_bytes = PyBytes_FromStringAndSize((char *)new_data, new_len);
        free(new_data);
        if (!new_code_bytes) {
            Py_DECREF(new_names); Py_DECREF(orig_code_bytes); Py_DECREF(code);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }

        PyObject *varnames = PyCode_GetVarnames(code);
        PyObject *freevars = PyCode_GetFreevars(code);
        PyObject *cellvars = PyCode_GetCellvars(code);
        PyObject *consts   = code->co_consts;   Py_INCREF(consts);
        PyObject *filename = code->co_filename; Py_INCREF(filename);
        PyObject *name     = code->co_name;     Py_INCREF(name);
        PyObject *qualname = code->co_qualname ? code->co_qualname : name;
        Py_INCREF(qualname);

        PyObject *linetable = code->co_linetable;
        if (!linetable || !PyBytes_Check(linetable)) {
            linetable = PyBytes_FromStringAndSize("", 0);
        } else {
            Py_INCREF(linetable);
        }

        PyObject *exc_table = code->co_exceptiontable;
        if (!exc_table || !PyBytes_Check(exc_table)) {
            exc_table = PyBytes_FromStringAndSize("", 0);
        } else {
            Py_INCREF(exc_table);
        }

        int new_stacksize = code->co_stacksize + 1;
        if (new_stacksize < 1) new_stacksize = 1;

        PyCodeObject *new_code = PyCode_New(
            code->co_argcount,
            code->co_kwonlyargcount,
            code->co_nlocals,
            new_stacksize,
            code->co_flags,
            new_code_bytes,
            consts,
            new_names,
            varnames,
            freevars,
            cellvars,
            filename,
            name,
            qualname,
            code->co_firstlineno,
            linetable,
            exc_table
        );

        Py_DECREF(orig_code_bytes);
        Py_DECREF(new_code_bytes);
        Py_DECREF(varnames);
        Py_DECREF(freevars);
        Py_DECREF(cellvars);
        Py_DECREF(consts);
        Py_DECREF(filename);
        Py_DECREF(name);
        Py_DECREF(qualname);
        Py_DECREF(linetable);
        Py_DECREF(exc_table);
        Py_DECREF(new_names);
//        Py_DECREF(code);

        if (!new_code) {
            fprintf(stderr, "❌ Failed to create new code for %s\n", input_file);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }
//        code = new_code;

        PyObject *marshal = PyImport_ImportModule("marshal");
        PyObject *dumps = PyObject_GetAttrString(marshal, "dumps");
        PyObject *marshalled = PyObject_CallFunctionObjArgs(dumps, (PyObject*)code, NULL);
        Py_DECREF(code);
        Py_DECREF(dumps);
        Py_DECREF(marshal);

        if (!marshalled || !PyBytes_Check(marshalled)) {
            fprintf(stderr, "❌ marshal failed for %s\n", input_file);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }

        Py_ssize_t len;
        char *data;
        PyBytes_AsStringAndSize(marshalled, &data, &len);

        size_t encrypted_len = 0;
        char *encrypted_data = aes_encrypt((const unsigned char *)data, len, &encrypted_len);
        Py_DECREF(marshalled);
        if (!encrypted_data) {
            fprintf(stderr, "❌ AES encryption failed for %s\n", input_file);
            free(input_file); free(out_file); free(out_dir);
            continue;
        }

        const char *import_path = "mk_runtime";

        time_t now;
        struct tm* tm_info;
        char time_str[32];
        time(&now);
        tm_info = localtime(&now);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        
        // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        FILE* out = fopen(out_file, "w");
        if (!out) {
            perror("fopen output");
            free(encrypted_data); free(input_file); free(out_file); free(out_dir);
            continue;
        }
        
        fprintf(out, "# mk -%s , %s\n", version, time_str);
        fprintf(out, "from %s import __run_protected__\n", import_path);
        fprintf(out, "parameter = b'");
        for (Py_ssize_t j = 0; j < (Py_ssize_t)encrypted_len; j++) {
            fprintf(out, "\\x%02x", (unsigned char)encrypted_data[j]);
        }
        fprintf(out, "'\n");
        fprintf(out, "__run_protected__(__name__, __file__, parameter)\n");
        fclose(out);
        // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        
//        fprintf(out, "from %s import __run_protected__\n", import_path);
//        fprintf(out, "__run_protected__(__name__, __file__, b'");
//        for (Py_ssize_t j = 0; j < (Py_ssize_t)encrypted_len; j++) {
//            fprintf(out, "\\x%02x", (unsigned char)encrypted_data[j]);
//        }
//        fprintf(out, "')\n");
//        fclose(out);
        // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        free(encrypted_data);
        free(input_file);
        free(out_file);
        free(out_dir);
    }

    Py_Finalize();
    printf("✅ Success! product output path:\n   %s/\n", dist_dir);

cleanup_list:
    list_free(&py_files);
    set_free(&parent_dirs);
    if (!is_single_file) {
        free(abs_input);
        if (dist_dir != dist_parent) {
            free(dist_dir);
        }
    }
    free(input_dir_dup);
    free(input_parent_dup);
    free(dist_parent);
    return 0;
}
