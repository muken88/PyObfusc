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
#include <stdarg.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <mach-o/dyld.h>
#include <cpython/code.h>
#include <opcode.h>
#include "mk_print.h"
#include <openssl/evp.h>
#include <openssl/err.h>

static const char *fixed_runtime_path = FIXED_RUNTIME_PATH;
static const char *version = VERSION;

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

void collect_files(const char *root, const char *current, StringList *py_files, StringList *json_files) {
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
                collect_files(root, full_path, py_files, json_files);  // 递归
            } else if (S_ISREG(st.st_mode)) {
                const char *name = entry->d_name;
                size_t len = strlen(name);
                const char *rel = full_path + strlen(root);
                if (*rel == '/') rel++;

                if (len > 3 && strcmp(name + len - 3, ".py") == 0) {
                    list_push(py_files, rel);
                } else if (len > 5 && strcmp(name + len - 5, ".json") == 0) {
                    list_push(json_files, rel);
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

// copy file
int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    
    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, bytes, out) != bytes) {
            fclose(in); fclose(out);
            return -1;
        }
    }
    
    fclose(in);
    fclose(out);
    return 0;
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

static int is_valid_platform(const char *platform) {
    return platform
        && (strcmp(platform, "mac") == 0
            || strcmp(platform, "linux-x86_64") == 0
            || strcmp(platform, "linux-arm64") == 0);
}

static char *format_cmd(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list aq;
    va_copy(aq, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) {
        va_end(aq);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)needed + 1);
    if (!buf) {
        va_end(aq);
        return NULL;
    }
    vsnprintf(buf, (size_t)needed + 1, fmt, aq);
    va_end(aq);
    return buf;
}

static char *join_path(const char *a, const char *b) {
    if (!a || !b) return NULL;
    size_t la = strlen(a);
    int need_slash = (la > 0 && a[la - 1] != '/');
    size_t n = la + strlen(b) + (need_slash ? 2 : 1);
    char *out = (char *)malloc(n);
    if (!out) return NULL;
    if (need_slash) snprintf(out, n, "%s/%s", a, b);
    else snprintf(out, n, "%s%s", a, b);
    return out;
}

// Installed layout: <root>/bin/pyobfusc. A binary built in DerivedData
// falls back to the source tree that contains source/mk_runtime.c.
static char *tool_root(void) {
    char buf[PATH_MAX];
    uint32_t size = (uint32_t)sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        char *exe = realpath(buf, NULL);
        if (exe) {
            char *exe_copy = strdup(exe);
            char *dir = dirname(exe_copy);
            char *dir_copy = strdup(dir);
            char *base = basename(dir_copy);
            char *root = NULL;
            if (strcmp(base, "bin") == 0) {
                char *dir_for_parent = strdup(dir);
                root = strdup(dirname(dir_for_parent));
                free(dir_for_parent);
            }
            free(dir_copy);
            free(exe_copy);
            free(exe);
            if (root) return root;
        }
    }

    char *runtime_copy = strdup(fixed_runtime_path);
    char *source_dir = dirname(runtime_copy);
    char *source_copy = strdup(source_dir);
    char *root = strdup(dirname(source_copy));
    free(source_copy);
    free(runtime_copy);
    return root;
}

static void print_help(const char *root) {
    const char *shown = root ? root : "(未知)";
    printf(
        "pyobfusc %s — 把 Python 源码加密成可运行的受保护脚本\n"
        "\n"
        "用法:\n"
        "  pyobfusc [选项] <输入路径>\n"
        "\n"
        "参数:\n"
        "  <输入路径>              一个 .py 文件，或一个包含 .py 的目录\n"
        "\n"
        "选项:\n"
        "  -p, --platform <平台>   运行时所针对的系统。默认: mac\n"
        "                          mac            使用预编译的 mac 版 mk_runtime.so\n"
        "                          linux-x86_64   使用预编译的 linux x86_64 版 mk_runtime.so\n"
        "                          linux-arm64    使用预编译的 linux arm64 版 mk_runtime.so\n"
        "  --build-runtime         预编译 mk_runtime.so。不带 -p 时编译全部平台\n"
        "  -h, --help              显示这份说明\n"
        "  -V, --version           显示版本\n"
        "\n"
        "行为:\n"
        "  输出目录是输入路径的上一级里的 dist/，已有的 dist/ 会先整目录删除。\n"
        "  目录输入时，其中的 .py 会被加密，.json 会原样复制，并生成 dist/mk_runtime/。\n"
        "  单个 .py 文件时，加密结果写到该文件所在目录的 dist/ 下。\n"
        "  加密后的 .py 通过 mk_runtime.__run_protected__ 在对应平台上运行。\n"
        "\n"
        "示例:\n"
        "  pyobfusc ./src\n"
        "  pyobfusc -p mac /Users/liaoyu/Desktop/fs-ai-chat/fs-iqa-db/src\n"
        "  pyobfusc -p linux-x86_64 /Users/liaoyu/Desktop/fs-ai-chat/fs-iqa-db/src\n"
        "  pyobfusc --platform linux-arm64 ./app.py\n"
        "\n"
        "运行时:\n"
        "  mk_runtime.so 在安装或执行 --build-runtime 时按平台预编译，放在\n"
        "  %s/runtime/<平台>/\n"
        "  加密时只复制对应平台的 .so 和 __init__.py，不会调用 clang，也不会启动 Docker。\n"
        "\n"
        "  pyobfusc --build-runtime              预编译 mac、linux-x86_64、linux-arm64\n"
        "  pyobfusc --build-runtime -p mac       只预编译某一个平台\n"
        "\n"
        "  --build-runtime 编 Linux 运行时才需要 Docker 镜像：\n"
        "    mk_python3.11_obfuscated_linux_x86_64\n"
        "    mk_python3.11_obfuscated_linux_aarch64\n"
        "\n"
        "依赖:\n"
        "  加密本身需要 /Library/Frameworks 里的 Python 3.11。\n"
        "  mac 运行时的预编译还需要 clang。\n"
        "  Linux 运行时的预编译还需要上面的 Docker 镜像。\n",
        version, shown);
}

static int write_runtime_init(const char *root) {
    char *runtime_dir = join_path(root, "runtime");
    if (!runtime_dir) return 1;
    mkdir_p(runtime_dir);
    char *init_path = join_path(runtime_dir, "__init__.py");
    free(runtime_dir);
    if (!init_path) return 1;
    FILE *fp = fopen(init_path, "w");
    if (!fp) {
        fprintf(stderr, "❌ 无法写入 %s\n", init_path);
        free(init_path);
        return 1;
    }
    fputs("from .mk_runtime import __run_protected__\n", fp);
    fclose(fp);
    free(init_path);
    return 0;
}

static int build_one_runtime(const char *root, const char *platform) {
    char *source_dir = join_path(root, "source");
    char *source_file = source_dir ? join_path(source_dir, "mk_runtime.c") : NULL;
    char *openssl_mac_include = join_path(root, "OpenSSL/openssl-mac/include");
    char *openssl_mac_crypto = join_path(root, "OpenSSL/openssl-mac/lib/libcrypto.a");
    char *openssl_linux = join_path(root, "OpenSSL/openssl-linux");
    char *out_dir = join_path(root, "runtime");
    char *plat_dir = out_dir ? join_path(out_dir, platform) : NULL;
    char *out_so = plat_dir ? join_path(plat_dir, "mk_runtime.so") : NULL;
    char *cmd = NULL;
    int rc = 1;

    if (!source_file || !file_exists(source_file)) {
        fprintf(stderr, "❌ 找不到 mk_runtime.c: %s\n", source_file ? source_file : "(null)");
        goto done;
    }
    if (!plat_dir || !out_so) goto done;
    mkdir_p(plat_dir);
    if (write_runtime_init(root) != 0) goto done;

    if (strcmp(platform, "mac") == 0) {
        if (!openssl_mac_crypto || !file_exists(openssl_mac_crypto)) {
            fprintf(stderr, "❌ 找不到 libcrypto.a: %s\n", openssl_mac_crypto ? openssl_mac_crypto : "(null)");
            goto done;
        }
        cmd = format_cmd(
            "clang -shared -fPIC "
            "-I\"%s\" "
            "-I/Library/Frameworks/Python.framework/Versions/3.11/include/python3.11 "
            "-I\"%s\" "
            "-o \"%s\" "
            "\"%s\" "
            "\"%s\" "
            "-undefined dynamic_lookup",
            source_dir,
            openssl_mac_include,
            out_so,
            source_file,
            openssl_mac_crypto);
    } else if (strcmp(platform, "linux-x86_64") == 0 || strcmp(platform, "linux-arm64") == 0) {
        const char *image = strcmp(platform, "linux-x86_64") == 0
            ? "mk_python3.11_obfuscated_linux_x86_64"
            : "mk_python3.11_obfuscated_linux_aarch64";
        const char *py_include = strcmp(platform, "linux-x86_64") == 0
            ? "/usr/local/include/python3.11"
            : "/usr/include/python3.11";
        if (!openssl_linux || !file_exists(openssl_linux)) {
            fprintf(stderr, "❌ 找不到 OpenSSL linux 目录: %s\n", openssl_linux ? openssl_linux : "(null)");
            goto done;
        }
        const char *crypto_a = strcmp(platform, "linux-x86_64") == 0
            ? "/openssl/lib64/libcrypto.a"
            : "/usr/lib/aarch64-linux-gnu/libcrypto.a";
        const char *openssl_include = strcmp(platform, "linux-x86_64") == 0
            ? "-I/openssl/include"
            : "-I/usr/include";
        const char *docker_platform = strcmp(platform, "linux-x86_64") == 0
            ? "linux/amd64"
            : "linux/arm64";
        cmd = format_cmd(
            "/usr/local/bin/docker run --rm --platform %s "
            "-v \"%s:/workspace:ro\" "
            "-v \"%s:/openssl:ro\" "
            "-v \"%s:/output\" "
            "%s "
            "gcc -shared -fPIC "
            "-I%s "
            "%s "
            "-o /output/mk_runtime.so "
            "/workspace/mk_runtime.c "
            "%s "
            "-lpthread -ldl",
            docker_platform,
            source_dir,
            openssl_linux,
            plat_dir,
            image,
            py_include,
            openssl_include,
            crypto_a);
    }

    if (!cmd) goto done;
    printf("📦 预编译 mk_runtime.so (%s) -> %s\n", platform, out_so);
    fflush(stdout);
    if (run_command(cmd) != 0) {
        fprintf(stderr, "❌ 预编译失败: %s\n", platform);
        goto done;
    }
    rc = 0;

done:
    free(cmd);
    free(source_dir);
    free(source_file);
    free(openssl_mac_include);
    free(openssl_mac_crypto);
    free(openssl_linux);
    free(out_dir);
    free(plat_dir);
    free(out_so);
    return rc;
}

static int build_runtime(const char *root, const char *platform, int platform_set) {
    if (platform_set) {
        return build_one_runtime(root, platform);
    }
    const char *all[] = {"mac", "linux-x86_64", "linux-arm64"};
    int failed = 0;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); ++i) {
        if (build_one_runtime(root, all[i]) != 0) failed = 1;
    }
    return failed;
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
    const char *input_path = NULL;
    const char *platform = "mac";
    int platform_set = 0;
    int want_help = 0;
    int want_version = 0;
    int want_build_runtime = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            want_help = 1;
        } else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
            want_version = 1;
        } else if (strcmp(arg, "--build-runtime") == 0) {
            want_build_runtime = 1;
        } else if (strcmp(arg, "-p") == 0 || strcmp(arg, "--platform") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "❌ %s 需要一个平台参数。查看用法: pyobfusc --help\n", arg);
                return 1;
            }
            platform = argv[++i];
            platform_set = 1;
            if (!is_valid_platform(platform)) {
                fprintf(stderr, "❌ 非法平台 '%s'。可选: mac、linux-x86_64、linux-arm64。\n", platform);
                return 1;
            }
        } else if (strncmp(arg, "--platform=", 11) == 0) {
            platform = arg + 11;
            platform_set = 1;
            if (!is_valid_platform(platform)) {
                fprintf(stderr, "❌ 非法平台 '%s'。可选: mac、linux-x86_64、linux-arm64。\n", platform);
                return 1;
            }
        } else if (arg[0] == '-') {
            fprintf(stderr, "❌ 无法识别的参数: %s\n查看用法: pyobfusc --help\n", arg);
            return 1;
        } else if (input_path == NULL) {
            input_path = arg;
        } else {
            fprintf(stderr, "❌ 无法识别的参数: %s\n查看用法: pyobfusc --help\n", arg);
            return 1;
        }
    }

    if (want_help) {
        char *root = tool_root();
        print_help(root);
        free(root);
        return 0;
    }
    if (want_version) {
        printf("pyobfusc %s\n", version);
        return 0;
    }
    if (want_build_runtime) {
        if (input_path) {
            fprintf(stderr, "❌ --build-runtime 不接受输入路径。查看用法: pyobfusc --help\n");
            return 1;
        }
        char *root = tool_root();
        if (!root) {
            fprintf(stderr, "❌ 无法定位 pyobfusc 安装目录\n");
            return 1;
        }
        int rc = build_runtime(root, platform, platform_set);
        free(root);
        return rc;
    }
    if (!input_path) {
        fprintf(stderr, "❌ 缺少输入路径。查看用法: pyobfusc --help\n");
        return 1;
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
    
    StringList json_files;
    list_init(&json_files);

    int is_single_file = 0;
    char *single_file_path = NULL;
    char *mk_runtime_dir = NULL;
    int status = 0;

    if (S_ISDIR(input_stat.st_mode)) {
        collect_files(abs_input, abs_input, &py_files, &json_files);
        if (py_files.count == 0) {
            fprintf(stderr, "❌ No .py files found in: %s\n", abs_input);
            status = 1;
            goto cleanup_list;
        }
    } else {
        size_t len = strlen(abs_input);
        if (len <= 3 || strcmp(abs_input + len - 3, ".py") != 0) {
            fprintf(stderr, "❌ Not a .py file: %s\n", abs_input);
            status = 1;
            goto cleanup_list;
        }
        list_push(&py_files, input_basename);
        is_single_file = 1;
        single_file_path = abs_input;
    }

    char *dist_dir = dist_parent;
    if (!is_single_file) {
        mkdir_p(dist_dir);
    }

    // Copy the prebuilt runtime. Encryption does not compile or start Docker.
    char *root = tool_root();
    char *runtime_pkg = root ? join_path(root, "runtime") : NULL;
    char *plat_dir = runtime_pkg ? join_path(runtime_pkg, platform) : NULL;
    char *src_so = plat_dir ? join_path(plat_dir, "mk_runtime.so") : NULL;
    char *src_init = runtime_pkg ? join_path(runtime_pkg, "__init__.py") : NULL;
    size_t len = strlen(dist_parent) + strlen("/mk_runtime") + 1;
    mk_runtime_dir = malloc(len);
    snprintf(mk_runtime_dir, len, "%s/mk_runtime", dist_parent);
    mkdir_p(mk_runtime_dir);
    char *dst_so = join_path(mk_runtime_dir, "mk_runtime.so");
    char *dst_init = join_path(mk_runtime_dir, "__init__.py");

    if (!src_so || !file_exists(src_so) || !src_init || !file_exists(src_init)) {
        fprintf(stderr, "❌ 未找到预编译运行时: %s\n", src_so ? src_so : platform);
        fprintf(stderr, "请先执行: pyobfusc --build-runtime -p %s\n", platform);
        status = 1;
    } else {
        printf("📦 复制运行时 (%s)\n", platform);
        if (copy_file(src_so, dst_so) != 0 || copy_file(src_init, dst_init) != 0) {
            fprintf(stderr, "❌ 复制 mk_runtime 失败\n");
            status = 1;
        }
    }
    free(root);
    free(runtime_pkg);
    free(plat_dir);
    free(src_so);
    free(src_init);
    free(dst_so);
    free(dst_init);
    if (status != 0) goto cleanup_list;
    //
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
        
        fprintf(out, "# PyObfusc -%s , %s\n", version, time_str);
        // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
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
    
    // Copy .json files directly
    for (size_t i = 0; i < json_files.count; ++i) {
        const char *rel_path = json_files.items[i];

        size_t src_len = strlen(abs_input) + strlen(rel_path) + 2;
        char *src_path = malloc(src_len);
        snprintf(src_path, src_len, "%s/%s", abs_input, rel_path);

        size_t dst_len = strlen(dist_dir) + 1 + strlen(rel_path) + 1;
        char *dst_path = malloc(dst_len);
        snprintf(dst_path, dst_len, "%s/%s", dist_dir, rel_path);

        char *dst_dir = strdup(dst_path);
        char *last_slash = strrchr(dst_dir, '/');
        if (last_slash) *last_slash = '\0';
        mkdir_p(dst_dir);

        printf("📄 Copying JSON: %s\n", rel_path);
        if (copy_file(src_path, dst_path) != 0) {
            fprintf(stderr, "❌ Failed to copy JSON file: %s\n", src_path);
        }

        free(src_path);
        free(dst_path);
        free(dst_dir);
    }

    Py_Finalize();
    printf("✅ Success! product output path:\n   %s/\n", dist_dir);

cleanup_list:
    list_free(&py_files);
    list_free(&json_files);
    if (mk_runtime_dir) {
        free(mk_runtime_dir);
    }
    if (!is_single_file) {
        free(abs_input);
    }
    free(input_dir_dup);
    free(input_parent_dup);
    free(dist_parent);
    return status;
}
