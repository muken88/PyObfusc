//
//  mk_runtime.c
//  PyObfusc
//
//  Created by muken on 2025/12/1.
//

#include "mk_runtime.h"
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <cpython/code.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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

unsigned char *aes_decrypt(const unsigned char *input, size_t input_len, size_t* out_len) {
    if (!input || !out_len) return NULL;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    size_t max_out_len = (input_len > 0) ? input_len + block_size : block_size;
    unsigned char *output = (unsigned char *)malloc(max_out_len);
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, output, &len, input, (int)input_len)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        // Padding error or corruption
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *out_len = (size_t)plaintext_len;
    return output;
}

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// __mk_enter__   __mk_exit__
static PyObject* __mk_enter__(PyObject *self, PyObject *args);
static PyObject* __mk_exit__(PyObject *self, PyObject *args);

static PyMethodDef mk_enter_def = {
    "__mk_enter__", __mk_enter__, METH_NOARGS, NULL
};
static PyMethodDef mk_exit_def = {
    "__mk_exit__", __mk_exit__, METH_NOARGS, NULL
};

static PyObject*
__run_protected__(PyObject *self, PyObject *args)
{
    const char *module_name;
    const char *file_path;
    const char *encrypted_bytes;
    Py_ssize_t encrypted_len;

    if (!PyArg_ParseTuple(args, "sss#", &module_name, &file_path, &encrypted_bytes, &encrypted_len)) {
        return NULL;
    }
    
    // >>>>>>>>>>>>>>>>>> DEBUG LOGS <<<<<<<<<<<<<<<<<<
    fprintf(stderr, "[MK_RUNTIME] module_name = '%s'\n", module_name ? module_name : "(null)");
    fprintf(stderr, "[MK_RUNTIME] file_path   = '%s'\n", file_path ? file_path : "(null)");
    
    if (file_path) {
        if (access(file_path, F_OK) == 0) {
            fprintf(stderr, "[MK_RUNTIME] file_path EXISTS on disk.\n");
        } else {
            fprintf(stderr, "[MK_RUNTIME] file_path DOES NOT EXIST! errno=%d (%s)\n", errno, strerror(errno));
        }
    }

    char cwd_buf[1024];
    if (getcwd(cwd_buf, sizeof(cwd_buf))) {
        fprintf(stderr, "[MK_RUNTIME] current working directory = '%s'\n", cwd_buf);
    } else {
        fprintf(stderr, "[MK_RUNTIME] failed to get cwd\n");
    }
    fflush(stderr);
    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    // >>>>>>>>>>>>>>>>>>> AES decrypt <<<<<<<<<<<<<<<<<<<<<
    size_t decrypted_len = 0;
    unsigned char *decrypted_data = aes_decrypt((const unsigned char *)encrypted_bytes, encrypted_len, &decrypted_len);
    if (!decrypted_data) {
        PyErr_SetString(PyExc_RuntimeError, "AES decryption failed");
        return NULL;
    }
    
    PyObject *code = PyMarshal_ReadObjectFromString((char *)decrypted_data, decrypted_len);
    free(decrypted_data);
    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    
    if (!code) {
        PyErr_SetString(PyExc_RuntimeError, "Unmarshal failed");
        return NULL;
    }
    
    PyObject *module = PyImport_ExecCodeModuleEx(module_name, code, file_path);
    Py_DECREF(code);
    
    if (!module) {
//        PyErr_Print();
        return NULL;
    }
    
    Py_DECREF(module);  // sys.modules hold
    Py_RETURN_NONE;
}

static PyMethodDef MkRuntimeMethods[] = {
    {"__run_protected__", __run_protected__, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "mk_runtime",
    NULL,
    -1,
    MkRuntimeMethods
};

static PyObject*
__mk_enter__(PyObject *self, PyObject *args)
{
    fflush(stdout);
    Py_RETURN_NONE;
}

static PyObject*
__mk_exit__(PyObject *self, PyObject *args)
{
    fflush(stdout);
    Py_RETURN_NONE;
}

PyMODINIT_FUNC
PyInit_mk_runtime(void)
{
    PyObject *enter_func = PyCFunction_NewEx(&mk_enter_def, NULL, NULL);
    PyObject *exit_func  = PyCFunction_NewEx(&mk_exit_def,  NULL, NULL);
    PyObject *builtins = PyEval_GetBuiltins();
    PyDict_SetItemString(builtins, "__mk_enter__", enter_func);
    PyDict_SetItemString(builtins, "__mk_exit__", exit_func);
    return PyModule_Create(&module);
}
