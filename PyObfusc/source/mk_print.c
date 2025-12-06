//
//  mk_print.c
//  PyObfusc
//
//  Created by muken on 2025/12/3.
//

#include <stdio.h>
#include <Python.h>
#include <stdint.h>

static PyObject *_dis_opname_list = NULL;

static int init_dis_opname_cache(void) {
    if (_dis_opname_list != NULL) {
        return 1; // already initialized
    }
    
    PyObject *dis_module = PyImport_ImportModule("dis");
    if (!dis_module) {
        PyErr_Print();
        return 0;
    }

    _dis_opname_list = PyObject_GetAttrString(dis_module, "opname");
    Py_DECREF(dis_module);

    if (!_dis_opname_list || !PyList_Check(_dis_opname_list)) {
        Py_XDECREF(_dis_opname_list);
        _dis_opname_list = NULL;
        PyErr_Print();
        return 0;
    }

    // Increase the references to prevent being reclaimed (assuming the lifecycle of this module is consistent with that of the interpreter)
    Py_INCREF(_dis_opname_list);
    return 1;
}

// Clear cache (optional, to be called when the module is unloaded)
void clear_opcode_cache(void) {
    Py_XDECREF(_dis_opname_list);
    _dis_opname_list = NULL;
}

// Obtain the opcode name dynamically, using dis.opname
static const char *get_opcode_name(unsigned char opcode) {
    // Lazy loading: Initializes on the first call.
    if (_dis_opname_list == NULL) {
        if (!init_dis_opname_cache()) {
            return "<init_dis_failed>";
        }
    }
    
    if (opcode >= 256) {
        return "<invalid_opcode>";
    }
    
    // By citation, without incrementing the citation count.
    PyObject *name_obj = PyList_GetItem(_dis_opname_list, opcode);
    if (name_obj && PyUnicode_Check(name_obj)) {
        const char *str = PyUnicode_AsUTF8(name_obj);
        if (str) {
            return str;
        }
    }
    
    return "<unknown>";
}

void print_co_names(PyObject *code) {
    if (!PyCode_Check(code)) {
        printf("print_co_names: not a code object\n");
        return;
    }

    PyObject *names = PyObject_GetAttrString(code, "co_names");
    if (!names || !PyTuple_Check(names)) {
        printf("print_co_names: failed to get co_names\n");
        Py_XDECREF(names);
        return;
    }

    Py_ssize_t len = PyTuple_GET_SIZE(names);
    printf("co_names (length=%zd):\n", len);
    for (Py_ssize_t i = 0; i < len; i++) {
        PyObject *name = PyTuple_GET_ITEM(names, i);
        if (PyUnicode_Check(name)) {
            const char *str = PyUnicode_AsUTF8(name);
            if (str) {
                printf("  [%zd] %s\n", i, str);
            } else {
                printf("  [%zd] <non-utf8 string>\n", i);
                PyErr_Clear();
            }
        } else {
            printf("  [%zd] <non-string object>\n", i);
        }
    }
    Py_DECREF(names);
    fflush(stdout);
}

void print_bytecode(PyObject *code_obj) {
    if (!PyCode_Check(code_obj)) {
        printf("print_bytecode: not a code object\n");
        return;
    }

    PyObject *co_code = PyObject_GetAttrString(code_obj, "co_code");
    if (!co_code || !PyBytes_Check(co_code)) {
        printf("print_bytecode: failed to get co_code\n");
        Py_XDECREF(co_code);
        return;
    }

    const char *byte_str = PyBytes_AS_STRING(co_code);
    Py_ssize_t byte_len = PyBytes_GET_SIZE(co_code);

    if (byte_len % sizeof(uint16_t) != 0) {
        printf("print_bytecode: co_code size not aligned to uint16_t\n");
        Py_DECREF(co_code);
        return;
    }

    Py_ssize_t num_instr = byte_len / sizeof(uint16_t);
    const uint16_t *instrs = (const uint16_t *)byte_str;

    printf("Bytecode (length=%zd instructions):\n", num_instr);
    for (Py_ssize_t i = 0; i < num_instr; i++) {
        uint16_t word = instrs[i];
        unsigned char opcode = word & 0xFF;
        unsigned char oparg = (word >> 8) & 0xFF;

        const char *opname = get_opcode_name(opcode);
        printf("  [%04zd] %02x %02x  %-40s %d\n", i, opcode, oparg, opname, oparg);
    }
    Py_DECREF(co_code);
    fflush(stdout);
}

static void
dump_code_object(PyObject *code_obj)
{
    if (!PyCode_Check(code_obj)) {
        fprintf(stderr, "❌ Not a code object!\n");
        fflush(stderr);
        return;
    }

    PyCodeObject *co = (PyCodeObject *)code_obj;

    const char *name_str = PyUnicode_AsUTF8(co->co_name);
    const char *file_str = PyUnicode_AsUTF8(co->co_filename);

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "🔍 Code Object Debug Dump (Direct Access)\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "co_name        : %s\n", name_str ? name_str : "<NULL>");
    fprintf(stderr, "co_filename    : %s\n", file_str ? file_str : "<NULL>");
    fprintf(stderr, "co_firstlineno : %d\n", co->co_firstlineno);
    fprintf(stderr, "co_stacksize   : %d\n", co->co_stacksize);
    fprintf(stderr, "co_flags       : 0x%08x\n", co->co_flags);

    // co_names
    fprintf(stderr, "co_names       : [");
    if (co->co_names && PyTuple_Check(co->co_names)) {
        Py_ssize_t len = PyTuple_GET_SIZE(co->co_names);
        for (Py_ssize_t i = 0; i < len; ++i) {
            PyObject *item = PyTuple_GET_ITEM(co->co_names, i); // borrowed
            const char *s = PyUnicode_Check(item) ? PyUnicode_AsUTF8(item) : "<non-str>";
            if (i > 0) {
                fprintf(stderr, ", ");
            }
            fprintf(stderr, "'%s'", s ? s : "<invalid>");
        }
    }
    fprintf(stderr, "]\n");

    PyObject *co_code_bytes = co->_co_code;
    if (!co_code_bytes) {
        Py_ssize_t n = _PyCode_NBYTES(co);
        co_code_bytes = PyBytes_FromStringAndSize((const char *)_PyCode_CODE(co), n);
        if (co_code_bytes) {
            const char *bytes = PyBytes_AS_STRING(co_code_bytes);
            Py_ssize_t size = PyBytes_GET_SIZE(co_code_bytes);
            Py_ssize_t show = (size < 32) ? size : 32;

            fprintf(stderr, "co_code (hex)  : ");
            for (Py_ssize_t i = 0; i < show; ++i) {
                fprintf(stderr, "%02x ", (unsigned char)bytes[i]);
            }
            fprintf(stderr, "\n");

            Py_DECREF(co_code_bytes);
        }
    } else {
        const char *bytes = PyBytes_AS_STRING(co_code_bytes);
        Py_ssize_t size = PyBytes_Size(co_code_bytes);
        Py_ssize_t show = (size < 32) ? size : 32;

        fprintf(stderr, "co_code (hex)  : ");
        for (Py_ssize_t i = 0; i < show; ++i) {
            fprintf(stderr, "%02x ", (unsigned char)bytes[i]);
        }
        fprintf(stderr, "\n");
    }
    
    if (_PyCode_NBYTES(co) >= 2) {
        _Py_CODEUNIT *instructions = _PyCode_CODE(co);
        _Py_CODEUNIT first = instructions[0];
        unsigned char opcode = _Py_OPCODE(first);
        unsigned short oparg = _Py_OPARG(first);

        if (opcode == 0x74) { // LOAD_GLOBAL
            int name_idx = oparg >> 1;
            int push_null = oparg & 1;
            fprintf(stderr,
                    "                 ⚠️  First instr: LOAD_GLOBAL oparg=%u → name_idx=%d, push_null=%d\n",
                    oparg, name_idx, push_null);
        }
    }

    fprintf(stderr, "========================================\n\n");
    fflush(stderr);
}
