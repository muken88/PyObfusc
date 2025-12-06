//
//  mk_print.h
//  PyObfusc
//
//  Created by muken on 2025/12/3.
//

#ifndef mk_print_h
#define mk_print_h

#include <stdio.h>
#include <Python.h>

void print_bytecode(PyObject *code_obj);
void print_co_names(PyObject *code);

void clear_opcode_cache(void);

#endif /* mk_print_h */






