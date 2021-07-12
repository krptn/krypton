#include <Python.h>

/*
 * Implements an example function.
 */
PyDoc_STRVAR(CryptoLibLinux_example_doc, "example(obj, number)\
\
Example function");

PyObject *CryptoLibLinux_example(PyObject *self, PyObject *args, PyObject *kwargs) {
    /* Shared references that do not need Py_DECREF before returning. */
    PyObject *obj = NULL;
    int number = 0;

    /* Parse positional and keyword arguments */
    static char* keywords[] = { "obj", "number", NULL };
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Oi", keywords, &obj, &number)) {
        return NULL;
    }

    /* Function implementation starts here */

    if (number < 0) {
        PyErr_SetObject(PyExc_ValueError, obj);
        return NULL;    /* return NULL indicates error */
    }

    Py_RETURN_NONE;
}

/*
 * List of functions to add to CryptoLibLinux in exec_CryptoLibLinux().
 */
static PyMethodDef CryptoLibLinux_functions[] = {
    { "example", (PyCFunction)CryptoLibLinux_example, METH_VARARGS | METH_KEYWORDS, CryptoLibLinux_example_doc },
    { NULL, NULL, 0, NULL } /* marks end of array */
};

/*
 * Initialize CryptoLibLinux. May be called multiple times, so avoid
 * using static state.
 */
int exec_CryptoLibLinux(PyObject *module) {
    PyModule_AddFunctions(module, CryptoLibLinux_functions);

    PyModule_AddStringConstant(module, "__author__", "Mark");
    PyModule_AddStringConstant(module, "__version__", "1.0.0");
    PyModule_AddIntConstant(module, "year", 2021);

    return 0; /* success */
}

/*
 * Documentation for CryptoLibLinux.
 */
PyDoc_STRVAR(CryptoLibLinux_doc, "The CryptoLibLinux module");


static PyModuleDef_Slot CryptoLibLinux_slots[] = {
    { Py_mod_exec, exec_CryptoLibLinux },
    { 0, NULL }
};

static PyModuleDef CryptoLibLinux_def = {
    PyModuleDef_HEAD_INIT,
    "CryptoLibLinux",
    CryptoLibLinux_doc,
    0,              /* m_size */
    NULL,           /* m_methods */
    CryptoLibLinux_slots,
    NULL,           /* m_traverse */
    NULL,           /* m_clear */
    NULL,           /* m_free */
};

PyMODINIT_FUNC PyInit_CryptoLibLinux() {
    return PyModuleDef_Init(&CryptoLibLinux_def);
}
