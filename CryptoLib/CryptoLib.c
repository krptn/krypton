#include <Python.h>
#include <crypto.h>

/*
 * Implements an example function.
 */
PyDoc_STRVAR(CryptoLib_example_doc, "example(obj, number)\
\
Example function");

PyObject *AESEn(PyObject *self, PyObject *args, PyObject *kwargs) {
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
 * List of functions to add to CryptoLib in exec_CryptoLib().
 */
static PyMethodDef CryptoLib_functions[] = {
    { "EncryptAES", (PyCFunction)AESEn, METH_VARARGS | METH_KEYWORDS, "Encrypts AES in CBC 256." },
    { NULL, NULL, 0, NULL } /* marks end of array */
};

/*
 * Initialize CryptoLib. May be called multiple times, so avoid
 * using static state.
 */
int exec_CryptoLib(PyObject *module) {
    PyModule_AddFunctions(module, CryptoLib_functions);

    PyModule_AddStringConstant(module, "__author__", "Mark");
    PyModule_AddStringConstant(module, "__version__", "1.0.0");
    PyModule_AddIntConstant(module, "year", 2021);

    return 0; /* success */
}

/*
 * Documentation for CryptoLib.
 */
PyDoc_STRVAR(CryptoLib_doc, "The CryptoLib module");


static PyModuleDef_Slot CryptoLib_slots[] = {
    { Py_mod_exec, exec_CryptoLib },
    { 0, NULL }
};

static PyModuleDef CryptoLib_def = {
    PyModuleDef_HEAD_INIT,
    "CryptoLib",
    CryptoLib_doc,
    0,              /* m_size */
    NULL,           /* m_methods */
    CryptoLib_slots,
    NULL,           /* m_traverse */
    NULL,           /* m_clear */
    NULL,           /* m_free */
};

PyMODINIT_FUNC PyInit_CryptoLib() {
    return PyModuleDef_Init(&CryptoLib_def);
}
