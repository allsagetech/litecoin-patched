#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "crypto/scrypt.h"

/**
 * getPoWHash(header: bytes) -> bytes
 *
 * header must be exactly 80 bytes (a Litecoin block header).
 * Returns the 32-byte scrypt_1024_1_1_256 hash, using the same
 * implementation and prototype as src/crypto/scrypt.h:
 *
 *   void scrypt_1024_1_1_256(const char* input, char* output);
 */
static PyObject* getPoWHash(PyObject* self, PyObject* args)
{
    const unsigned char* header = nullptr;
    Py_ssize_t header_len = 0;

    // Parse a single bytes-like argument
    if (!PyArg_ParseTuple(args, "y#", &header, &header_len)) {
        return nullptr;
    }

    if (header_len != 80) {
        PyErr_SetString(PyExc_ValueError, "expected 80-byte block header");
        return nullptr;
    }

    unsigned char out[32];

    // Call Litecoin's scrypt_1024_1_1_256 exactly as declared in scrypt.h
    scrypt_1024_1_1_256(
        reinterpret_cast<const char*>(header),
        reinterpret_cast<char*>(out)
    );

    return PyBytes_FromStringAndSize(
        reinterpret_cast<const char*>(out),
        32
    );
}

static PyMethodDef Methods[] = {
    {"getPoWHash", getPoWHash, METH_VARARGS,
     "Compute Litecoin PoW hash (scrypt_1024_1_1_256) for an 80-byte block header."},
    {nullptr, nullptr, 0, nullptr}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_litecoin_scrypt",
    nullptr,
    -1,
    Methods
};

PyMODINIT_FUNC PyInit__litecoin_scrypt(void)
{
    return PyModule_Create(&moduledef);
}
