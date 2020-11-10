#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <memory.h>

#include <crypt.h>

#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>

#include <openssl/sha.h>

#include "Python.h"
#include "structmember.h"


typedef unsigned char BYTE;
typedef unsigned int  WORD;


/* CPython MD4Hash Object Data */

#ifndef MD4_H
#define MD4_H

#define MD4_BLOCK_SIZE 16

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[MD4_BLOCK_SIZE + 1];
	char __c_hex_value[(MD4_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} MD4Hash;

#endif

static void MD4Hash_dealloc(MD4Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * MD4Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	MD4Hash * self;

	self = (MD4Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int MD4Hash_init(MD4Hash * self, PyObject * args, PyObject * kwds) {

	PyObject * plaintext;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * MD4Hash_digest(MD4Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);

	if (pt_repr == NULL) {
		return NULL;
;	}

	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");
	const char * plaintext = PyBytes_AsString(pt_str);

	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	MD4_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < MD4_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[MD4_BLOCK_SIZE] = '\0';
	self->__c_hex_value[MD4_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * MD4Hash_digest_dict(MD4Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);

	if (pt_repr == NULL) {
		return NULL;
;	}

	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");
	const char * plaintext = PyBytes_AsString(pt_str);

	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	MD4_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < MD4_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[MD4_BLOCK_SIZE] = '\0';
	self->__c_hex_value[MD4_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);


	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef MD4Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(MD4Hash, plaintext), 0, "MD4 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(MD4Hash, value), 0, "MD4 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(MD4Hash, hex_value), 0, "MD4 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef MD4Hash_methods[] = {
	{"digest", (PyCFunction)MD4Hash_digest, METH_NOARGS, "Digest MD4 hash object (returns raw hash)"},
	{"digest_dict", (PyCFunction)MD4Hash_digest_dict, METH_NOARGS, "Digest MD4 hash object (returns dictionary with raw hash and hex hash)"},
	{NULL}
};

static PyTypeObject MD4HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.MD4Hash",
	.tp_basicsize = sizeof(MD4Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = MD4Hash_new,
	.tp_init = (initproc)MD4Hash_init,
	.tp_dealloc = (destructor)MD4Hash_dealloc,
	.tp_members = MD4Hash_members,
	.tp_methods = MD4Hash_methods,
};


/* CPython MD5Hash Object Data */

#ifndef MD5_H
#define MD5_H

#define MD5_BLOCK_SIZE 16

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[MD5_BLOCK_SIZE + 1];
	char __c_hex_value[(MD5_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} MD5Hash;

#endif

static void MD5Hash_dealloc(MD5Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * MD5Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	MD5Hash * self;

	self = (MD5Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int MD5Hash_init(MD5Hash * self, PyObject * args, PyObject * kwds) {

	PyObject * plaintext;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * MD5Hash_digest(MD5Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);

	if (pt_repr == NULL) {
		return NULL;
;	}

	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");
	const char * plaintext = PyBytes_AsString(pt_str);

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	MD5_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < MD5_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[MD5_BLOCK_SIZE] = '\0';
	self->__c_hex_value[MD5_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * MD5Hash_digest_dict(MD5Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);

	if (pt_repr == NULL) {
		return NULL;
;	}

	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");
	const char * plaintext = PyBytes_AsString(pt_str);

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	MD5_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < MD5_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[MD5_BLOCK_SIZE] = '\0';
	self->__c_hex_value[MD5_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);


	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef MD5Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(MD5Hash, plaintext), 0, "MD5 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(MD5Hash, value), 0, "MD5 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(MD5Hash, hex_value), 0, "MD5 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef MD5Hash_methods[] = {
	{"digest", (PyCFunction)MD5Hash_digest, METH_NOARGS, "Digest MD5 hash object (returns raw hash)"},
	{"digest_dict", (PyCFunction)MD5Hash_digest_dict, METH_NOARGS, "Digest MD5 hash object (returns dictionary with raw hash and hex hash)"},
	{NULL}
};

static PyTypeObject MD5HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.MD5Hash",
	.tp_basicsize = sizeof(MD5Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = MD5Hash_new,
	.tp_init = (initproc)MD5Hash_init,
	.tp_dealloc = (destructor)MD5Hash_dealloc,
	.tp_members = MD5Hash_members,
	.tp_methods = MD5Hash_methods,
};



/* CPython SHA1Hash Object Data */

#ifndef SHA1_H
#define SHA1_H

#define SHA1_BLOCK_SIZE 20

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[SHA1_BLOCK_SIZE + 1];
	char __c_hex_value[(SHA1_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} SHA1Hash;

#endif

static void SHA1Hash_dealloc(SHA1Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * SHA1Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	SHA1Hash * self;

	self = (SHA1Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int SHA1Hash_init(SHA1Hash * self, PyObject * args, PyObject * kwds) {
	PyObject * plaintext = NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * SHA1Hash_digest(SHA1Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA1_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA1_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA1_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA1_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * SHA1Hash_digest_dict(SHA1Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA1_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA1_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA1_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA1_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef SHA1Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(SHA1Hash, plaintext), 0, "SHA1 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(SHA1Hash, value), 0, "SHA1 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(SHA1Hash, hex_value), 0, "SHA1 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef SHA1Hash_methods[] = {
	{"digest", (PyCFunction)SHA1Hash_digest, METH_NOARGS, "Digest SHA1 hash object (returns hash)"},
	{"digest_dict", (PyCFunction)SHA1Hash_digest_dict, METH_NOARGS, "Digest SHA1 hash object (returns hash)"},

	{NULL}
};

static PyTypeObject SHA1HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.SHA1Hash",
	.tp_basicsize = sizeof(SHA1Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = SHA1Hash_new,
	.tp_init = (initproc)SHA1Hash_init,
	.tp_dealloc = (destructor)SHA1Hash_dealloc,
	.tp_members = SHA1Hash_members,
	.tp_methods = SHA1Hash_methods,
};


/* CPython SHA224Hash Object Data */

#ifndef SHA224_H
#define SHA224_H

#define SHA224_BLOCK_SIZE 28

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[SHA224_BLOCK_SIZE + 1];
	char __c_hex_value[(SHA224_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} SHA224Hash;

#endif

#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLOCK_SIZE 32

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[SHA256_BLOCK_SIZE + 1];
	char __c_hex_value[(SHA256_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} SHA256Hash;

#endif

static void SHA224Hash_dealloc(SHA224Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * SHA224Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	SHA224Hash * self;

	self = (SHA224Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int SHA224Hash_init(SHA224Hash * self, PyObject * args, PyObject * kwds) {
	PyObject * plaintext = NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * SHA224Hash_digest(SHA224Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA256_CTX ctx;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA224_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA224_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA224_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA224_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * SHA224Hash_digest_dict(SHA224Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA256_CTX ctx;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA224_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA224_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA224_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA224_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef SHA224Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(SHA224Hash, plaintext), 0, "SHA224 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(SHA224Hash, value), 0, "SHA224 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(SHA224Hash, hex_value), 0, "SHA224 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef SHA224Hash_methods[] = {
	{"digest", (PyCFunction)SHA224Hash_digest, METH_NOARGS, "Digest SHA224 hash object (returns hash)"},
	{"digest_dict", (PyCFunction)SHA224Hash_digest_dict, METH_NOARGS, "Digest SHA224 hash object (returns hash)"},
	{NULL}
};

static PyTypeObject SHA224HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.SHA224Hash",
	.tp_basicsize = sizeof(SHA224Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = SHA224Hash_new,
	.tp_init = (initproc)SHA224Hash_init,
	.tp_dealloc = (destructor)SHA224Hash_dealloc,
	.tp_members = SHA224Hash_members,
	.tp_methods = SHA224Hash_methods,
};


/* CPython SHA256Hash Object Data */

#ifndef SHA384_H
#define SHA384_H

#define SHA384_BLOCK_SIZE 48

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[SHA384_BLOCK_SIZE + 1];
	char __c_hex_value[(SHA384_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} SHA384Hash;

#endif

static void SHA256Hash_dealloc(SHA256Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * SHA256Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	SHA256Hash * self;

	self = (SHA256Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int SHA256Hash_init(SHA256Hash * self, PyObject * args, PyObject * kwds) {
	PyObject * plaintext = NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * SHA256Hash_digest(SHA256Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA256_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA256_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA256_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * SHA256Hash_digest_dict(SHA256Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA256_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA256_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA256_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef SHA256Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(SHA256Hash, plaintext), 0, "SHA256 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(SHA256Hash, value), 0, "SHA256 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(SHA256Hash, hex_value), 0, "SHA256 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef SHA256Hash_methods[] = {
	{"digest", (PyCFunction)SHA256Hash_digest, METH_NOARGS, "Digest SHA256 hash object (returns hash)"},
	{"digest_dict", (PyCFunction)SHA256Hash_digest_dict, METH_NOARGS, "Digest SHA256 hash object (returns hash)"},
	{NULL}
};

static PyTypeObject SHA256HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.SHA256Hash",
	.tp_basicsize = sizeof(SHA256Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = SHA256Hash_new,
	.tp_init = (initproc)SHA256Hash_init,
	.tp_dealloc = (destructor)SHA256Hash_dealloc,
	.tp_members = SHA256Hash_members,
	.tp_methods = SHA256Hash_methods,
};



/* CPython SHA384Hash Object Data */

static void SHA384Hash_dealloc(SHA384Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * SHA384Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	SHA384Hash * self;

	self = (SHA384Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int SHA384Hash_init(SHA384Hash * self, PyObject * args, PyObject * kwds) {
	PyObject * plaintext = NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * SHA384Hash_digest(SHA384Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA384_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA384_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA384_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA384_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * SHA384Hash_digest_dict(SHA384Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA384_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA384_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA384_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA384_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef SHA384Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(SHA384Hash, plaintext), 0, "SHA384 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(SHA384Hash, value), 0, "SHA384 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(SHA384Hash, hex_value), 0, "SHA384 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef SHA384Hash_methods[] = {
	{"digest", (PyCFunction)SHA384Hash_digest, METH_NOARGS, "Digest SHA384 hash object (returns hash)"},
	{"digest_dict", (PyCFunction)SHA384Hash_digest_dict, METH_NOARGS, "Digest SHA384 hash object (returns hash)"},
	{NULL}
};

static PyTypeObject SHA384HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.SHA384Hash",
	.tp_basicsize = sizeof(SHA384Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = SHA384Hash_new,
	.tp_init = (initproc)SHA384Hash_init,
	.tp_dealloc = (destructor)SHA384Hash_dealloc,
	.tp_members = SHA384Hash_members,
	.tp_methods = SHA384Hash_methods,
};


/* CPython SHA512Hash Object Data */

#ifndef SHA512_H
#define SHA512_H

#define SHA512_BLOCK_SIZE 64

typedef struct {
	PyObject_HEAD

	PyObject * plaintext;

	char __c_value[SHA512_BLOCK_SIZE + 1];
	char __c_hex_value[(SHA512_BLOCK_SIZE * 2) + 1];

	PyObject * value;
	PyObject * hex_value;
} SHA512Hash;

#endif

static void SHA512Hash_dealloc(SHA512Hash * self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->value);
	Py_XDECREF(self->hex_value);

	memset(self->__c_value, '\0', sizeof(self->__c_value));
	memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject * SHA512Hash_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	SHA512Hash * self;

	self = (SHA512Hash *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");
		self->value = PyUnicode_FromString("");
		self->hex_value = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->__c_value, '\0', sizeof(self->__c_value));
		memset(self->__c_hex_value, '\0', sizeof(self->__c_hex_value));
	}

	return (PyObject *)self;
}

static int SHA512Hash_init(SHA512Hash * self, PyObject * args, PyObject * kwds) {
	PyObject * plaintext = NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "O", &plaintext)) {
		return -1;
	}

	if (plaintext) {
		copy = self->plaintext;
		Py_INCREF(plaintext);
		self->plaintext = plaintext;
		Py_XDECREF(copy);
	}

	Py_INCREF(self->value);
	Py_INCREF(self->hex_value);

	return 0;
}

static PyObject * SHA512Hash_digest(SHA512Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA512_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA512_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA512_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA512_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	return PyBytes_FromFormat("%s", self->__c_value);
}

static PyObject * SHA512Hash_digest_dict(SHA512Hash * self, PyObject * Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "plaintext");

		return NULL;
	}

	PyObject * pt_repr = PyObject_Str(self->plaintext);
	PyObject * pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char * plaintext = PyBytes_AsString(pt_str);

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (BYTE*)plaintext, strlen(plaintext));
	SHA512_Final((BYTE*)self->__c_value, &ctx);

	for (int i = 0; i < SHA512_BLOCK_SIZE; ++i) {
		snprintf(self->__c_hex_value + (i * 2), sizeof(self->__c_hex_value), "%02x", self->__c_value[i] & 0xFF);
	}

	self->__c_value[SHA512_BLOCK_SIZE] = '\0';
	self->__c_hex_value[SHA512_BLOCK_SIZE * 2] = '\0';

	self->value = PyBytes_FromString(self->__c_value);
	self->hex_value = PyBytes_FromString(self->__c_hex_value);

	Py_XDECREF(pt_repr);
	Py_XDECREF(pt_str);

	PyObject * plaintext_key = PyUnicode_FromString("plaintext");
	PyObject * raw_key = PyUnicode_FromString("raw");
	PyObject * raw_item = PyBytes_FromFormat("%s", self->__c_value);
	PyObject * hex_key = PyUnicode_FromString("hex");
	PyObject * hex_item = PyUnicode_FromFormat("%s", self->__c_hex_value);

	PyObject * hash_dict = PyDict_New();

	PyDict_SetItem(hash_dict, plaintext_key, self->plaintext);
	PyDict_SetItem(hash_dict, raw_key, raw_item);
	PyDict_SetItem(hash_dict, hex_key, hex_item);

/*	{"raw": "(raw hash)", "hex": "(hex-encoded hash)", "plaintext" "(original plaintext)"} */

	Py_XDECREF(raw_key);
	Py_XDECREF(raw_item);
	Py_XDECREF(hex_key);
	Py_XDECREF(hex_item);

	return hash_dict;
}

static PyMemberDef SHA512Hash_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(SHA512Hash, plaintext), 0, "SHA512 Plaintext"},
	{"value", T_OBJECT_EX, offsetof(SHA512Hash, value), 0, "SHA512 Hash digest value (raw)"},
	{"hex_value", T_OBJECT_EX, offsetof(SHA512Hash, hex_value), 0, "SHA512 Hash digest value (hex)"},

	{NULL}
};

static PyMethodDef SHA512Hash_methods[] = {
	{"digest", (PyCFunction)SHA512Hash_digest, METH_NOARGS, "Digest SHA512 hash object (returns hash)"},
	{"digest_dict", (PyCFunction)SHA512Hash_digest_dict, METH_NOARGS, "Digest SHA512 hash object (returns hash)"},
	{NULL}
};

static PyTypeObject SHA512HashType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.SHA512Hash",
	.tp_basicsize = sizeof(SHA512Hash),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = SHA512Hash_new,
	.tp_init = (initproc)SHA512Hash_init,
	.tp_dealloc = (destructor)SHA512Hash_dealloc,
	.tp_members = SHA512Hash_members,
	.tp_methods = SHA512Hash_methods,
};


/* Dictionary Attack Objects & Methods */

typedef struct {
	PyObject_HEAD

	PyObject * wordlist_path;

	MD4_CTX md4_ctx;
	MD5_CTX md5_ctx;
	SHA_CTX sha1_ctx;
	SHA256_CTX sha224_ctx, sha256_ctx;
	SHA512_CTX sha384_ctx, sha512_ctx;

	PyObject * plaintext;
	PyObject * hash_value;
	PyObject * hash_type;
	PyObject * cracked;
//	PyObject * background;

	int attempt;
	int completed;
} DictionaryAttackObject;

static void DictionaryAttack_dealloc(DictionaryAttackObject * self) {
	Py_XDECREF(self->wordlist_path);
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->hash_value);
	Py_XDECREF(self->hash_type);
	Py_XDECREF(self->cracked);
//	Py_XDECREF(self->background);

	memset(&self->md4_ctx, 0, sizeof(MD4_CTX));
	memset(&self->md5_ctx, 0, sizeof(MD5_CTX));
	memset(&self->sha1_ctx, 0, sizeof(SHA_CTX));
	memset(&self->sha224_ctx, 0, sizeof(SHA256_CTX));
	memset(&self->sha256_ctx, 0, sizeof(SHA256_CTX));
	memset(&self->sha384_ctx, 0, sizeof(SHA512_CTX));
	memset(&self->sha512_ctx, 0, sizeof(SHA512_CTX));

	self->attempt = 0;
	self->completed = 0;
}

static PyObject * DictionaryAttack_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	DictionaryAttackObject * self;

	self = (DictionaryAttackObject*)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->wordlist_path = PyUnicode_FromString("");
		self->plaintext = PyUnicode_FromString("");
		self->hash_value = PyUnicode_FromString("");
		self->hash_type = PyUnicode_FromString("");
		self->cracked = Py_False;
		//self->background = Py_False;

		if (self->wordlist_path == NULL || self->plaintext == NULL || self->hash_value == NULL || self->hash_type == NULL || self->cracked == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		self->attempt = 0;
		self->completed = 0;
	}

	return (PyObject *)self;
}

static int DictionaryAttack_init(DictionaryAttackObject * self, PyObject * args, PyObject * kwds) {
	PyObject * hash_value = NULL;
	PyObject * wordlist_path= NULL;
	PyObject * copy;

	if (!PyArg_ParseTuple(args, "OO", &hash_value, &wordlist_path))
		return -1;

	if (hash_value) {
		copy = self->hash_value;
		Py_INCREF(hash_value);
		self->hash_value = hash_value;
		Py_XDECREF(copy);
	}

	if (wordlist_path) {
		copy = self->wordlist_path;
		Py_INCREF(wordlist_path);
		self->wordlist_path = wordlist_path;
		Py_XDECREF(copy);
	}

	PyObject * wordlist_path_repr = PyObject_Str(self->wordlist_path);
	PyObject * wordlist_path_str = PyUnicode_AsEncodedString(wordlist_path_repr, "ascii", "~E~");

	const char * __c_wordlist_path = PyBytes_AsString(wordlist_path_str);

	if (access(__c_wordlist_path, F_OK) != 0) {
		PyErr_Format(PyExc_FileNotFoundError, "Cannot open file (%s).", __c_wordlist_path);

		return -1;
	}

	return 0;
}

int __c_DictionaryAttack(const char __hash_value[], const char * hash_type, const char * wordlist_path, DictionaryAttackObject * dao, char * error_buf, size_t error_buf_len) {
	FILE * wordlist_file = fopen(wordlist_path, "r");

	if (wordlist_file == NULL) {
		snprintf(error_buf, error_buf_len, "Could not open file (%s): %s", wordlist_path, strerror(errno));
		return -1;
	}

	char * hash_value = strdup(__hash_value);

	for (int i = 0; i < strlen(__hash_value); ++i) {
		if (isalpha(__hash_value[i]))
			hash_value[i] = tolower(__hash_value[i]);
	}

	int c = 0;

	if (!strcmp(hash_type, "md5")) {
		c = 1;
		dao->hash_type = PyUnicode_FromString("MD5");
	} else if (!strcmp(hash_type, "sha1")) {
		c = 2;
		dao->hash_type = PyUnicode_FromString("SHA1");
	} else if (!strcmp(hash_type, "sha224")) {
		c = 3;
		dao->hash_type = PyUnicode_FromString("SHA224");
	} else if (!strcmp(hash_type, "sha256")) {
		c = 4;
		dao->hash_type = PyUnicode_FromString("SHA256");
	} else if (!strcmp(hash_type, "sha384")) {
		c = 5;
		dao->hash_type = PyUnicode_FromString("SHA384");
	} else if (!strcmp(hash_type, "sha512")) {
		c = 6;
		dao->hash_type = PyUnicode_FromString("SHA512");
	} else {
		snprintf(error_buf, error_buf_len, "%s is not a valid hash type choice", hash_type);

		return -1;
	}

	char word[128];
	unsigned char digest[SHA512_BLOCK_SIZE + 1];
	char hexdigest[(SHA512_BLOCK_SIZE * 2) + 1]; // SHA512 is the largest block size. safe for all hashes

		memset(digest, '\0', sizeof(digest));
		memset(hexdigest, '\0', sizeof(hexdigest));

		word[strlen(word) - 1] = '\0';

		if (c == 1) {
			MD5((unsigned char *)word, strlen(word), digest);
			digest[MD5_BLOCK_SIZE] = '\0';

			for (int i = 0; i < MD5_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA512_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[MD5_BLOCK_SIZE * 2] = '\0';
		} else if (c == 2) {
			SHA1((unsigned char *)word, strlen(word), digest);
			digest[SHA1_BLOCK_SIZE] = '\0';

			for (int i = 0; i < SHA1_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA1_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[SHA1_BLOCK_SIZE * 2] = '\0';
		} else if (c == 3) {
			SHA224((unsigned char *)word, strlen(word), digest);
			digest[SHA224_BLOCK_SIZE] = '\0';

			for (int i = 0; i < SHA224_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA224_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[SHA224_BLOCK_SIZE * 2] = '\0';
		} else if (c == 4) {
			SHA256((unsigned char *)word, strlen(word), digest);
			digest[SHA256_BLOCK_SIZE] = '\0';

			for (int i = 0; i < SHA256_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA256_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[SHA256_BLOCK_SIZE * 2] = '\0';
		} else if (c == 5) {
			SHA384((unsigned char *)word, strlen(word), digest);
			digest[SHA384_BLOCK_SIZE] = '\0';

			for (int i = 0; i < SHA384_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA384_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[SHA384_BLOCK_SIZE * 2] = '\0';
		} else if (c == 6) {
			SHA512((unsigned char *)word, strlen(word), digest);
			digest[SHA512_BLOCK_SIZE] = '\0';

			for (int i = 0; i < SHA512_BLOCK_SIZE; ++i)
				snprintf(hexdigest + (i * 2), SHA512_BLOCK_SIZE * 2, "%02x", digest[i] & 0xFF);

			hexdigest[SHA512_BLOCK_SIZE * 2] = '\0';
		}

		dao->attempt++;
		if (!strncmp(hash_value, hexdigest, strlen(hexdigest))) {
			dao->plaintext = PyBytes_FromFormat("%s", word);
			dao->cracked = Py_True;

			return 1;
		}

		memset(word, '\0', sizeof(word));
	}

	return 0;
}

static PyObject * DictionaryAttack_start(DictionaryAttackObject * self, PyObject * Py_UNUSED(ignored)) {
	if (self->hash_value == NULL) {
		PyErr_SetString(PyExc_AttributeError, "Attribute 'hash_value' hash not been set.");

		return NULL;
	}

	if (self->wordlist_path == NULL) {
		PyErr_SetString(PyExc_AttributeError, "Attribute 'wordlist_path' has not been set.");

		return NULL;
	}

/*
	if (self->background == NULL) {
		PyErr_SetString(PyExc_AttributeError, "Attribute 'background' has not been set.");

		return NULL;
	}
*/

	PyObject * hash_value_repr = PyObject_Str(self->hash_value);
	PyObject * hash_value_str = PyUnicode_AsEncodedString(hash_value_repr, "ascii", "~E~");

	PyObject * wordlist_path_repr = PyObject_Str(self->wordlist_path);
	PyObject * wordlist_path_str = PyUnicode_AsEncodedString(wordlist_path_repr, "ascii", "~E~");

	const char * hash_value = PyBytes_AsString(hash_value_str);
	const char * wordlist_path = PyBytes_AsString(wordlist_path_str);

	char * hash_type;
	size_t hash_value_len = strlen(hash_value);

	if (hash_value_len == 32)
		hash_type = "md5";
	else if (hash_value_len == 40)
		hash_type = "sha1";
	else if (hash_value_len == 56)
		hash_type = "sha224";
	else if (hash_value_len == 64)
		hash_type = "sha256";
	else if (hash_value_len == 96)
		hash_type = "sha384";
	else if (hash_value_len == 128)
		hash_type = "sha512";
	else {
		PyErr_Format(PyExc_ValueError, "(Hash length: %ld): Could not identify the hash.", hash_value_len);

		return NULL;
	}

	char error_buf[512];

	int status = __c_DictionaryAttack(hash_value, hash_type, wordlist_path, self, error_buf, sizeof(error_buf));
	self->completed = 1;

	if (status && self->cracked)
		return Py_True;
	else if (status < 0) {
		PyErr_SetString(PyExc_RuntimeError, error_buf);

		return NULL;
	}

	return Py_False;
}

static PyMemberDef DictionaryAttack_members[] = {
	{"wordlist_path", T_OBJECT_EX, offsetof(DictionaryAttackObject, wordlist_path), 0, "The full path of the wordlist to use for the dictionary attack"},
	{"hash_value", T_OBJECT_EX, offsetof(DictionaryAttackObject, hash_value), 0, "Hex value of a hash"},
	{"hash_type", T_OBJECT_EX, offsetof(DictionaryAttackObject, hash_type), 0, "The hash type of the....... hash"},
	{"plaintext", T_OBJECT_EX, offsetof(DictionaryAttackObject, plaintext), 0, "The plaintext of the hash (will not be empty if cracked)"},
	{"cracked", T_OBJECT_EX, offsetof(DictionaryAttackObject, cracked), 0, "Boolean/Int representing if the hash has been cracked"},
	{"attempt", T_INT, offsetof(DictionaryAttackObject, attempt), 0, "Integer representing how many hashes have been calculated"},
	{"completed", T_INT, offsetof(DictionaryAttackObject, completed), 0, "Boolean/Int representing if the attack is completed"},

	{NULL}
};

static PyMethodDef DictionaryAttack_methods[] = {
	{"start", (PyCFunction)DictionaryAttack_start, METH_NOARGS, "Start the dictionary attack"},

	{NULL}
};

static PyTypeObject DictionaryAttackType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "easycracker.DictionaryAttack",
	.tp_doc = "DictionaryAttack object",
	.tp_basicsize = sizeof(DictionaryAttackObject),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = DictionaryAttack_new,
	.tp_init = (initproc)DictionaryAttack_init,
	.tp_dealloc = (destructor)DictionaryAttack_dealloc,
	.tp_members = DictionaryAttack_members,
	.tp_methods = DictionaryAttack_methods,
};


/* Module Setup */

static PyModuleDef easycrackermodule = {
	PyModuleDef_HEAD_INIT,
	.m_name = "easycracker",
	.m_doc = "A simple to use, hash dictionary attack module",
	.m_size = -1,
};

PyMODINIT_FUNC PyInit_easycracker(void) {
	PyObject *m;

	if (PyType_Ready(&MD4HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&MD5HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&SHA1HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&SHA224HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&SHA256HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&SHA384HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&SHA512HashType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&DictionaryAttackType) < 0) {
		return NULL;
	}

	m = PyModule_Create(&easycrackermodule);

	if (m == NULL) {
		return NULL;
	}

	Py_INCREF(&MD4HashType);
	Py_INCREF(&MD5HashType);
	Py_INCREF(&SHA1HashType);
	Py_INCREF(&SHA224HashType);
	Py_INCREF(&SHA256HashType);
	Py_INCREF(&SHA384HashType);
	Py_INCREF(&SHA512HashType);
	Py_INCREF(&DictionaryAttackType);

	if (PyModule_AddObject(m, "MD4Hash", (PyObject *)&MD4HashType) < 0){
		Py_DECREF(&MD4HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "MD5Hash", (PyObject *)&MD5HashType) < 0) {
		Py_DECREF(&MD5HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "SHA1Hash", (PyObject *)&SHA1HashType) < 0) {
		Py_DECREF(&SHA256HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "SHA224Hash", (PyObject *)&SHA224HashType) < 0) {
		Py_DECREF(&SHA224HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "SHA256Hash", (PyObject *)&SHA256HashType) < 0) {
		Py_DECREF(&SHA256HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "SHA384Hash", (PyObject *)&SHA384HashType) < 0) {
		Py_DECREF(&SHA384HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "SHA512Hash", (PyObject *)&SHA512HashType) < 0) {
		Py_DECREF(&SHA512HashType);
		Py_DECREF(m);

		return NULL;
	}

	if (PyModule_AddObject(m, "DictionaryAttack", (PyObject *)&DictionaryAttackType) < 0) {
		Py_DECREF(&DictionaryAttackType);
		Py_DECREF(m);

		return NULL;
	}

	return m;
}
