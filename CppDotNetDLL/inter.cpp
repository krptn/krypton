#include "inter.h"
#include <stdio.h>
#define PY_SSIZE_T_CLEAN
#include <Python.h>

using namespace System;
#using "..\PythonCSharp\bin\Release\net5.0\PythonCSharp.dll"  //Asssembly
using namespace intdotnet;
#include <string.h>
using namespace System::Runtime::InteropServices;
#include < stdlib.h >
#include < vcclr.h >
#include<tuple>
#include <iostream> 
using namespace System::IO;
using namespace Reflection;
using namespace std;

#define DLLEXPORT extern "C" __declspec(dllexport)
#pragma managed

class crypto {
	public:
		static Assembly^ AssemblyResolve(Object^ Sender, ResolveEventArgs^ args)
		{
			AssemblyName^ assemblyName = gcnew AssemblyName(args->Name);

			if (assemblyName->Name == "PythonCSharp")
			{
				String^ path = Path::Combine(Path::GetDirectoryName(Assembly::GetExecutingAssembly()->Location), "PythonCSharp.dll");

				return Assembly::LoadFile(path);
			}

			return nullptr;
		}
		static void Initialize()
		{
				AppDomain::CurrentDomain->AssemblyResolve += gcnew ResolveEventHandler(AssemblyResolve);
		}
		static std::tuple<char, char> AESEncrypt(char* text, char* key) {
			cli::array< Byte >^ bytekey = gcnew cli::array< Byte >((strlen(key) + 1);
			Marshal::Copy((IntPtr)*key, bytekey, 0, strlen(*key));
			GCHandle handlekey = GCHandle::Alloc(bytekey, GCHandleType::Pinned);
			memset(key, 0, strlen(*key));


			cli::array< Byte > ^ bytetext = gcnew cli::array< Byte >(strlen(text) + 1);
			Marshal::Copy((IntPtr)text, bytetext, 0, strlen(key));
			GCHandle handleiv = GCHandle::Alloc(bytetext, GCHandleType::Pinned);
			memset(text, 0, strlen(text));

			ValueTuple<cli::array <unsigned char>^, cli::array <unsigned char>^>  result = Crypto::AESEncrypt(bytetext, bytekey);
			GCHandle handleresult = GCHandle::Alloc(result, GCHandleType::Pinned);
			char* iv = new char[(result.Item1->Length)];
			char* ctext = new char[(result.Item2->Length)];


			for (int i = 0; i < result.Item1->Length; i++) {
				ctext[i] = result.Item1[i];
			}
			for (int i = 0; i < result.Item2->Length; i++) {
				ctext[i] = result.Item2[i];
			}
			memset(&bytekey, 0, bytekey->Length);
			memset(&bytetext, 0, bytetext->Length);
			delete bytekey;
			delete bytetext;
			memset(&text, 0, strlen(text));
			memset(&key, 0, strlen(key));
			delete key;
			delete text;
			delete result;
			std::tuple<char, char> a = { *ctext, *iv };
			return a;
		};

		static char* AESDecrypt(char* iv, char* key, char* ctext) {
			cli::array< Byte >^ bytekey = gcnew cli::array< Byte >((strlen(key) + 1));
			Marshal::Copy((IntPtr)*key, bytekey, 0, strlen(*key));
			GCHandle handlekey = GCHandle::Alloc(bytekey, GCHandleType::Pinned);
			memset(*key, 0, strlen(*key));
			cli::array< Byte >^ byteiv = gcnew cli::array< Byte >(strlen(iv) + 1);
			Marshal::Copy((IntPtr)*iv, byteiv, 0, strlen(*key));
			GCHandle handleiv = GCHandle::Alloc(byteiv, GCHandleType::Pinned);

			cli::array< Byte >^ bytectext = gcnew cli::array< Byte >(strlen(ctext) + 1);
			Marshal::Copy((IntPtr)*ctext, bytectext, 0, strlen(*ctext));
			GCHandle handlectext = GCHandle::Alloc(bytectext, GCHandleType::Pinned);

			String^ result = Crypto::AESDecrypt(*bytekey, *bytectext, *byteiv);
			GCHandle handleresult = GCHandle::Alloc(result, GCHandleType::Pinned);

			char* r = new char[(result->Length)];

			for (int i = 0; i < result->Length; i++) {
				r[i] = result[i];
			}

			memset(&result, 0, result->Length);
			memset(&bytekey, 0, bytekey->Length);

			delete bytectext;
			delete byteiv;
			delete bytekey;
			delete key;
			delete iv;
			delete ctext;
			handlekey.Free();
			delete handlekey;
			return r;
		};

};
#pragma unmanaged
DLLEXPORT int test(int a, int b) {
	return a + b;
}

DLLEXPORT PyObject* AesEncryptPy(PyObject textb, PyObject keyb) {
	char *text = PyBytes_AsString(&textb);
	char *key = PyBytes_AsString(&keyb);
	std::tuple<char, char> a = crypto::AESEncrypt(*text,*key);
	PyObject* tup = Py_BuildValue("(yy)", std::get<0>(a), std::get<1>(a)); 
	memset(text,0,strlen(text));
	memset(key, 0, strlen(key));
	delete key;
	delete text;
	delete a;
	return tup;
}
DLLEXPORT PyObject* AesDecryptPy(PyObject ivb, PyObject keyb, PyObject ctextb) {
	char *ctext = PyBytes_AsString(&ctextb);
	char *key = PyBytes_AsString(&keyb);
	char *iv = PyBytes_AsString(&ivb);

	char *a = crypto::AESDecrypt(iv, key, ctext);
	PyObject* result = Py_BuildValue("y", a);
	memset(a, 0, strlen(a));
	return result;
}

DLLEXPORT void Init() {
	Py_Initialize();
	crypto::Initialize();
}

