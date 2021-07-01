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
using namespace cli;

#define DLLEXPORT extern "C" __declspec(dllexport)
#pragma managed


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
		String^ path = Path::Combine(Path::GetDirectoryName(Assembly::GetExecutingAssembly()->Location), "PythonCSharp.dll");
		auto deb =  Assembly::LoadFile(path);
}
static std::tuple<char, char> AESEncrypt(char* text, char* key) {
	cli::array< Byte >^ bytekey = gcnew cli::array< Byte >(strlen(key) + 1);
	/*
	Marshal::Copy((IntPtr)*key, bytekey, 0, strlen(key));
	*/

	pin_ptr<Byte> data_array_start = &bytekey[0];
	memcpy(data_array_start, &key, strlen(key));
	memset(key, 0, strlen(key));


	cli::array< Byte > ^ bytetext = gcnew cli::array< Byte >(strlen(text) + 1);
	/*
	Marshal::Copy((IntPtr)text, bytetext, 0, strlen(key));
	*/
	
	pin_ptr<Byte> data_two_array_start = &bytetext[0];
	memcpy(data_two_array_start, &text, strlen(text));
	memset(text, 0, strlen(text));


	ValueTuple<cli::array <unsigned char>^, cli::array <unsigned char>^>  result = Crypto::AESEncrypt(bytetext, bytekey);

	// pin them here
	pin_ptr<ValueTuple<cli::array <unsigned char>^, cli::array <unsigned char>^>> result_pin = &result;
	pin_ptr<Byte> result_arr1 = &result.Item1[0];
	pin_ptr<Byte> result_arr2 = &result.Item2[0];

	char* iv = new char[(result.Item1->Length)];
	char* ctext = new char[(result.Item2->Length)];

	memcpy(iv,result_arr1,result.Item1->Length);
	memcpy(ctext,result_arr2,result.Item2->Length);

	//Safely delete them from mem
	memset(&bytekey, 0, bytekey->Length);
	memset(&bytetext, 0, bytetext->Length);
	delete &bytekey;
	delete &bytetext;
	memset(&text, 0, strlen(text));
	memset(&key, 0, strlen(key));
	delete &key;
	delete &text;
	delete &result;
	std::tuple<char, char> a = { *ctext, *iv };
	return a;
};

static char* AESDecrypt(char* iv, char* key, char* ctext) {
	cli::array< Byte >^ bytekey = gcnew cli::array< Byte >((strlen(key) + 1));
	pin_ptr<Byte> data_array_start = &bytekey[0];
	memcpy(data_array_start, &key, strlen(key));
	memset(key, 0, strlen(key));


	cli::array< Byte >^ byteiv = gcnew cli::array< Byte >(strlen(iv) + 1);
	pin_ptr<Byte> data_array_starti = &byteiv[0];
	memcpy(data_array_starti, &iv, strlen(iv));

	cli::array< Byte >^ bytectext = gcnew cli::array< Byte >(strlen(ctext) + 1);
	pin_ptr<Byte> data_array_startii = &bytectext[0];
	memcpy(data_array_startii, &iv, strlen(iv));

	String^ result = Crypto::AESDecrypt(bytekey, bytectext, byteiv);
	pin_ptr<String^> resulthandler = &result;

	char* r = new char[(result->Length)];

	memcpy(r,resulthandler,result->Length);

	memset(&result, 0, result->Length);
	memset(&bytekey, 0, bytekey->Length);

	delete &bytectext;
	delete &byteiv;
	delete &bytekey;
	delete &key;
	delete &iv;
	delete &ctext;
	return r;
};


#pragma unmanaged
DLLEXPORT int test(int a, int b) {
	return a + b;
}

DLLEXPORT PyObject* AesEncryptPy(char* textb, char* keyb) {
	/*
	char *text = PyBytes_AsString(&textb);
	char *key = PyBytes_AsString(&keyb);
	*/
	std::tuple<char, char> a = AESEncrypt(textb,keyb);
	PyObject* tup = Py_BuildValue("(yy)", std::get<0>(a), std::get<1>(a)); 
	memset(textb,0,strlen(textb));
	memset(keyb, 0, strlen(keyb));
	delete &keyb;
	delete &textb;
	delete &a;

	return tup;
}
DLLEXPORT PyObject* AesDecryptPy(PyObject ivb, PyObject keyb, PyObject ctextb) {
	char *ctext = PyBytes_AsString(&ctextb);
	char *key = PyBytes_AsString(&keyb);
	char* iv = PyBytes_AsString(&ivb);
	char *a = AESDecrypt(iv, key, ctext);
	memset(key,0,strlen(key));
	PyObject* result = Py_BuildValue("y", a);
	memset(a, 0, strlen(a));
	delete &ctext;
	delete &key;
	delete &iv;
	delete &a;
	return result;
}

DLLEXPORT void Init() {
	Py_Initialize();
	Initialize();
}

