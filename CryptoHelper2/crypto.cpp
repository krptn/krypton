#include "pch.h"
#include "crypto.h"
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
/*
using namespace System;
using namespace System::Security::Cryptography;
using namespace System::IO;
*/
#include <tuple>
#include <openssl/aes.h>

//#define DLLEXPORT extern "C" __declspec(dllexport)  <- expanded it already for perfromance reasons
#pragma managed

/*
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
*/
/*
static std::tuple<char, char> AESEncrypt(char* text, char* key) {
	cli::array< Byte >^ bytekey = gcnew cli::array< Byte >(strlen(key) + 1);

	pin_ptr<Byte> data_array_start = &bytekey[0];
	memcpy(data_array_start, &key, strlen(key));
	memset(&key[0], 0, strlen(key));


	cli::array< Byte >^ bytetext = gcnew cli::array< Byte >(strlen(text) + 1);

	pin_ptr<Byte> data_two_array_start = &bytetext[0];
	memcpy(data_two_array_start, &text, strlen(text));
	memset(&text[0], 0, strlen(text));
	cli::array<Byte>^ encrypted;
	cli::array<Byte>^ biv;

	Aes^ myAes = Aes::Create();
	biv = myAes->IV;
	pin_ptr<Byte> result_arr2 = &biv[0];
	myAes->Clear();

	Aes^ aesAlg = Aes::Create();
	aesAlg->Key = bytekey;
	aesAlg->IV = biv;
	memset(data_array_start, 0, bytekey->Length); //Get rid of it
	ICryptoTransform^ encryptor = aesAlg->CreateEncryptor(aesAlg->Key, aesAlg->IV);
	MemoryStream^ msEncrypt = gcnew MemoryStream();
	CryptoStream^ csEncrypt = gcnew CryptoStream(msEncrypt, encryptor, CryptoStreamMode::Write);
	StreamWriter^ swEncrypt = gcnew StreamWriter(csEncrypt);
	swEncrypt->Write(bytetext);
	memset(data_two_array_start, 0, bytetext->Length);
	swEncrypt->Close();
	encrypted = msEncrypt->ToArray();
	pin_ptr<Byte> result_arr1 = &encrypted[0];
	csEncrypt->Clear();
	msEncrypt->Close();
	aesAlg->Clear();

	char* iv = new char[(encrypted->Length)];
	char* ctext = new char[(biv->Length)];

	memcpy(iv, result_arr1, encrypted->Length);
	memcpy(ctext, result_arr2, biv->Length);

	delete text;
	delete key;
	std::tuple<char, char> a = { *ctext, *iv };
	return a;
};


static char* AESDecrypt(char* iv, char* key, char* ctext) {
	cli::array< Byte >^ bytekey = gcnew cli::array< Byte >((strlen(key) + 1));
	pin_ptr<Byte> data_array_start = &bytekey[0];
	memcpy(data_array_start, &key, strlen(key));
	memset(&key[0], 0, strlen(key));

	cli::array< Byte >^ byteiv = gcnew cli::array< Byte >(strlen(iv) + 1);
	pin_ptr<Byte> data_array_starti = &byteiv[0];
	memcpy(data_array_starti, &iv, strlen(iv));

	cli::array< Byte >^ bytectext = gcnew cli::array< Byte >(strlen(ctext) + 1);
	pin_ptr<Byte> data_array_startii = &bytectext[0];
	memcpy(data_array_startii, &iv, strlen(iv));

	Aes^ aesAlg = Aes::Create();
	aesAlg->Key = bytekey;
	memset(data_array_start, 0, bytekey->Length);
	aesAlg->IV = byteiv;
	ICryptoTransform^ decryptor = aesAlg->CreateDecryptor(aesAlg->Key, aesAlg->IV);
	MemoryStream^ msDecrypt = gcnew MemoryStream(bytectext);
	CryptoStream^ csDecrypt = gcnew CryptoStream(msDecrypt, decryptor, CryptoStreamMode::Read);
	StreamReader^ srDecrypt = gcnew StreamReader(csDecrypt);
	System::String^ result = srDecrypt->ReadToEnd();
	pin_ptr<String^> resulthandler = &result;
	srDecrypt->Close();
	csDecrypt->Clear();
	csDecrypt->Clear();
	srDecrypt->Close();
	aesAlg->Clear();

	char* r = new char[(result->Length)];

	memcpy(r, resulthandler, result->Length);
	memset(resulthandler, 0, result->Length);
	delete iv;
	delete key;
	delete ctext;
	return r;
};
*/

#pragma unmanaged
static std::tuple<char*, char> AESEncrypt(unsigned char* text, unsigned char* key) {
	int msglen = strlen((char*)text);
	unsigned char iv[8];

	RAND_bytes(iv, 8);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);

	AES_cbc_encrypt(text, out, msglen, &aes_key, iv, AES_ENCRYPT);
	memset((void*)text, 0, strlen((const char*)text));
	memset((void*)key, 0, strlen((const char*)key));
	memset(&aes_key, 0, sizeof(aes_key));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	memset(out, 0, msglen);
	delete out;
	delete text;
	delete key;

	return { result, (char)iv };


}
static char* AESDecrypt(unsigned char* iv, unsigned char* key, unsigned char* ctext) {
	int msglen = strlen((char*)ctext);
	unsigned char* out = new unsigned char[msglen];
	AES_KEY aes_key;
	AES_cbc_encrypt(ctext, out, msglen, &aes_key, iv, AES_DECRYPT);
	memset((void*)ctext, 0, strlen((const char*)ctext));
	memset((void*)key, 0, strlen((const char*)key));
	memset(&aes_key, 0, sizeof(aes_key));
	memset(&iv, 0, sizeof(iv));
	char* result = new char[msglen];
	memcpy(result, out, msglen);
	memset(out, 0, msglen);
	return result;
}

extern "C" {
	__declspec(dllexport) PyObject* AesEncryptPy(char* textb, char* keyb) {
		
		std::tuple<char, char> a = AESEncrypt(textb, keyb);
		PyObject* tup = Py_BuildValue("(yy)", std::get<0>(a), std::get<1>(a));
		memset(textb, 0, strlen(textb));
		memset(keyb, 0, strlen(keyb));
		delete keyb;
		delete textb;
		delete &a;

		return tup;
		
		
	}
	__declspec(dllexport) PyObject* AesDecryptPy(char* iv, char* key, char* ctext) {
		/*
		char* ctext = PyBytes_AsString(&ctextb);
		char* key = PyBytes_AsString(&keyb);
		char* iv = PyBytes_AsString(&ivb);
		*/
		char* a = AESDecrypt(iv, key, ctext);  //We believe it is unecesary to delete arguments passed inside functions as it is passed as reference
		memset(key, 0, strlen(key));
		PyObject* result = Py_BuildValue("y", a);
		memset(a, 0, strlen(a));
		delete ctext;
		delete key;
		delete iv;
		delete a;
		return result;
	}

	__declspec(dllexport) void Init() {
		Py_Initialize();
		//Initialize();
	}
}


extern "C" __declspec(dllexport) int test(int a, int b) {
	return a + b;
}

