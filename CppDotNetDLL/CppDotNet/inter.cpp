#include "inter.h"
#include <stdio.h>
using namespace System;
#using "C:\Users\markb\source\repos\PySec\PythonCSharp\bin\Release\net5.0\PythonCSharp.dll"  //Asssembly
using namespace intdotnet;
#include <string.h>
using namespace System::Runtime::InteropServices;
#include < stdlib.h >
#include < vcclr.h >
#include<tuple>
#include <iostream> 
using namespace std;
#pragma unmanaged


namespace dotnet {
	auto Systemnet5 = System;
	static class crypto {

		std::tuple<char[], char[]> AESEncrypt(char text[], char key[]) {
#pragma managed
			array< Byte >^ bytekey = gcnew array< Byte >(strlen(key));
			Marshal::Copy((IntPtr)key, bytekey, 0, strlen(key));
			GCHandle handlekey = GCHandle::Alloc(bytekey, GCHandleType::Pinned);
			for (int i = 0; i < strlen(key); i++) {
				char* ptr = &key[i];
				*ptr = 0;
			}


			array< Byte >^ bytetext = gcnew array< Byte >(strlen(text));
			Marshal::Copy((IntPtr)text, bytetext, 0, strlen(key));
			GCHandle handleiv = GCHandle::Alloc(bytetext, GCHandleType::Pinned);
			for (int i = 0; i < strlen(text); i++) {
				char* ptr = &text[i];
				*ptr = 0;
			}

			System::ValueTuple<array<unsigned char>^, array<unsigned char>^>  result = Crypto::AESEncrypt(bytetext, bytekey);
			GCHandle handleresult = GCHandle::Alloc(result, GCHandleType::Pinned);
			char* iv = new char[(result.Item1->Length) + 1];
			char* ctext = new char[(result.Item2->Length)];


			for (int i = 0; i < result.Item1->Length; i++) {
				ctext[i] = result.Item1[i];
			}
			for (int i = 0; i < result.Item2->Length; i++) {
				ctext[i] = result.Item2[i];
			}
			for (int i = 0; i < bytekey->Length; i++) {
				auto pbArr2 = &bytekey[i];
				*pbArr2 = 0;
			}
			for (int i = 0; i < bytetext->Length; i++) {
				auto pbArr2 = &bytetext[i];
				*pbArr2 = 0;
			}
#pragma unmanaged
			std::tuple<char[], char[]> r(ctext, &iv);  //Needs finishing
			return r;
		}

		char* AESDecrypt(char iv[], char key[], char ctext[]) {

#pragma managed
			array< Byte >^ bytekey = gcnew array< Byte >(strlen(key));
			Marshal::Copy((IntPtr)key, bytekey, 0, strlen(key));
			GCHandle handlekey = GCHandle::Alloc(bytekey,GCHandleType::Pinned);
			for (int i = 0; i < strlen(key); i++) {
				char* ptr = &key[i];
				*ptr = 0;
			}

			array< Byte >^ byteiv = gcnew array< Byte >(strlen(iv));
			Marshal::Copy((IntPtr)iv, byteiv, 0, strlen(key));
			GCHandle handleiv = GCHandle::Alloc(byteiv, GCHandleType::Pinned);

			array< Byte >^ bytectext = gcnew array< Byte >(strlen(ctext));
			Marshal::Copy((IntPtr)ctext, bytectext, 0, strlen(ctext));
			GCHandle handlectext = GCHandle::Alloc(bytectext, GCHandleType::Pinned);

			String^ result = Crypto::AESDecrypt(bytekey, bytectext, byteiv);
			GCHandle handleresult = GCHandle::Alloc(result, GCHandleType::Pinned);

			char* r = new char[(result->Length) + 1];

			for (int i = 0; i < result->Length; i++) {
				r[i] = result[i];
				auto *n = &result; // Reset it to avoid memory leaks -- still needs finsihing
				*n = " ";
			}

			for (int i = 0; i < bytekey->Length; i++) {
				auto pbArr2 = &bytekey[i];
				*pbArr2 = 0;
			}

			Array::Clear(bytekey,0,bytekey->Length);
			Array::Clear(byteiv, 0, byteiv->Length);
			Array::Clear(bytectext, 0, bytectext->Length);
			handlekey.Free();


#pragma unmanaged

			return r;
		}

	};
}