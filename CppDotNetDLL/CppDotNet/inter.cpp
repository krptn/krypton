#include "inter.h"
#include <stdio.h>
using namespace System;
#using "C:\Users\markb\source\repos\PySec\PythonCSharp\bin\Release\net5.0\PythonCSharp.dll"  //Asssembly
using namespace intdotnet;
#include <string.h>
using namespace System::Runtime::InteropServices;
#include < stdlib.h >
#include < vcclr.h >
#pragma unmanaged


namespace dotnet {
	static class crypto {

		void removeVar(char var){

		}

		char AESEncrypt() {

		}

		char* AESDecrypt(char iv[], char key[], char ctext[]) {

#pragma managed
			array< Byte >^ bytekey = gcnew array< Byte >(strlen(key));
			Marshal::Copy((IntPtr)key, bytekey, 0, strlen(key));
			GCHandle handlekey = GCHandle::Alloc(bytekey,GCHandleType::Pinned);

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
				Char* n = &result[i]; // Reset it to avoid memory leaks -- still needs finsihing
				*n = 0;
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