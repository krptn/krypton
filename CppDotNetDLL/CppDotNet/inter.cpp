#include "inter.h"
#include <stdio.h>
using namespace System;
#using "C:\Users\markb\source\repos\PySec\PythonCSharp\bin\Release\net5.0\PythonCSharp.dll"  //Asssembly
using namespace intdotnet;

#pragma unmanaged
namespace dotnet {
	static class crypto {
		char AESEncrypt() {

		}

		char AESDecrypt(char iv, char key, char ctext) {
			char a;
			
			a = Crypto::AESDecrypt(&key, &ctext, &iv);
		}

	};
}