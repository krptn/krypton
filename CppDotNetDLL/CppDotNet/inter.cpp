#include "inter.h"
#include <stdio.h>
using namespace System;
#using ""  //Asssembly

struct __declspec(dllimport) A {
	void Test();
};
