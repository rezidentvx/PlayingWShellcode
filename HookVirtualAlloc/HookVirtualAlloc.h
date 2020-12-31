#pragma once
#include "../HookLib/Hook.h"
//#include "../HookLib/Util.h"
//#pragma comment(lib,"../HookLib/HookLib.lib")
#include <minwindef.h>
LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

int RunInject();

int main(int argc, char* argv[]);