// RemoteProcess.cpp : This is a sample remote process that calls the function to be hooked
//

#include <iostream>
//#include "..\HookLib\Util.h"
#include <Windows.h>

int main()
{
	//auto hHandle = LoadLib((LPCSTR)"kernel32.dll");

	//// get address of the VirtualAlloc function in memory
	//__if_not_exists(VirtualAlloc) {
	//	typedef LPVOID(CALLBACK* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
	//	VIRTUALALLOC VirtualAlloc = (VIRTUALALLOC)GetProcAddress(hHandle, "VirtualAlloc");
	//}
	printf("[+] Real VirtualAlloc address is %p\n", &VirtualAlloc);
    system("pause");

	VirtualAlloc(0, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}