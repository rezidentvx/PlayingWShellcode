// Supply PID or name of process to hook VirtualAlloc in. Use HookedVirtualAlloc to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function

#include <iostream>
#include <Windows.h>
#include <AclAPI.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include <iomanip>
#include <map>
#include <vector>
#include <cctype>
#include <wctype.h>
#include <locale.h>
#include <wchar.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <csignal>
#include "Hook.h"

MemoryProtections mp;
FARPROC virtualAllocAddress = NULL;
HANDLE htargetProcess = 0;
SIZE_T bytesWritten = 0;
const size_t patchSize = 6;
char virtualAllocOriginalBytes[patchSize] = {};

std::string MemoryProtections::FlToStr(DWORD flProtect) {
	std::string flags;
	for (std::pair<DWORD, std::string> element : mProtects) {
		if (flProtect & element.first)
			flags += (flags == "" ? "" : " | ") + element.second;
	}
	return flags;
};

// FATAL: I think this fails in remote processes because they don't have access to the memory
LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	MessageBoxA(0, "Got em", "Got em", MB_OK);
	//abort();
	std::cout << "Entered HookedVirtualAlloc." << std::endl;

	// Print intercepted values from the VirtualAlloc call
	std::cout << "\t[+] Intercepted alloc of " << dwSize << " bytes of " << mp.FlToStr(flProtect) << " at " << (lpAddress ? lpAddress : "(Any)") << std::endl;
	
	// TODO: Only need to remove patch if targetprocess is this process
	RemovePatch();

	// Call the original VirtualAlloc with the same (intercepted) parameters
	std::cout << "Running legitimate VirtualAlloc...";
	LPVOID addr;
	addr = VirtualAllocEx(htargetProcess, lpAddress, dwSize, flAllocationType, flProtect);

	ApplyPatch();

	return addr;
}

bool CanPatch() {
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQueryEx(htargetProcess, (LPVOID)virtualAllocAddress, &meminfo, sizeof(meminfo));
	std::cout << mp.FlToStr(meminfo.AllocationProtect) << " || " << mp.FlToStr(meminfo.Protect) << std::endl;

	char rbytes[patchSize];
	ReadProcessMemory(htargetProcess, (LPVOID)virtualAllocAddress, rbytes, patchSize, &bytesWritten);
	std::cout << "\t[+] Successfully read " << bytesWritten << " bytes: ";
	for (int i = 0; i < patchSize; i++) {
		printf("\\%02X", ((unsigned char*)virtualAllocOriginalBytes)[i]);
	}
	printf("\n");
	return bytesWritten;
}

bool ApplyPatch() {
	std::cout << "Patching in new VirtualAlloc bytes...";

	if (!CanPatch()) {
		std::cout << "\n\t[-] Unable to patch, error: " << GetLastError() << std::endl;
		return 0;
	}
	
	// Create a patch "push <address of new VirtualAlloc>; ret"
	void* hookedVirtualAllocAddress = &HookedVirtualAlloc;
	std::cout << "\n\t[+] Address of hooked function is " << hookedVirtualAllocAddress << std::endl;
	char patch[patchSize] = { 0 };
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedVirtualAllocAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);
	std::cout << "\t[+] Assembled patch is: ";
	for (int i = 0; i < patchSize; i++) {
		printf("\\%02X", ((unsigned char*)patch)[i]);
	}
	printf("\n");

	// Patch VirtualAlloc
	// BUG: Despite successful OpenProcess with PROCESS_ALL_ACCESS, this will fail 
	//		to write to target memory in another process. Access violation (err 5 & 998)
	WriteProcessMemory(htargetProcess, (LPVOID)virtualAllocAddress, patch, patchSize, &bytesWritten);
	//std::cout << GetLastError() << std::endl;

	if (bytesWritten < patchSize) {
		std::cout << "Failed\n" << "\t[-] Bytes written: " << bytesWritten << std::endl;
		return 0;
	}
	std::cout << "Success" << std::endl;
	return 1;
}

bool RemovePatch() {
	std::cout << "Unpatching VirtualAlloc...";
	WriteProcessMemory(htargetProcess, (LPVOID)virtualAllocAddress, virtualAllocOriginalBytes, sizeof(virtualAllocOriginalBytes), &bytesWritten);
	if (bytesWritten < patchSize) {
		std::cout << "Failed" << "\t[-] Bytes written: " << bytesWritten << std::endl;
		return 0;
	}
	std::cout << "Success" << std::endl;
	return 1;
}

BOOL WINAPI SignalHandler(DWORD fdwCtrlType) {
	std::cout << "Interrupt received. Cleaning up..." << std::endl;
	RemovePatch();
	abort();
	return TRUE;
}

DWORD FindProcessId(const std::wstring &processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	do {
		if (processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	} while (Process32Next(processesSnapshot, &processInfo));

	CloseHandle(processesSnapshot);
	return 0;
}

DWORD ArgToPID(char * input) {
	DWORD pid = 0;

	try {
		pid = atoi(input);
	}
	catch (...) {
		std::cout << "Argument was not a number. Interpreting input as name..." << std::endl;
		size_t size = strlen(input) + 1;
		wchar_t* processName = new wchar_t[size];
		mbstowcs_s(0, processName, size, input, size - 1);
		std::wstring basicstring(processName);

		DWORD targetProcessID = FindProcessId(processName);
	}

	if (!pid) {
		std::cout << "Failed to retrieve PID" << std::endl;
	}
	return pid;
}

int main(int argc, char* argv[])
{
	DWORD targetProcessID = 0;
	
	// Give everyone access to us...because we're nice :)
	//GetSecurityInfo();
	//SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, 0,0,0,0);

	const char* buildString = __DATE__ ", " __TIME__;
	printf("Compiled at: %s \n", buildString);
	std::cout << "Starting..." << std::endl;

	// Clean up if signal sent to kill process
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)SignalHandler, TRUE)) {
		std::cout << "\t[-] Failed to set interrupt handler" << std::endl;
		return 0;
	}

	// Check if a PID was not hardcoded for testing
	if (!targetProcessID) {
		// Look in argv for PID
		if (argc > 2) {
			std::cout << "Too many arguments" << std::endl;
			return 0;
		}
		else if (argc == 2) {
			targetProcessID = ArgToPID(argv[1]);
			std::cout << "Target PID is " << targetProcessID << std::endl;
			htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
			if (!htargetProcess) {
				std::cout << "OpenProcess threw error " << GetLastError() << std::endl;
				return 0;
			}
		}
		else {
			std::cout << "No remote process requested. Executing on this process." << std::endl;
			htargetProcess = GetCurrentProcess();
		}
	}
	else {
		std::cout << "Target PID is " << targetProcessID << std::endl;
		htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
		std::cout << "OpenProcess threw error " << GetLastError() << std::endl;
	}

	if (!htargetProcess) {
		std::cout << "Failed to open process" << std::endl;
		return 0;
	}
	std::cout << "Opened process " << htargetProcess << std::endl;

	std::cout << "Loading library...";
	HMODULE hHandle = LoadLibraryA((LPCSTR)"kernel32.dll");
	if (!hHandle) {
		std::cout << "Failed" << std::endl;
		return 0;
	}
	std::cout << "Success" << std::endl;

	// get address of the VirtualAlloc function in memory
	std::cout << "Getting address of VirtualAlloc...";
	virtualAllocAddress = GetProcAddress(hHandle, "VirtualAlloc");
	if (!virtualAllocAddress) {
		std::cout << "Failed" << std::endl;
		return 0;
	}
	std::cout << "Success" << std::endl;
	printf("\t[+] VirtualAlloc address is %p\n", virtualAllocAddress);

	std::cout << "Getting original VirtualAlloc bytes..."  << std::endl;
	// save bytes of the original VirtualAlloc function - will need for unhooking
	SIZE_T bytesRead = 0;
	ReadProcessMemory(htargetProcess, virtualAllocAddress, virtualAllocOriginalBytes, patchSize, &bytesRead);

	printf("\t[+] Original VirtualAlloc bytes are ");
	for (int i = 0; i < patchSize; i++) {
		printf("\\%02X", ((unsigned char*)virtualAllocOriginalBytes)[i]);
	}
	printf("\n");
	
	// Patch target process
	if (!ApplyPatch()) { return 0; }
	
	// If not injecting into another process, run VirtualAlloc as a test
	if (htargetProcess == GetCurrentProcess()) {
		std::cout << "Running VirtualAlloc...";
		LPVOID mem = VirtualAlloc(0, 101, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		std::cout << "Success" << std::endl << "\t[+] Allocated memory at address " << mem << std::endl;
	}

	// Hang out while we capture as many VirtualAllocs as we'd like.
	while (true) {}

	// Unpatch target process
	if (!RemovePatch()) { return 0; }

	// If not injecting into another process, run VirtualAlloc as a test
	if (htargetProcess == GetCurrentProcess()) {
		std::cout << "Running VirtualAlloc again. You should only see status message after this...";
		LPVOID mem = VirtualAlloc(0, 101, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		std::cout << "Success" << std::endl << "\t[+] Allocated memory at address " << mem << std::endl;
	}

	system("pause");
	return 1;
}