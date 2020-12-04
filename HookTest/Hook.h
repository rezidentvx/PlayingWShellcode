#pragma once
// Supply PID or name of process to hook VirtualAlloc in. Use HookedVirtualAlloc to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function

#include <iostream>
#include <Windows.h>
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

class MemoryProtections
{
public:
	std::map<DWORD, std::string> mProtects;
	MemoryProtections() {
		mProtects = {
		{0x1, "PAGE_NOACCESS"},
		{0x2, "PAGE_READONLY"},
		{0x4, "PAGE_READWRITE"},
		{0x8, "PAGE_WRITECOPY"},
		{0x10, "PAGE_EXECUTE"},
		{0x20, "PAGE_EXECUTE_READ"},
		{0x40, "PAGE_EXECUTE_READWRITE"},
		{0x80, "PAGE_EXECUTE_WRITECOPY"},
		{0x100, "PAGE_GUARD"},
		{0x200, "PAGE_NOCACHE"},
		{0x400, "PAGE_WRITECOMBINE"},
		{0x40000000, "PAGE_TARGETS_NO_UPDATE"}
		};
	};
	std::string FlToStr(DWORD flProtect);
};

LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

bool CanPatch();

bool ApplyPatch();

bool RemovePatch();

BOOL WINAPI SignalHandler(DWORD);

DWORD FindProcessId(const std::wstring& processName);

int main(int argc, char* argv[]);