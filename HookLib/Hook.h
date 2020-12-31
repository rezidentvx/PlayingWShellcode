#pragma once
// Supply PID or name of process to hook function in. Use Hooked{Function} to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function
#ifndef _HOOK_H_
#define _HOOK_H_

#include "Util.h"

#include <iostream>
#include <Windows.h>
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
#include <array>

class MemoryProtections
{
public:
	static const std::map<DWORD, std::string> mProtects;

	static std::string FlToStr(DWORD flProtect) {
		std::string flags;
		for (std::pair<DWORD, std::string> prot : MemoryProtections::mProtects) {
			if (flProtect & prot.first) {
				if (!flags.empty())
					flags += " | ";
				flags += prot.second;
			}
		}
		return flags;
	}
};

class MemPatcher {
public:
	HANDLE htargetProcess = NULL;
	LPVOID pMyFunc = nullptr;
	LPVOID pTargetMem = nullptr;
	std::vector<BYTE> originalBytes;
	std::vector<BYTE> patch;

	MemPatcher() = default;
	~MemPatcher() = default;

	std::vector<BYTE> ReadBytes(LPVOID address, SIZE_T nbytes);

	SIZE_T StoreBytes(LPVOID address, SIZE_T nbytes);

	bool CanPatch(LPVOID address, SIZE_T nbytes);

	bool ApplyPatch();

	bool RemovePatch();

};

#endif // _HOOK_H_