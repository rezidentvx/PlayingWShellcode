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
#include <array>

#define assert(condition) ((void)0)

namespace MemoryProtections
{
	std::map<DWORD, std::string> mProtects = {
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
	std::string FlToStr(DWORD flProtect) {
		std::string flags;
		for (std::pair<DWORD, std::string> prot : mProtects) {
			if (flProtect & prot.first)
				flags += (flags.empty() ? "" : " | ") + prot.second;
		}
		return flags;
	}
};

LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

std::vector<BYTE> ReadBytes(LPVOID address, SIZE_T nbytes);

SIZE_T StoreBytes(LPVOID address, SIZE_T nbytes);

bool CanPatch(LPVOID address, SIZE_T nbytes);

bool ApplyPatch();

bool RemovePatch();

BOOL WINAPI SignalHandler(DWORD);

DWORD FindProcessId(const std::wstring& processName);

HMODULE LoadLib(LPCSTR name);

int RunInject();

template <typename T>
void PrintHex(T& data) {
	for (SIZE_T i = 0; i < sizeof(T); i++)
		printf("\\%02X", ((PBYTE)&data)[i]);
	printf("\n");
}

template <typename T>
void PrintHex(T& data, SIZE_T length) {
	for (SIZE_T i = 0; i < length; i++)
		printf("\\%02X", (BYTE)data[i]);
	printf("\n");
}

void PrintHex(std::vector<BYTE> v) {
	for (SIZE_T i = 0; i < v.size(); i++)
		printf("\\%02X", v.at(i));
	printf("\n");
}

void PrintHex(LPVOID data, SIZE_T length) {
	for (SIZE_T i = 0; i < length; i++)
		printf("\\%02X", *((PBYTE)data + i));
	printf("\n");
}

void PrintHex(LPVOID& data, SIZE_T length) {
	SIZE_T i = 0;
	while (i++ < length)
		printf("\\%02X", *((PBYTE)data+i));
	printf("\n");
}

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, BYTE b) {
	v.push_back(b);
	return v;
}

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, char b) {
	v.push_back(b);
	return v;
}

template <typename T>
std::vector<BYTE>& operator<<(std::vector<BYTE>& v, T data) {
	for (SIZE_T i = 0; i < sizeof(T); i++)
		v << *((PBYTE)&data + i);
	return v;
}

template <typename T>
std::vector<BYTE>& operator<<(std::vector<BYTE>& v, T& data) {
	BYTE bytes[sizeof(T)];
	//data = reinterpret_cast<BYTE*>(data);
	std::copy((BYTE*)data, (BYTE*)data + sizeof(T), bytes);
	for (BYTE b : bytes)
		v << (char)b;
	return v;
}

//template <typename T>
//std::vector<BYTE>& operator<<(std::vector<BYTE>& v, T&& data) {
//	v << data;
//	return v;
//}

#if (__cplusplus >= 201703L) // C++17+ enabled
template <typename R, typename... Ts>
inline R die(R ret, Ts const&... message) {
	((std::cout << message), ...);
	return ret;
}
#else
template <typename R, typename T, typename... Ts>
inline R die(R ret, T const& first, Ts const&... rest) {
	std::cout << first;
	if constexpr (sizeof...(rest) > 0)
		die(rest..., 0);
	/*for (auto item : ...message)
	std::cout << message;
	std::cout << std::endl;*/
	return ret;
}
#endif

int main(int argc, char* argv[]);