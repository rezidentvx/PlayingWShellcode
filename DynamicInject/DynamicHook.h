#pragma once
// Supply PID or name of process to hook VirtualAlloc in. Use HookedVirtualAlloc to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function

#include <exception>
#include <cstdint>
#include <sstream>
#include <fstream>
#include <algorithm>
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
#include <Psapi.h>
#include <stdlib.h>
#include <array>
//#include <DbgHelp.h>
//#include <ImageHlp.h>
/*
template <typename T>
void print_hex(std::ostream& stream, T x, int width = 8) {
	stream << std::hex << std::setw(width) << std::setfill('0') << x << std::dec;
}

template <typename T>
void print_address(std::ostream& stream, T x) {
	if (x < 0x100)
		print_hex(stream, x, 2);
	else if (x < 0x10000)
		print_hex(stream, x, 4);
	else if (x < 0x100000000ULL)
		print_hex(stream, x, 8);
	else
		print_hex(stream, x, 16);
}

class DebugProcess {
	DWORD pid;
public:
	DebugProcess(DWORD pid) : pid(pid) {
		if (!DebugActiveProcess(pid)) {
			auto error = GetLastError();
			std::cerr << "DebugActiveProcess() failed with error " << error << " (0x";
			print_hex(std::cerr, error);
			std::cerr << ")\n";
			throw std::exception();
		}
	}
	~DebugProcess() {
		if (!DebugActiveProcessStop(this->pid)) {
			auto error = GetLastError();
			std::cerr << "DebugActiveProcessStop() failed with error " << error << " (0x";
			print_hex(std::cerr, error);
			std::cerr << ")\n";
		}
	}
};

bool is_handle_valid(HANDLE handle) {
	return handle && handle != INVALID_HANDLE_VALUE;
}

class AutoHandle {
	HANDLE handle;
public:
	AutoHandle(HANDLE handle) : handle(handle) {}
	~AutoHandle() {
		if (is_handle_valid(this->handle))
			CloseHandle(this->handle);
	}
};

template <typename T>
void zero_struct(T& mem) {
	memset(&mem, 0, sizeof(mem));
}

struct memory_region {
	std::uint64_t start,
		size;
	MEMORY_BASIC_INFORMATION info;
};

void dump_process_memory(DWORD pid) {
	DebugProcess dp(pid);

	auto proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!is_handle_valid(proc)) {
		auto error = GetLastError();
		std::cerr << "OpenProcess() failed with error " << error << " (0x";
		print_hex(std::cerr, error);
		std::cerr << ")\n";
		return;
	}

	return dump_process_memory(proc);
}

void dump_process_memory(HANDLE proc) {
	AutoHandle autoproc(proc);
	std::vector<memory_region> regions;

	for (std::uint64_t address = 0; address < 0x10000000ULL;) {
		MEMORY_BASIC_INFORMATION mbi;
		zero_struct(mbi);
		auto bytes = VirtualQueryEx(proc, (LPCVOID)address, &mbi, sizeof(mbi));
		if (!bytes) {
			address += 4096;
			continue;
		}
		if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) != PAGE_GUARD)
			regions.push_back(memory_region{ (std::uint64_t)mbi.BaseAddress, mbi.RegionSize, mbi });

		address += mbi.RegionSize;
	}

	if (regions.size()) {
		std::cout << "Flat size:   " << regions.back().start + regions.back().size << std::endl;
		std::uint64_t sum = 0;
		for (auto& region : regions)
			sum += region.size;
		std::cout << "Packed size: " << sum << std::endl;
	}

	std::ofstream file("dump.bin", std::ios::binary);
	std::uint64_t current_size = 0;
	for (auto& region : regions) {
		std::vector<char> buffer(region.size);
		size_t read;
		if (!ReadProcessMemory(proc, (LPCVOID)region.start, &buffer[0], buffer.size(), &read)) {
			auto error = GetLastError();
			if (error != ERROR_PARTIAL_COPY) {
				std::cerr << "ReadProcessMemory() failed with error " << error << " (0x";
				print_hex(std::cerr, error);
				std::cerr << ")\n";
				return;
			}
		}

		if (read < region.size) {
#if 1
			std::cerr << "Warning: region starting at 0x";
			print_address(std::cerr, region.start);
			std::cerr << " has size " << region.size << ", but only " << read
				<< " bytes could be read by ReadProcessMemory().\n";
#endif
			memset(&buffer[read], 0, buffer.size() - read);
		}

		file.seekp(region.start);

		file.write(&buffer[0], buffer.size());
	}
}
*/

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

struct PROC_WIN_3264
{
	BOOL windowsIs32Bit;
	BOOL isWOW64;
	BOOL processIs32Bit;
};

BOOL GetProcWin32Or64(HANDLE hTargetProcess, PROC_WIN_3264& pw3264);

BYTE ReadByte(HANDLE hTargetProcess, LPVOID address);

std::vector<BYTE> ReadBytes(HANDLE hTargetProcess, LPVOID address, SIZE_T nbytes);

bool CanPatch(HANDLE hTargetProcess, LPVOID address, SIZE_T nbytes);

bool ApplyPatch(HANDLE hTargetProcess, const LPVOID pTarget, std::vector<BYTE>& patch, std::vector<BYTE>& originalBytes);

BOOL WINAPI SignalHandler(DWORD);

DWORD FindProcessId(const std::wstring& processName);

std::vector<LPVOID> scan_memory(LPVOID address_low, std::size_t nbytes, const std::vector<BYTE>& bytes_to_find);

std::vector<LPVOID> scan_memory(const std::vector<BYTE>& bytes_to_find, HANDLE hTargetProcess = nullptr, std::string* moduleName = nullptr);

std::vector<LPVOID> Scanner(HANDLE hTargetProcess);

std::vector<BYTE> GeneratePatch(const LPVOID pTarget);

std::vector<std::vector<BYTE>> Patcher(HANDLE hTargetProcess, std::vector<LPVOID>& vecpTargets);

bool RunInject(HANDLE hTargetProcess);

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

//void PrintHex(std::vector<BYTE> v) {
//	for (SIZE_T i = 0; i < v.size(); i++)
//		printf("\\%02X", v.at(i));
//	printf("\n");
//}

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