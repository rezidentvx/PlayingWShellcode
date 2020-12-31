#pragma once
//#include "pch.h"
#ifndef _UTIL_H_
#define _UTIL_H_

#include <Windows.h>
#include <xstring>
#include <vector>
#include <iostream>
#include <tlhelp32.h>

BOOL WINAPI SignalHandler(DWORD);

DWORD FindProcessId(const std::wstring& processName);

DWORD ArgToPID(char* input);

HMODULE LoadLib(LPCSTR name);

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

void PrintHex(std::vector<BYTE> v);

void PrintHex(LPVOID data, SIZE_T length);

void PrintHex(LPVOID& data, SIZE_T length);

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, BYTE b);

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, char b); 

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

void PrintHex(std::vector<BYTE> v);

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
		die(0, rest...);
	/*for (auto item : ...message)
	std::cout << message;
	std::cout << std::endl;*/
	return ret;
}
#endif // (__cplusplus >= 201703L)

#endif // _UTIL_H_