//#include "pch.h"
#include "Util.h"

BOOL WINAPI SignalHandler(DWORD fdwCtrlType) {
	std::cout << "Interrupt received. Cleaning up..." << std::endl;
	//RemovePatch();
	abort();
	return TRUE;
}

DWORD FindProcessId(const std::wstring& processName)
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

DWORD ArgToPID(char* input) {
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

	if (!pid)
		std::cout << "Failed to retrieve PID" << std::endl;

	return pid;
}

HMODULE LoadLib(LPCSTR name) {
	HMODULE hHandle = LoadLibraryA(name);
	if (!hHandle)
		return die((HMODULE)NULL, "[-] Failed to load library");
	return hHandle;
}

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, BYTE b) {
	v.push_back(b);
	return v;
}

std::vector<BYTE>& operator<<(std::vector<BYTE>& v, char b) {
	v.push_back(b);
	return v;
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
		printf("\\%02X", *((PBYTE)data + i));
	printf("\n");
}