// Supply PID or name of process to hook VirtualAlloc in. Use HookedVirtualAlloc to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function

#include "Hook.h"

typedef LPVOID (CALLBACK* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
LPVOID mem;
LPVOID hookedvalloc;
LPVOID targetmem = nullptr;
VIRTUALALLOC VAlloc = NULL;
HANDLE htargetProcess = 0;
std::vector<BYTE> originalBytes;
std::vector<BYTE> patch;

LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	std::cout << "[+] Intercepted alloc of " << dwSize << " bytes of " << MemoryProtections::FlToStr(flProtect) << " at " << (lpAddress ? lpAddress : "(Any)") << std::endl;
	
	LPVOID addr = 0;
	if (htargetProcess == GetCurrentProcess()) {
		RemovePatch();
		addr = VirtualAllocEx(htargetProcess, lpAddress, dwSize, flAllocationType, flProtect);
		ApplyPatch();
	}
	else
		addr = VirtualAllocEx(htargetProcess, lpAddress, dwSize, flAllocationType, flProtect);

	return addr;
}

std::vector<BYTE> ReadBytes(LPVOID address, SIZE_T nbytes) {
	char* bRead = new char[nbytes];
	SIZE_T nbRead = 0;
	ReadProcessMemory(htargetProcess, address, bRead, nbytes, &nbRead);
	if (nbRead < nbytes)
		return die(std::vector<BYTE>(), "[-] Only read", nbRead, " of ", nbytes, " bytes");

#ifdef _DEBUG
	std::cout << "[+] Read " << nbRead << " bytes: "; PrintHex(bRead, nbRead);
#endif

	return std::vector<BYTE>(bRead, bRead + nbRead);
}

SIZE_T StoreBytes(LPVOID address, SIZE_T nbytes) {
	// save bytes of the original VirtualAlloc function - will need for unhooking
	auto bytes = ReadBytes(address, nbytes);
	if (bytes.empty())
		return 0;

	originalBytes = bytes;
	return originalBytes.size();
}

bool CanPatch(LPVOID address, SIZE_T nbytes) {
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQueryEx(htargetProcess, &address, &meminfo, sizeof(meminfo));
#ifdef _DEBUG
	std::cout << "[*] Memory is set to: " << MemoryProtections::FlToStr(meminfo.AllocationProtect) << " || "
										  << MemoryProtections::FlToStr(meminfo.Protect) << std::endl;
#endif
	return !ReadBytes(address, nbytes).empty();
}

bool ApplyPatch() {
	SSIZE_T hookoffset = (intptr_t)targetmem - (intptr_t)hookedvalloc;
#ifdef _DEBUG
	printf("[*] Offset is %02X\n", (int)hookoffset);
#endif
	
	if ((intptr_t)targetmem - hookoffset != (intptr_t)hookedvalloc)
		return die(FALSE, "[-] Failed to measure offset between target and hook\n");

	patch.clear();
	patch << (UINT64)hookedvalloc;

#ifdef _DEBUG
	std::cout << "[+] Assembled (" << patch.size() << " byte) patch is: "; PrintHex(patch, patch.size());
#endif

	if (!CanPatch(targetmem, patch.size()))
		return die(FALSE, "[-] Unable to patch, error: ", GetLastError());

	StoreBytes(targetmem, patch.size());

	SIZE_T nbWritten = 0;
	WriteProcessMemory(htargetProcess, (LPVOID)targetmem, patch.data(), patch.size(), &nbWritten);
	if (nbWritten < patch.size())
		return die(FALSE, "[-] Patch was not applied. Last error: ", GetLastError());

	return TRUE;
}

bool RemovePatch() {
	SIZE_T nbWritten = 0;
	WriteProcessMemory(htargetProcess, (LPVOID)targetmem, originalBytes.data(), originalBytes.size(), &nbWritten);
	if (nbWritten < patch.size() || ReadBytes(targetmem, patch.size()) != originalBytes)
		return die(FALSE, "[-] Unpatching failed. Bytes written: ", nbWritten, "/", originalBytes.size());

	return TRUE;
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

int RunInject() {
	auto hHandle = LoadLib((LPCSTR)"kernel32.dll");
	hookedvalloc = &HookedVirtualAlloc;
	printf("[+] My VirtualAlloc address is %p\n", hookedvalloc);

	// get address of the VirtualAlloc function in memory
	VAlloc = (VIRTUALALLOC)GetProcAddress(hHandle, "VirtualAlloc");
	targetmem = &VAlloc;
	if (targetmem == nullptr)
		return die(0, "[-] Failed to get address of VirtualAlloc");
	printf("[+] Real VirtualAlloc address is %p\n", targetmem);

	// Patch target process
	if (!ApplyPatch()) { return 0; }

	if (htargetProcess != GetCurrentProcess()) {
		// Hang out while we capture as many VirtualAllocs as we'd like.
		std::cout << "Listening for calls. Ctrl+C when done waiting..." << std::endl;
		while (true) {}
	} 
	else {
		// Call VirtualAlloc manually as a test
		if (!VAlloc(0, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
			return die(0, "[-] VirtualAlloc test failed");
		std::cout << "[+] VirtualAlloc test successful " << std::endl;
	}

	// Unpatch target process
	if (!RemovePatch()) { return 0; }

	return 1;
}

int main(int argc, char* argv[])
{
	DWORD targetProcessID = 0;

	const char* buildString = __DATE__ ", " __TIME__;
	printf("Compiled at: %s \n", buildString);

	// Clean up if signal sent to kill process
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)SignalHandler, TRUE))
		return die(0, "[-] Failed to set interrupt handler");

	// Check if a PID was not hardcoded for testing
	if (!targetProcessID) {
		// Look in argv for PID
		if (argc > 2)
			return die(0, "[!] Too many arguments");
		
		else if (argc == 2) {
			targetProcessID = ArgToPID(argv[1]);
			std::cout << "[+] Target PID is " << targetProcessID << std::endl;
			if (!(htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID)))
				return die(0, "[-] OpenProcess threw error ", GetLastError());
		}
		else {
			std::cout << "[*] No remote process requested. Executing on this process." << std::endl;
			htargetProcess = GetCurrentProcess();
		}
	}
	else {
		std::cout << "[+] Target PID is " << targetProcessID << std::endl;
		htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
		if (!htargetProcess) std::cout << "[-] OpenProcess threw error " << GetLastError() << std::endl;
	}

	if (!htargetProcess)
		return die(0, "[-] Failed to open process");

	std::cout << "[+] Opened target process " << htargetProcess << std::endl;
	return RunInject();
}