// DynamicInject.cpp : Scan process for injection points and craft+apply custom patches
//

#include "DynamicHook.h"

template <typename... Ts>
auto __stdcall HookedFunc(LPVOID lpAddress, Ts const&... args) {
	// Get intended address (e.g., VirtualAlloc())
	

	// Interpret arguments in that context. Example:
	// std::cout << [+] Captured call to {function(arg1, arg2, ...)} << std::endl;
	
	// Send flow to the intended address
	goto lpAddress;
}

BOOL GetProcWin32Or64(HANDLE hTargetProcess, PROC_WIN_3264& pw3264) {
	USHORT ProcessMachine;
	USHORT NativeMachine;

	if (!IsWow64Process2(hTargetProcess, &ProcessMachine, &NativeMachine)) {
		std::cerr << "IsWOW64Process2 returned FALSE (failed). GetLastError returned: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (ProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
		pw3264.isWOW64 = FALSE;

		if (NativeMachine == IMAGE_FILE_MACHINE_IA64 || NativeMachine == IMAGE_FILE_MACHINE_AMD64 || NativeMachine == IMAGE_FILE_MACHINE_ARM64) {
			pw3264.windowsIs32Bit = FALSE;
			pw3264.processIs32Bit = FALSE;

			return TRUE;
		}
		else if (NativeMachine == IMAGE_FILE_MACHINE_I386 || NativeMachine == IMAGE_FILE_MACHINE_ARM) {
			pw3264.windowsIs32Bit = TRUE;
			pw3264.processIs32Bit = TRUE;

			return TRUE;
		}

		std::cerr << "Unknown Windows Architecture." << std::endl;
		return FALSE;
	}

	pw3264.windowsIs32Bit = FALSE;
	pw3264.isWOW64 = TRUE;
	pw3264.processIs32Bit = TRUE;
	return TRUE;
}

BYTE ReadByte(HANDLE hTargetProcess, LPVOID address) {
	char bRead;
	SIZE_T nbRead = 0;
	ReadProcessMemory(hTargetProcess, address, &bRead, 1, &nbRead);
	
	return nbRead ? bRead : NULL;
}

std::vector<BYTE> ReadBytes(HANDLE hTargetProcess, LPVOID address, SIZE_T nbytes) {
	char* bRead = new char[nbytes];
	SIZE_T nbRead = 0;
	ReadProcessMemory(hTargetProcess, address, bRead, nbytes, &nbRead);
	if (nbRead < nbytes)
		return {};

#ifdef _DEBUG
	std::cout << "[+] Read " << nbRead << " bytes: "; PrintHex(bRead, nbRead);
#endif

	std::vector<BYTE> ret(bRead, bRead + nbRead);
	return ret;
}

bool CanPatch(HANDLE hTargetProcess, LPVOID address, SIZE_T nbytes) {
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQueryEx(hTargetProcess, &address, &meminfo, sizeof(meminfo));
#ifdef _DEBUG
	std::cout << "[*] Memory is set to: " << MemoryProtections::FlToStr(meminfo.AllocationProtect) << " || "
		<< MemoryProtections::FlToStr(meminfo.Protect) << std::endl;
#endif
	return !ReadBytes(hTargetProcess, address, nbytes).empty();
}

bool ApplyPatch(HANDLE hTargetProcess, const LPVOID pTarget, std::vector<BYTE>& patch, std::vector<BYTE>& originalBytes) {

	if (!CanPatch(hTargetProcess, pTarget, patch.size()))
		return die(FALSE, "[-] Unable to patch, error: ", GetLastError());

	// save bytes of the original VirtualAlloc function - will need for unhooking
	originalBytes = ReadBytes(hTargetProcess, pTarget, patch.size());

	SIZE_T nbWritten = 0;
	WriteProcessMemory(hTargetProcess, pTarget, patch.data(), patch.size(), &nbWritten);
	if (nbWritten < patch.size())
		return die(FALSE, "[-] Patch was not applied. Last error: ", GetLastError());

	return TRUE;
}

BOOL WINAPI SignalHandler(DWORD fdwCtrlType) {
	std::cout << "Interrupt received. Cleaning up..." << std::endl;
	//RemovePatch(); TODO
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

std::vector<LPVOID> scan_memory(LPVOID address_low, std::size_t nbytes, const std::vector<BYTE>& bytes_to_find) {

	// all readable pages: adjust this as required
	const DWORD pmask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE |
		PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

	BYTE* address = static_cast<BYTE*>(address_low);
	BYTE* address_high = address + nbytes;
	MEMORY_BASIC_INFORMATION mbi{};
	std::vector<LPVOID> pTargets;
	while (address < address_high && VirtualQuery(address, std::addressof(mbi), sizeof(mbi))) {
		// committed memory, readable, wont raise exception guard page
		if ((mbi.State == MEM_COMMIT) && (mbi.Protect & pmask) && !(mbi.Protect & PAGE_GUARD)) {
			const BYTE* begin = static_cast<const BYTE*>(mbi.BaseAddress);
			const BYTE* end = begin + mbi.RegionSize;

			const BYTE* found = std::search(begin, end, bytes_to_find.begin(), bytes_to_find.end());
			while (found < end) {
				pTargets.push_back((LPVOID)found);
				found = std::search(found + 1, end, bytes_to_find.begin(), bytes_to_find.end());
			}
		}

		address += mbi.RegionSize;
		mbi = {};
	}

	return pTargets;
}

std::vector<LPVOID> scan_memory(const std::vector<BYTE>& bytes_to_find, HANDLE hTargetProcess, std::string* moduleName)
{
	if (!hTargetProcess)
		hTargetProcess = GetCurrentProcess();

	std::vector<HMODULE> hModules;
	if (moduleName && !moduleName->empty() && hTargetProcess == GetCurrentProcess())
		hModules.push_back(GetModuleHandleA(moduleName->c_str()));
	
	DWORD cbNeeded;
	std::array<HMODULE, 1024> hModuleArr;
	if (!EnumProcessModulesEx(hTargetProcess, hModuleArr.data(), (DWORD)hModuleArr.size()*sizeof(HMODULE), &cbNeeded, LIST_MODULES_DEFAULT))
		return {};

	for (SIZE_T i = 0; i <= cbNeeded / sizeof(HMODULE); i++)
		hModules.emplace_back(hModuleArr[i++]);

	if (hModules.empty())
		return {};
	
	MODULEINFO minfo{};
	std::vector<LPVOID> pTargets;
	WORD target;
	for (auto& hModule : hModules) {
//#pragma comment(lib, "dbghelp.lib") // Access violation on bad handles
//		target = ImageNtHeader(hModule)->FileHeader.Machine; 
//		switch (target) {
//		case IMAGE_FILE_MACHINE_I386:
//			printf("[*] Target is a 32-bit process\n");
//		case IMAGE_FILE_MACHINE_AMD64:
//			printf("[*] Target is a 64-bit process\n");
//		}
		GetModuleInformation(hTargetProcess, hModule, std::addressof(minfo), sizeof(minfo));
		auto temp = scan_memory(hModule, minfo.SizeOfImage, bytes_to_find);
		pTargets.insert(pTargets.end(), temp.begin(), temp.end());
		//CloseHandle(hModule); Beware of bad handles
	}

	return pTargets;
}

std::vector<LPVOID> Scanner(HANDLE hTargetProcess, std::vector<BYTE> bytes_to_find) {

	const std::vector<LPVOID> pTargets = scan_memory(bytes_to_find, hTargetProcess);

	std::cout << "[+] Found pattern at " << pTargets.size() << " addresses\n";
	for (const LPVOID pTarget : pTargets)
		std::cout << pTarget << '\n';
	std::cout << "---END OF " << pTargets.size() << " RESULTS---\n";

	return pTargets;
}

std::vector<BYTE> GeneratePatch(HANDLE hTargetProcess, const LPVOID pTarget) {
	std::vector<BYTE> patch = {};
	auto p = (LPBYTE)pTarget;
	auto trampoline = (LPVOID)(MAXDWORD-0XFF); // Something noticeable to test with
	BYTE b = ReadByte(hTargetProcess, p++);

	if (b == 0x48) { // REX.W
		patch.push_back(0x48);
		b = ReadByte(hTargetProcess, p++);

		if (b == 0xFF) { // CALL
			patch.push_back(0xFF);
			b = ReadByte(hTargetProcess, p++);

			if (b == 0x85) { // rBP+sdword
				patch.push_back(0x85);

				auto addr = *(PDWORD)ReadBytes(hTargetProcess, p, sizeof(DWORD)).data();
				CONTEXT cxt;
				RtlCaptureContext(&cxt);
				auto rel = (intptr_t)trampoline - (intptr_t)cxt.Ebp;
				for (SIZE_T i = 0; i < sizeof(rel); i++)
					patch.emplace_back(*(((PBYTE)&rel)+i));
			}
		}
	}
	
	for (auto i : patch)
		std::clog << std::hex << (int)i << ' ';
	std::clog << std::endl;
	return patch;
}

std::vector<std::vector<BYTE>> Patcher(HANDLE hTargetProcess, std::vector<LPVOID>& vecpTargets) {
	std::vector<std::vector<BYTE>> originalBytes;

	for (auto pTarget : vecpTargets) {

		auto patch = GeneratePatch(hTargetProcess, pTarget);

		// Patch target process
		std::vector<BYTE> oBytes;
		//if (!ApplyPatch(hTargetProcess, pTarget, patch, &oBytes))
		//	return originalBytes;
		
		originalBytes.emplace_back(oBytes);
	}

	return originalBytes;
}

bool RunInject(HANDLE hTargetProcess) {
	PROC_WIN_3264 pw3264;
	if (!GetProcWin32Or64(hTargetProcess, pw3264))
		return FALSE;

	// Look for this byte pattern
	auto targetBytes = pw3264.processIs32Bit ?
		std::vector<BYTE>({ 0x48, 0xff }) : // 32 bit
		std::vector<BYTE>({ 0x48, 0xff }) ; // 64 bit

	auto pTargets = Scanner(hTargetProcess, targetBytes);

	// Dynamically patch all matches
	auto originalBytes = Patcher(hTargetProcess, pTargets);
	if (originalBytes.size() != pTargets.size())
		printf("[!] Only %u of %u targets patched\n", originalBytes.size(), pTargets.size());

	// Hang out while we capture as many calls as we'd like.
	std::cout << "Listening for calls. Ctrl+C when done waiting..." << std::endl;
	system("pause");

	// Unpatch each address we modified
	std::vector<BYTE> ob;
	for (SIZE_T i = 0; i < originalBytes.size(); i++)
		if (!ApplyPatch(hTargetProcess, pTargets[i], originalBytes[i], ob)) { return 0; }

	return TRUE;
}

int main(int argc, char* argv[])
{
	DWORD targetProcessID = 0;
	HANDLE htargetProcess = NULL;

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
	return RunInject(htargetProcess);
}
