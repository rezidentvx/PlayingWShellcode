// Supply PID or name of process to hook VirtualAlloc in. Use HookedVirtualAlloc to do whatever.
// Attempts to OpenProcess with PROCESS_ALL_ACCESS. This is bad. Fine-tune for your needs.
// TODO: Make more generic so it can be hotswapped with any function
#include "HookVirtualAlloc.h"

MemPatcher mp;

LPVOID __stdcall HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	std::cout << "[+] Intercepted alloc of " << std::endl << dwSize << std::endl << " bytes of " << std::endl << MemoryProtections::FlToStr(flProtect) << std::endl << " at " << std::endl << (lpAddress ? lpAddress : "(Any)") << std::endl;
	
	if (mp.htargetProcess == GetCurrentProcess())
		mp.RemovePatch();
	
	LPVOID addr = VirtualAllocEx(mp.htargetProcess, lpAddress, dwSize, flAllocationType, flProtect);

	if (mp.htargetProcess == GetCurrentProcess())
		mp.ApplyPatch();

	return addr;
}

int RunInject() {
	
	mp.pMyFunc = &HookedVirtualAlloc;
	printf("[+] My VirtualAlloc address is %p\n", mp.pMyFunc);

	// get address of the VirtualAlloc function in memory
	__if_not_exists(VirtualAlloc) {
		typedef LPVOID(CALLBACK* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
		auto hHandle = LoadLib((LPCSTR)"kernel32.dll");
		VIRTUALALLOC VirtualAlloc = (VIRTUALALLOC)GetProcAddress(hHandle, "VirtualAlloc");
	}
	mp.pTargetMem = &VirtualAlloc;
	if (mp.pTargetMem == nullptr)
		return die(0, "[-] Failed to get address of VirtualAlloc");
	printf("[+] Real VirtualAlloc address is %p\n", mp.pTargetMem);

	// Patch target process
	if (!mp.ApplyPatch()) { return 0; }

	if (mp.htargetProcess != GetCurrentProcess()) {
		// Hang out while we capture as many VirtualAllocs as we'd like.
		//std::cout << "Listening for calls. Ctrl+C when done waiting..." << std::endl;
		//while (true) { Sleep(2000); }
		std::cout << "Listening for calls. ";
		system("pause");
	} 
	else {
		// Call VirtualAlloc manually as a test
		if (!VirtualAlloc(0, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
			return die(0, "[-] VirtualAlloc test failed");
		std::cout << "[+] VirtualAlloc test successful " << std::endl;
	}

	// Unpatch target process
	if (!mp.RemovePatch()) { return 0; }

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
			if (!(mp.htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID)))
				return die(0, "[-] OpenProcess threw error ", GetLastError());
		}
		else {
			std::cout << "[*] No remote process requested. Executing on this process." << std::endl;
			mp.htargetProcess = GetCurrentProcess();
		}
	}
	else {
		std::cout << "[+] Target PID is " << targetProcessID << std::endl;
		mp.htargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessID);
		if (!mp.htargetProcess) std::cout << "[-] OpenProcess threw error " << GetLastError() << std::endl;
	}

	if (!mp.htargetProcess)
		return die(0, "[-] Failed to open process");

	std::cout << "[+] Opened target process " << mp.htargetProcess << std::endl;
	return RunInject();
}