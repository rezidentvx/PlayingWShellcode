//#include "pch.h"
//#include "framework.h"
#include "Hook.h"

const std::map<DWORD, std::string> MemoryProtections::mProtects = {
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

std::vector<BYTE> MemPatcher::ReadBytes(LPVOID address, SIZE_T nbytes) {
	char* bRead = new char[nbytes];
	SIZE_T nbRead = 0;
	ReadProcessMemory(htargetProcess, address, bRead, nbytes, &nbRead);
	if (nbRead < nbytes)
		return die(std::vector<BYTE>(), "[-] Only read ", nbRead, " of ", nbytes, " bytes");

#ifdef _DEBUG
	std::cout << "[+] Read " << nbRead << " bytes: "; PrintHex(bRead, nbRead);
#endif

	return std::vector<BYTE>(bRead, bRead + nbRead);
}

SIZE_T MemPatcher::StoreBytes(LPVOID address, SIZE_T nbytes) {
	// save original bytes - will need for unhooking
	auto bytes = ReadBytes(address, nbytes);
	if (bytes.empty())
		return 0;

	originalBytes = bytes;
	return originalBytes.size();
}

bool MemPatcher::CanPatch(LPVOID address, SIZE_T nbytes) {
	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQueryEx(htargetProcess, &address, &meminfo, sizeof(meminfo));
#ifdef _DEBUG
	std::cout << "[*] Memory is set to: " << MemoryProtections::FlToStr(meminfo.AllocationProtect) << " || "
		<< MemoryProtections::FlToStr(meminfo.Protect) << std::endl;
#endif
	return !ReadBytes(address, nbytes).empty();
}

bool MemPatcher::ApplyPatch() {
	SSIZE_T hookoffset = (intptr_t)pMyFunc - (intptr_t)pTargetMem;
#ifdef _DEBUG
	printf("[*] Offset is 0x%02llX (%lli)\n", hookoffset, hookoffset);
#endif

	if ((intptr_t)pMyFunc - hookoffset != (intptr_t)pTargetMem)
		return die(FALSE, "[-] Failed to measure offset between target and hook\n");

	patch.clear();
	//patch << '\x48';
	//patch << '\xFF';
	//patch << '\x25';
	//patch << (INT32)hookoffset;
	patch << (UINT64)pMyFunc;

#ifdef _DEBUG
	std::cout << "[+] Assembled (" << patch.size() << " byte) patch is: "; PrintHex(patch, patch.size());
#endif

	if (!CanPatch(pTargetMem, patch.size()))
		return die(FALSE, "[-] Unable to patch, error: ", GetLastError());

	StoreBytes(pTargetMem, patch.size());

	SIZE_T nbWritten = 0;
	WriteProcessMemory(htargetProcess, (LPVOID)pTargetMem, patch.data(), patch.size(), &nbWritten);
	if (nbWritten < patch.size())
		return die(FALSE, "[-] Patch was not applied. Last error: ", GetLastError());

	return TRUE;
}

bool MemPatcher::RemovePatch() {
	SIZE_T nbWritten = 0;
	WriteProcessMemory(htargetProcess, (LPVOID)pTargetMem, originalBytes.data(), originalBytes.size(), &nbWritten);
	if (nbWritten < patch.size() || ReadBytes(pTargetMem, patch.size()) != originalBytes)
		return die(FALSE, "[-] Unpatching failed. Bytes written: ", nbWritten, "/", originalBytes.size());

	return TRUE;
}
