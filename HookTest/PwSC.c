// Illustrative utility function to run supplied shellcode

#include <Windows.h>
#include <memoryapi.h>
#include <stdio.h>

// Example: NOP, NOP, ... return (void)
 BYTE hex[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3 };

void RunSC(BYTE hex[]) {
    const char* buildString = __DATE__ ", " __TIME__;
    printf("[+] Compiled at: %s \n" \
        "[+] Size of shellcode: %d \n" \
        "[+] Shellcode: ",
        buildString, sizeof(hex));
    for (int i = 0; i < sizeof(hex); i++) {
        printf("%02x", hex[i]);
    } printf("\n");

    void* exec = VirtualAlloc(0, sizeof(hex), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (exec == NULL) {
        printf("[-] Failed to allocate memory.");
        return;
    }

    printf("[+] Memory address: %p\n", exec);
    printf("[+] Memory before shellcode load: "); 

    for (int i = 0; i < sizeof(hex); i++) {
        printf("%02x", ((unsigned char*)exec)[i]);
    } printf("\n");

    memcpy(exec, hex, sizeof(hex));

    printf("[+] Memory after shellcode load:  ");
    for (int i = 0; i < sizeof(hex); i++) {
        printf("%02x", ((unsigned char*)exec)[i]);
    } printf("\n\n");

    printf("[*] Setting PAGE_EXECUTE_READ...\n");
    DWORD dummy;
    VirtualProtect(exec, sizeof(hex), PAGE_EXECUTE_READ, &dummy);

    printf("[*] Querying page...\n");
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T s = VirtualQuery(exec, &mbi, sizeof(mbi));
    if (!s) {
        printf("[-] Failed to query page permissions.");
        return;
    }
    printf("[+] Memory protection is: %x\n", mbi.Protect);

    printf("[*] Executing page...\n");
    int ret = ((int(*)()) exec)();

    // TODO: Output dynamically by type
    printf("[+] Value returned: %d \n", ret);

    printf("Completed.\n");
    return;
}
