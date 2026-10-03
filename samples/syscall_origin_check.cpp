// syscall_origin_check.cpp
// Detection-side research tool: validates that syscall return addresses
// originate from ntdll.dll, catching direct syscall stubs (technique 02).
// Demonstrates the concept behind InstrumentationCallback-based detection.

#include <windows.h>
#include <cstdio>
#include <cstdint>

// Simplified - real implementation uses NtSetInformationProcess to register
// the instrumentation callback at the kernel level.
//
// When registered, the OS calls this function after every syscall return
// in the process. The return address is in R10 (x64 Windows convention
// for instrumentation callbacks).
//
// This is a conceptual demonstration, not a drop-in snippet.

struct ModuleBounds {
    uintptr_t base;
    uintptr_t end;
};

static ModuleBounds g_ntdll = {};
static ModuleBounds g_win32u = {};

void InitModuleBounds() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");

    auto getBounds = [](HMODULE mod) -> ModuleBounds {
        if (!mod) return {0, 0};
        auto base = reinterpret_cast<uintptr_t>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
            reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
        return {base, base + nt->OptionalHeader.SizeOfImage};
    };

    g_ntdll = getBounds(hNtdll);
    g_win32u = getBounds(hWin32u);
}

bool IsLegitimateReturnAddress(uintptr_t retAddr) {
    // Syscall return should come from ntdll.dll or win32u.dll
    if (retAddr >= g_ntdll.base && retAddr < g_ntdll.end) return true;
    if (retAddr >= g_win32u.base && retAddr < g_win32u.end) return true;
    return false;
}

// This would be called by the instrumentation callback mechanism.
// In practice, registered via NtSetInformationProcess with
// ProcessInstrumentationCallback information class.
//
// x64 calling convention for the callback:
//   R10 = return address of the syscall
//   RAX = syscall return value
//   All other registers preserved
void OnSyscallReturn(uintptr_t returnAddress, uint32_t syscallNumber) {
    if (!IsLegitimateReturnAddress(returnAddress)) {
        // Return address is outside ntdll/win32u - direct syscall detected
        printf("[DETECTION] Syscall #%u returned to 0x%llX "
               "(outside ntdll/win32u)\n",
               syscallNumber, returnAddress);

        // In production: log, flag, or terminate
        // Could also dump the memory region at returnAddress to identify
        // the direct syscall stub
    }
}

// Demonstration: manually check if ntdll stubs are hooked
void CheckNtdllHookStatus() {
    printf("[*] Checking ntdll syscall stub integrity...\n\n");

    const char* funcs[] = {
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtQueryVirtualMemory",
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
    };

    for (auto name : funcs) {
        auto addr = reinterpret_cast<uint8_t*>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), name));
        if (!addr) continue;

        // Clean stub starts with: 4C 8B D1 (mov r10, rcx)
        // followed by:            B8 XX XX 00 00 (mov eax, SSN)
        bool clean = (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1);

        printf("  %-30s @ 0x%p  [%s]\n",
               name, addr,
               clean ? "CLEAN" : "HOOKED");

        if (!clean) {
            printf("    First bytes: %02X %02X %02X %02X %02X %02X\n",
                   addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        }
    }
}

int main() {
    printf("=== Syscall Origin Checker ===\n");
    printf("Detects direct syscall usage (technique 02).\n\n");

    InitModuleBounds();

    printf("[*] ntdll.dll: 0x%llX - 0x%llX\n", g_ntdll.base, g_ntdll.end);
    printf("[*] win32u.dll: 0x%llX - 0x%llX\n\n", g_win32u.base, g_win32u.end);

    CheckNtdllHookStatus();

    printf("\n[*] In production, register InstrumentationCallback to monitor\n");
    printf("    all syscall return addresses at runtime.\n");

    return 0;
}
