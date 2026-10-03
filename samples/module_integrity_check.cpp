// module_integrity_check.cpp
// Demonstrates the detection side: verifying in-memory module .text sections
// against their on-disk originals to detect DLL hollowing (technique 04).
// Analysis/research tool - not production AC code.

#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <vector>
#include <string>

struct IntegrityResult {
    std::wstring moduleName;
    uintptr_t textBase;
    size_t textSize;
    bool matches;
    size_t mismatchOffset;  // first byte that differs, if any
};

// Read a module's .text section from the file on disk
static std::vector<uint8_t> ReadTextFromDisk(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<uint8_t> fileData(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileData.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead < sizeof(IMAGE_DOS_HEADER)) return {};

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(fileData.data() + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            auto start = fileData.data() + section->PointerToRawData;
            auto size = min(section->SizeOfRawData, section->Misc.VirtualSize);
            return std::vector<uint8_t>(start, start + size);
        }
    }
    return {};
}

// Compare in-memory .text against on-disk .text for a loaded module
IntegrityResult CheckModuleIntegrity(HMODULE hMod) {
    IntegrityResult result = {};

    // Get module path
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(hMod, path, MAX_PATH);
    result.moduleName = path;

    auto base = reinterpret_cast<uint8_t*>(hMod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    // Find .text in memory
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            result.textBase = reinterpret_cast<uintptr_t>(base) + section->VirtualAddress;
            result.textSize = section->Misc.VirtualSize;
            break;
        }
    }

    if (!result.textSize) {
        result.matches = true; // no .text section, nothing to check
        return result;
    }

    // Read from disk
    auto diskText = ReadTextFromDisk(path);
    if (diskText.empty()) {
        result.matches = false;
        return result;
    }

    // Compare
    auto memText = reinterpret_cast<uint8_t*>(result.textBase);
    size_t compareSize = min(result.textSize, diskText.size());

    result.matches = true;
    for (size_t i = 0; i < compareSize; i++) {
        if (memText[i] != diskText[i]) {
            result.matches = false;
            result.mismatchOffset = i;
            break;
        }
    }

    return result;
}

// Scan all loaded modules in the current process
void ScanAllModules() {
    HMODULE modules[1024];
    DWORD needed;

    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed))
        return;

    DWORD count = needed / sizeof(HMODULE);

    printf("[*] Scanning %lu loaded modules for integrity...\n\n", count);

    int clean = 0, modified = 0, failed = 0;

    for (DWORD i = 0; i < count; i++) {
        auto result = CheckModuleIntegrity(modules[i]);

        if (result.matches) {
            clean++;
        } else {
            modified++;
            printf("[!] MODIFIED: %ls\n", result.moduleName.c_str());
            printf("    .text base: 0x%llX, size: 0x%zX\n",
                   result.textBase, result.textSize);
            printf("    First mismatch at offset: 0x%zX\n\n", result.mismatchOffset);
        }
    }

    printf("\n[*] Results: %d clean, %d modified, %d failed\n",
           clean, modified, failed);
}

int main() {
    printf("=== Module Integrity Scanner ===\n");
    printf("Compares in-memory .text sections against on-disk originals.\n");
    printf("Detects DLL hollowing (technique 04).\n\n");
    ScanAllModules();
    return 0;
}
