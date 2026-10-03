# 01 - Manual Mapping

## Summary

Manual mapping is the practice of loading a DLL into a target process without using the Windows loader (`LoadLibrary`). The image is parsed, relocated, and linked entirely in userland, skipping the standard `LdrLoadDll` path. Result: a module that exists in memory but doesn't appear in the PEB's `InLoadOrderModuleList`, making it invisible to naive module enumeration.

The baseline evasion technique. Almost every modern cheat loader uses some variant of it. It's been around since the early 2010s and has gone through several generations of refinement.

## Mechanism

Standard DLL loading via `LoadLibrary` goes through `ntdll!LdrLoadDll`, which:

1. Opens the file via `NtOpenFile`
2. Creates a section via `NtCreateSection`
3. Maps the section into the process via `NtMapViewOfSection`
4. Walks the import table and resolves dependencies
5. Registers the module in the PEB loader data structures
6. Calls `DllMain` with `DLL_PROCESS_ATTACH`

Steps 2, 3, and 5 are the detection surface. The section object links back to the file on disk. The PEB entry makes the module visible to `EnumProcessModules`, `NtQueryVirtualMemory(MemoryMappedFilenameInformation)`, and similar queries.

Manual mapping skips all of this:

1. Read the PE file into a local buffer (or receive it over a socket/pipe)
2. Allocate memory in the target process via `VirtualAllocEx` (RWX or RW->RX)
3. Copy headers + sections into the allocation, respecting section alignment
4. Apply base relocations (delta = allocated base - preferred base)
5. Resolve imports by walking the IAT and calling `GetProcAddress` (or a custom resolver)
6. Write the mapped image into the target
7. Execute `DllMain` via `CreateRemoteThread`, `NtCreateThreadEx`, APC queue, or thread hijacking

The module never touches the filesystem from the target process's perspective. There's no section object, no PEB entry, no loader data structure referencing it.

## Implementation Sketch

```cpp
// Stripped-down manual map outline - not a working loader
bool ManualMap(HANDLE hProcess, BYTE* rawDll, size_t dllSize) {
    auto dosHeader = (PIMAGE_DOS_HEADER)rawDll;
    auto ntHeaders = (PIMAGE_NT_HEADERS)(rawDll + dosHeader->e_lfanew);
    auto optHeader = &ntHeaders->OptionalHeader;

    // Allocate in target at any base
    void* remoteBase = VirtualAllocEx(
        hProcess, nullptr,
        optHeader->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteBase) return false;

    // Relocate
    ULONG_PTR delta = (ULONG_PTR)remoteBase - optHeader->ImageBase;
    ApplyRelocations(rawDll, ntHeaders, delta);

    // Resolve imports
    ResolveImports(rawDll, ntHeaders); // walks IAT, resolves each thunk

    // Copy sections
    auto section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        WriteProcessMemory(hProcess,
            (BYTE*)remoteBase + section->VirtualAddress,
            rawDll + section->PointerToRawData,
            section->SizeOfRawData, nullptr);
    }

    // Write headers
    WriteProcessMemory(hProcess, remoteBase, rawDll,
        optHeader->SizeOfHeaders, nullptr);

    // Execute DllMain
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)((BYTE*)remoteBase + optHeader->AddressOfEntryPoint),
        remoteBase, 0, nullptr);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}
```

This is intentionally incomplete - no TLS callback handling, no exception directory registration, no SEH setup, no API set resolution. Real loaders handle all of those.

## Why It Works

VAC's usermode module scan historically walked the PEB module list and compared it against known module hashes. A manually mapped module never enters that list, so it was simply never checked.

The real reason it works is that Windows doesn't have a kernel-level concept of "this memory region contains a loaded module" outside of the section object mechanism. If you skip `NtCreateSection`, there's no kernel object to query. The memory is just... memory.

## Detection Surface

Manual mapping leaves some detectable artifacts:

Memory region characteristics:
- Large `MEM_COMMIT | MEM_RESERVE` allocation with `PAGE_EXECUTE_READWRITE` (or RW that later flips to RX via `VirtualProtect`)
- Region contains a valid PE header (MZ + PE signature)
- Region contains executable sections with standard names (`.text`, `.rdata`)
- Region has no associated section object - `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` returns `STATUS_FILE_INVALID`

Behavioral artifacts:
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` sequence targeting a game process (though this specific call chain is increasingly avoided)
- New executable memory appearing in a process that didn't load a new module through normal channels
- Thread start address pointing into memory that isn't backed by any known module

Integrity checks:
- Walking all executable memory regions and checking whether they're backed by a file on disk
- Comparing the list of memory regions with executable permissions against the PEB module list - any executable region not in the list is suspicious

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2012 | Early manual mapping implementations appear on UC/GH forums. Primitive but effective against VAC's module scanning at the time. |
| 2014-2016 | Technique becomes standard. Most public CSGO cheat loaders adopt it. VAC begins scanning for PE headers in unbacked memory. |
| 2016-2017 | Loaders start wiping PE headers post-injection to defeat header scanning. VAC responds with heuristic scans for section-aligned executable memory. |
| 2018-2019 | Advanced loaders begin encrypting mapped images at rest and decrypting only during execution. Cat-and-mouse accelerates. |
| 2020+ | Kernel-level anti-cheats (EAC, BE, Vanguard) make usermode-only manual mapping largely insufficient. VAC itself still operates primarily in usermode, but games increasingly ship with secondary AC systems. |

## Known Variants

- Header wipe - zero or encrypt the DOS/NT headers after mapping to prevent header-based detection
- Scattered mapping - split the image across multiple small allocations instead of one contiguous block
- No-thread execution - instead of `CreateRemoteThread`, use APC injection, thread hijacking, or instrumentation callbacks to avoid creating a new thread
- Memory-only payloads - the DLL never exists on disk; it's compiled in-memory or received over a network socket
- Reflective loading - a variant where the DLL contains its own loader stub, performing the mapping from inside the target process (popularized by Stephen Fewer's ReflectiveDLLInjection)

## References

- Stephen Fewer, "Reflective DLL Injection" - original paper and PoC
- UnknownCheats forums - extensive discussion threads on manual mapping evolution (2012-present)
- GuidedHacking - manual mapping tutorial series
- `blackbone` by DarthTon - open-source library implementing advanced manual mapping with kernel support
- Various VACNet/VAC analysis threads documenting detection updates
