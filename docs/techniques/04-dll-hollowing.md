# 04 - DLL Hollowing

## Summary

DLL hollowing loads a legitimate, signed DLL into the target process using the standard Windows loader, then overwrites its `.text` section with cheat code. The result is a module that appears in the PEB module list with a valid name, valid signature metadata, and a file-backed section object - but is actually executing attacker-controlled code.

It's the module-level equivalent of process hollowing (`RunPE`), and it was effective for several years before integrity-checking scans caught up.

## Mechanism

1. **Load a sacrificial DLL** - pick a benign, appropriately-sized DLL that the target process wouldn't normally load. Something like `msftedit.dll`, `ieframe.dll`, or any large system DLL with a `.text` section big enough to hold the payload.

2. **Load it normally** - call `LoadLibrary` (or trigger loading via `LdrLoadDll`). The module now has a clean PEB entry, a valid section object, and file-backed memory mappings.

3. **Modify memory protections** - `VirtualProtect` the `.text` section to `PAGE_READWRITE`.

4. **Overwrite the code** - copy the cheat payload over the legitimate code in `.text`.

5. **Restore protections** - flip back to `PAGE_EXECUTE_READ`.

6. **Execute** - the cheat code now runs from a memory region that's associated with a legitimate, signed module.

```
Before hollowing:
  msftedit.dll .text section -> legitimate Microsoft code
  PEB entry: msftedit.dll [OK]
  File backing: C:\Windows\System32\msftedit.dll [OK]

After hollowing:
  msftedit.dll .text section -> cheat code
  PEB entry: msftedit.dll [OK]    (still looks legit)
  File backing: C:\Windows\System32\msftedit.dll [OK]    (still looks legit)
```

## Implementation Sketch

```cpp
bool HollowDll(HANDLE hProcess, const char* sacrificialDll,
               BYTE* payload, size_t payloadSize) {
    // Load the sacrificial DLL into the target
    // (via CreateRemoteThread calling LoadLibraryA, or similar)
    HMODULE hMod = RemoteLoadLibrary(hProcess, sacrificialDll);
    if (!hMod) return false;

    // Parse the remote module's PE headers to find .text
    IMAGE_DOS_HEADER dosHeader;
    ReadProcessMemory(hProcess, hMod, &dosHeader, sizeof(dosHeader), nullptr);

    IMAGE_NT_HEADERS ntHeaders;
    ReadProcessMemory(hProcess, (BYTE*)hMod + dosHeader.e_lfanew,
                      &ntHeaders, sizeof(ntHeaders), nullptr);

    IMAGE_SECTION_HEADER textSection;
    // Find .text section...
    BYTE* textAddr = (BYTE*)hMod + textSection.VirtualAddress;
    SIZE_T textSize = textSection.Misc.VirtualSize;

    if (payloadSize > textSize) return false; // payload too big

    // Unprotect, write, reprotect
    DWORD oldProtect;
    VirtualProtectEx(hProcess, textAddr, textSize, PAGE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, textAddr, payload, payloadSize, nullptr);
    VirtualProtectEx(hProcess, textAddr, textSize, PAGE_EXECUTE_READ, &oldProtect);

    return true;
}
```

## Why It Works (Worked)

Early VAC module scans checked:
- Is this module in the PEB list? -> Yes (it was loaded normally)
- Does it have a valid file backing? -> Yes (LoadLibrary created the section object)
- Is the file signed? -> Yes (it's a legitimate Microsoft DLL)

What they didn't check (initially):
- Does the in-memory code match the on-disk code?

That's the gap. The module *metadata* was clean. The module *contents* were not.

## Detection Surface

This technique has a straightforward detection path, which is why it's largely burned:

**Integrity verification:**
- Read the `.text` section from memory, read the same section from the file on disk, compare. Any mismatch (beyond expected relocations) is a detection.
- This is exactly what VAC began doing, and it kills DLL hollowing dead.

**Memory attribute anomalies:**
- A `.text` section that was `PAGE_READWRITE` at any point during process lifetime (logged via page fault history or ETW)
- Copy-on-write pages - when a file-backed section is written to, Windows creates a private copy. The page is no longer backed by the original file. `NtQueryVirtualMemory` reveals this.

**Behavioral:**
- A process loading DLLs it has no business loading (msftedit.dll in a game process)
- `VirtualProtect` calls targeting the `.text` section of a signed system DLL

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2016 | Technique adapted from malware (process hollowing) to game cheats. Effective against PEB-list-only module scans. |
| 2017-2018 | Widespread adoption in CSGO cheat scene. Multiple public loaders use it. |
| 2018-2019 | VAC adds in-memory vs. on-disk module integrity checks. Technique becomes risky. |
| 2020-2021 | Most public cheat developers abandon it in favor of manual mapping + syscalls. Private cheats that still use it add encryption/re-encoding of the hollowed section to slow down hash comparisons. |
| 2022+ | Largely dead as a standalone technique. Occasionally combined with other methods (hollow a module, then encrypt the contents and only decrypt per-call). |

## Known Variants

- **Section remapping** - instead of overwriting .text, unmap the original section and map a new one with cheat code
- **Partial hollowing** - overwrite only the entry point and a small trampoline, keeping most of the original code intact to pass partial hash checks  
- **Module stomping** - similar concept but targets modules already loaded by the process (no new LoadLibrary call), overwriting rarely-used code paths
- **Encrypted hollowing** - hollow the section but keep the payload encrypted at rest, decrypting only during active use

## References

- Various process hollowing / RunPE papers (2010s) - the original technique this derives from
- hasherezade, "Process Hollowing and PE Image Relocations" - technical deep dive
- UnknownCheats forums - DLL hollowing discussions and implementations
- Microsoft documentation on copy-on-write semantics for section-backed pages
