# 02 - Syscall Proxying (Direct & Indirect)

## Summary

Syscall proxying bypasses usermode API hooks by invoking Windows system calls directly, skipping the hooked `ntdll.dll` stubs entirely. Instead of calling `NtReadVirtualMemory` through ntdll (where an anti-cheat might have placed a detour), the cheat builds and executes its own `syscall` instruction with the correct syscall number.

This is the single most impactful evasion technique of the last five years. It rendered an entire generation of usermode hooks useless overnight and forced anti-cheat vendors to move detection logic into the kernel.

## Mechanism

### How Windows System Calls Work

Every `Nt*` function in `ntdll.dll` is a thin stub that:

1. Moves the syscall number (SSN) into `eax`
2. Executes the `syscall` instruction (x64) or `int 0x2e` / `sysenter` (x86)
3. The CPU transitions to kernel mode and dispatches through `KiSystemCall64`

```asm
; ntdll!NtReadVirtualMemory on a typical Win10 build
NtReadVirtualMemory:
    mov r10, rcx
    mov eax, 0x3F        ; syscall number (varies per build)
    syscall
    ret
```

### How Anti-Cheats Hook This

Usermode anti-cheats (including VAC modules) hook these stubs by patching the first bytes with a `jmp` to their monitoring code. Every call to `NtReadVirtualMemory` now goes through the AC's filter first.

### How Direct Syscalls Bypass It

Instead of calling through ntdll, the cheat:

1. Resolves the correct SSN for the target OS build (from ntdll's export table, from a lookup table, or by parsing the stub bytes)
2. Emits its own assembly stub with `mov eax, SSN; syscall`
3. Calls that stub directly

The hooked ntdll code is never executed.

### Direct vs Indirect

**Direct syscall:** The `syscall` instruction executes from within the cheat's own module. This is simple but detectable - the return address on the kernel stack points into an unknown memory region instead of ntdll.

**Indirect syscall:** The cheat jumps into the *middle* of a legitimate ntdll stub (past the hook, directly to the `syscall` instruction). The return address now points into ntdll, which looks normal. This is harder to detect.

```
Direct:     cheat.dll -> mov eax, SSN -> syscall -> kernel
Indirect:   cheat.dll -> mov eax, SSN -> jmp ntdll!NtXxx+0x12 -> syscall -> kernel
```

## Implementation Sketch

### Direct Syscall

```cpp
// Runtime-resolved direct syscall stub
extern "C" NTSTATUS DirectSyscall(DWORD ssn, ...);

// In .asm:
// DirectSyscall PROC
//     mov r10, rcx      ; first param (Windows calling convention quirk)
//     mov eax, edx      ; SSN passed as second param
//     syscall
//     ret
// DirectSyscall ENDP

DWORD GetSSN(const char* funcName) {
    // Parse ntdll's export table, find the function, read the SSN
    // from the mov eax, imm32 instruction at the start of the stub
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, funcName);

    // Check if hooked - first bytes should be mov r10, rcx (49 89 CA)
    // If not, walk nearby stubs to infer the SSN from neighbors
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1) {
        // Clean stub: SSN is at offset +4
        return *(DWORD*)(func + 4);
    }

    // Hooked - use Halo's Gate / Tartarus' Gate to find SSN
    // by walking adjacent syscall stubs
    return ResolveSSNFromNeighbors(func);
}
```

### Indirect Syscall

```cpp
// Find the syscall instruction inside a clean ntdll stub
void* FindSyscallInstruction(const char* funcName) {
    BYTE* func = (BYTE*)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), funcName);

    // Scan forward for the syscall opcode (0F 05)
    for (int i = 0; i < 32; i++) {
        if (func[i] == 0x0F && func[i + 1] == 0x05) {
            return &func[i];
        }
    }
    return nullptr;
}

// The stub now does: mov eax, SSN; mov r10, rcx; jmp [syscall_addr]
// Return address on kernel stack points into ntdll - looks clean
```

## Why It Works

The fundamental issue is that usermode hooks are cooperative - they depend on code flowing through the hooked path. If code can reach the kernel without touching the hook, the hook sees nothing.

VAC's usermode monitoring relied heavily on ntdll hooks to observe `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtQuerySystemInformation`, and similar calls. Direct syscalls made all of that monitoring blind to any cheat using them.

The deeper architectural problem is that Windows doesn't provide a clean kernel-level mechanism for monitoring which usermode code initiated a system call in a performant way. You can check the return address on the kernel stack, but that's bypassable with indirect syscalls or ROP-style gadgets.

## Detection Surface

**Direct syscall detection:**
- Kernel-mode callback or instrumentation checking the return address of the `syscall` - if it's not inside ntdll.dll or win32u.dll, something is wrong
- `InstrumentationCallback` (available since Win10) can intercept all syscall returns in usermode and validate the calling module
- Thread call stack analysis - a thread whose stack shows a syscall return into non-module memory

**Indirect syscall detection:**
- The return address points into ntdll, but the *call stack* doesn't make sense - there's no legitimate call chain leading to that ntdll address
- Stack unwinding reveals frames in unbacked memory
- `InstrumentationCallback` combined with stack tracing can catch this, but it's expensive

**SSN resolution detection:**
- Monitoring access to ntdll's `.text` section (reading stub bytes to extract SSNs)
- Detecting patterns of sequential reads across multiple Nt* stubs (characteristic of SSN harvesting)

**General heuristics:**
- A process making `NtReadVirtualMemory` calls that the AC's ntdll hooks never see is a strong signal, but requires a secondary monitoring mechanism to compare against

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2018 | Direct syscalls gain traction in cheat development. Initial implementations use hardcoded SSN tables per Windows build. |
| 2019 | `SysWhispers` released publicly - generates direct syscall stubs for any Nt* function. Massive adoption follows. |
| 2019-2020 | Anti-cheats begin checking syscall return addresses in kernel callbacks. Direct syscalls from cheat modules become detectable. |
| 2020 | `SysWhispers2` introduces indirect syscalls (jumping into ntdll to execute the actual `syscall` instruction). Return address now looks legitimate. |
| 2020-2021 | "Hell's Gate" / "Halo's Gate" / "Tartarus' Gate" - techniques for resolving SSNs at runtime even when ntdll stubs are hooked. |
| 2021+ | `SysWhispers3` and various forks add support for egg-hunting, random syscall jump targets, and other anti-detection measures. |
| 2022+ | Anti-cheats move to kernel-mode monitoring, `InstrumentationCallback`, and ETW-based tracing. The arms race continues. |

## Known Variants

- **SysWhispers (1/2/3)** - the de facto tooling. Generates header + ASM files for direct/indirect syscalls
- **Hell's Gate** - runtime SSN resolution by reading ntdll stub opcodes
- **Halo's Gate** - resolves SSNs from neighboring stubs when the target stub is hooked
- **Tartarus' Gate** - handles stubs hooked with longer detours (multiple patched bytes)
- **Egg hunting** - instead of jumping to a fixed offset in ntdll, scan for the `syscall` opcode dynamically
- **Spoofed call stacks** - combine indirect syscalls with call stack spoofing (synthetic RBP chains) to defeat stack unwinding

## References

- jthuraisamy, "SysWhispers" - original release (GitHub, 2019)
- klezVirus, "SysWhispers2/3" - indirect syscall evolution
- am0nsec & smelly__vx, "Hell's Gate" - runtime SSN resolution paper
- Alice Climent-Pommeret, "A Syscall Journey in the Windows Kernel" - deep dive on syscall dispatch
- `InstrumentationCallback` research by various authors (2020-2022)
- Elastic Security Labs - "Blinding EDR On Windows" (2022) - covers instrumentation callback detection
