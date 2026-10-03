# 05 - Thread Hijacking

## Summary

Thread hijacking avoids creating new threads in the target process - one of the most monitored injection indicators - by suspending an existing thread, redirecting its instruction pointer to cheat code, and resuming it. Once the code executes, the thread's context is restored to its original state and it continues as if nothing happened.

An execution primitive, not a full injection technique on its own. It's typically combined with manual mapping (technique 01) as the final step to trigger `DllMain` or an initialization function without calling `CreateRemoteThread`.

## Mechanism

1. **Enumerate threads** in the target process via `CreateToolhelp32Snapshot` + `Thread32First/Next`
2. **Pick a thread** - ideally one that's in a wait state or a known safe point (not holding critical locks)
3. **Suspend it** - `SuspendThread`
4. **Save context** - `GetThreadContext` captures the full register state (RIP, RSP, general purpose, XMM, etc.)
5. **Write a shellcode stub** into the target process that:
   - Saves any additional state
   - Calls the target function (e.g., mapped DLL's entry point)
   - Restores state
   - Signals completion (via event or flag)
   - Jumps back to the original RIP
6. **Redirect RIP** - `SetThreadContext` with RIP pointing to the shellcode
7. **Resume** - `ResumeThread`
8. **Wait for completion** - poll the signal flag or wait on the event
9. **Optionally clean up** - free the shellcode allocation

```
Before:  Thread -> GameCode @ 0x7FF601234
Hijack:  Thread -> Shellcode -> CheatInit() -> Restore -> GameCode @ 0x7FF601234
After:   Thread -> GameCode @ 0x7FF601234 (as if nothing happened)
```

## Implementation Sketch

```cpp
bool HijackThread(HANDLE hProcess, DWORD threadId, void* targetFunc) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, threadId);
    if (!hThread) return false;

    SuspendThread(hThread);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    ULONG64 originalRip = ctx.Rip;

    // Write shellcode that calls targetFunc then jumps back
    // [simplified - real code handles stack alignment, saves XMM, etc.]
    BYTE shellcode[] = {
        0x50,                                     // push rax (save)
        0x51,                                     // push rcx
        0x52,                                     // push rdx
        0x48, 0xB8, 0,0,0,0,0,0,0,0,            // mov rax, targetFunc
        0xFF, 0xD0,                               // call rax
        0x5A,                                     // pop rdx
        0x59,                                     // pop rcx
        0x58,                                     // pop rax
        0x48, 0xB8, 0,0,0,0,0,0,0,0,            // mov rax, originalRip
        0xFF, 0xE0                                // jmp rax
    };
    *(ULONG64*)(shellcode + 5) = (ULONG64)targetFunc;
    *(ULONG64*)(shellcode + 18) = originalRip;

    void* remoteShell = VirtualAllocEx(hProcess, nullptr,
        sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteShell, shellcode, sizeof(shellcode), nullptr);

    ctx.Rip = (ULONG64)remoteShell;
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    // Wait for execution, then clean up
    Sleep(100);
    VirtualFreeEx(hProcess, remoteShell, 0, MEM_RELEASE);

    CloseHandle(hThread);
    return true;
}
```

This sketch is intentionally simplified. Production hijacking code handles: XMM/YMM register preservation, stack alignment to 16 bytes before the call, TEB checks, structured exception handling, and the case where the target thread is holding a critical section.

## Why It Works

Anti-cheats monitor thread creation because `CreateRemoteThread` and `NtCreateThreadEx` are the standard injection execution primitives. A new thread in a game process with a start address pointing to unbacked memory is an immediate detection.

Thread hijacking avoids this entirely - no new thread is created. The execution happens on an existing, legitimate game thread. The only suspicious activity is:

1. `SuspendThread` + `SetThreadContext` + `ResumeThread` - which are legitimate debugging operations
2. A brief moment where a game thread's RIP points to unusual memory

If the shellcode executes and cleans up fast enough, there's no thread with an anomalous start address to scan for.

## Detection Surface

API monitoring:
- `SuspendThread` + `GetThreadContext` + `SetThreadContext` + `ResumeThread` sequence targeting a game thread from an external process
- Cross-process context modification is relatively rare in legitimate use

Stack analysis:
- Periodic stack walks of game threads - if a thread's current RIP or return addresses point to unbacked memory, that's suspicious
- This is a timing-dependent detection (you have to catch it during execution)

ETW tracing:
- Thread context modification events can be captured via ETW providers
- `SuspendThread`/`ResumeThread` generate traceable events

Shellcode artifacts:
- The shellcode allocation - a small RWX region that appears and disappears is suspicious
- If the shellcode isn't cleaned up immediately, it's scannable

APC-based variant detection:
- `QueueUserAPC` targeting game threads is another form of hijacking
- APC queues can be enumerated from kernel mode

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2010 | Thread hijacking used in malware for years before game cheats adopt it. |
| 2015-2016 | Game cheat developers adopt it as a `CreateRemoteThread` alternative. Often paired with manual mapping. |
| 2017-2018 | Becomes standard practice in quality loaders. `CreateRemoteThread` usage drops in anything that's trying to be stealthy. |
| 2019+ | Anti-cheats add stack walking and thread context monitoring. The technique still works but the window of opportunity shrinks. |
| 2021+ | Some loaders move to instrumentation callbacks or exception-based execution to avoid even `SetThreadContext`. |

## Known Variants

- APC injection - instead of modifying RIP directly, queue an APC to the target thread. The thread executes the APC when it enters an alertable wait state. Avoids `SetThreadContext` but requires the thread to be alertable.
- Exception-based execution - trigger a hardware breakpoint or guard page exception in the target thread. The exception handler (registered via VEH in advance) redirects to cheat code.
- NtQueueApcThreadEx - kernel-mode APC that executes even if the thread is not alertable (special APC). Requires a kernel driver.
- Instrumentation callback - set the process instrumentation callback to cheat code. Every syscall return triggers it. Very powerful but monitored.

## References

- Various malware analysis papers on thread context manipulation (2010s)
- UnknownCheats - thread hijacking implementation discussions
- Microsoft documentation on `CONTEXT` structure and thread context manipulation
- ETW provider documentation for thread events
