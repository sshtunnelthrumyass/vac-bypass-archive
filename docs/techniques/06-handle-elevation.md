# 06 - Handle Elevation & Abuse

## Summary

Instead of opening a handle to the game process directly (which anti-cheats monitor via `ObRegisterCallbacks`), handle elevation techniques acquire or upgrade a handle through indirect means that bypass the monitoring callbacks. This includes duplicating handles from other processes, exploiting handle inheritance, abusing debug privileges, or leveraging vulnerable drivers that expose handle-granting IOCTLs.

The goal is simple: get `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` access to the game process without triggering the anti-cheat's handle creation callbacks.

## Mechanism

### Why Direct Handle Opening Gets Caught

Kernel-level anti-cheats register an `ObRegisterCallbacks` routine that fires on every `ObOpenObjectByPointer` / `NtOpenProcess` call. The callback inspects:

- What process is being opened
- What access rights are requested
- Who's requesting them

If an unknown process requests `PROCESS_VM_READ` to the game, the callback strips the access bits or denies the request entirely.

### Elevation Methods

**1. Handle Duplication from a Privileged Process**

Some system processes (like `lsass.exe`, `csrss.exe`, or certain service hosts) already hold handles to every process. If you can get code execution in one of these, you can duplicate their existing handle to yourself.

```
csrss.exe has handle to game.exe (PROCESS_ALL_ACCESS)
    -> Duplicate to cheat.exe via NtDuplicateObject
    -> cheat.exe now has a handle that was never opened through ObRegisterCallbacks
```

**2. Handle Inheritance**

When a process creates a child process, the child can inherit the parent's handles if they're marked as inheritable. A cheat can:

1. Mark its handle to the game as inheritable
2. Spawn a child process that inherits it
3. The child now has a "clean" handle that it never opened

**3. Vulnerable Driver Exploitation**

Numerous signed kernel drivers expose IOCTLs that perform operations on behalf of the caller - including opening handles, reading memory, or mapping physical memory. These are commonly called "bring your own vulnerable driver" (BYOVD) attacks.

```
capcom.sys      - exposes a "run this function in kernel mode" IOCTL
iqvw64e.sys     - Intel driver, exposes physical memory mapping
dbutil_2_3.sys  - Dell driver, arbitrary read/write
gdrv.sys        - Gigabyte driver, physical memory access
```

**4. Debug Privilege + PssCaptureSnapshot**

With `SeDebugPrivilege` enabled, a process can use `PssCaptureSnapshot` to create a snapshot of the target process. The snapshot contains a copy of the process's memory that can be read without holding a handle to the original process.

## Implementation Sketch

```cpp
// Method 1: Duplicate from csrss.exe (simplified)
HANDLE StealHandleFromCsrss(DWORD gamePid) {
    // Find csrss
    DWORD csrssPid = FindProcessByName(L"csrss.exe");
    HANDLE hCsrss = OpenProcess(PROCESS_DUP_HANDLE, FALSE, csrssPid);

    // Enumerate handles in csrss via NtQuerySystemInformation
    auto handles = EnumProcessHandles(csrssPid);

    for (auto& h : handles) {
        // Check if this handle points to our game process
        // by duplicating with DUPLICATE_SAME_ACCESS and querying the PID
        HANDLE dup;
        DuplicateHandle(hCsrss, (HANDLE)h.HandleValue,
                       GetCurrentProcess(), &dup,
                       0, FALSE, DUPLICATE_SAME_ACCESS);

        if (GetProcessId(dup) == gamePid) {
            // Found it - this handle was never opened through
            // ObRegisterCallbacks targeting our process
            CloseHandle(hCsrss);
            return dup;
        }
        CloseHandle(dup);
    }
    CloseHandle(hCsrss);
    return nullptr;
}
```

```cpp
// Method 3: BYOVD - using a vulnerable driver to read memory
// (Generic pattern - specific IOCTL codes vary per driver)
struct DriverReadRequest {
    ULONG64 targetPid;
    ULONG64 sourceAddress;
    ULONG64 destAddress;
    ULONG64 size;
};

bool ReadViaDriver(HANDLE hDriver, DWORD pid, void* addr, void* buf, size_t sz) {
    DriverReadRequest req = {};
    req.targetPid = pid;
    req.sourceAddress = (ULONG64)addr;
    req.destAddress = (ULONG64)buf;
    req.size = sz;

    DWORD bytesReturned;
    return DeviceIoControl(hDriver, IOCTL_READ_MEMORY,
        &req, sizeof(req), nullptr, 0, &bytesReturned, nullptr);
}
```

## Detection Surface

**Handle duplication detection:**
- `ObRegisterCallbacks` can also be registered for `OB_OPERATION_HANDLE_DUPLICATE`
- Monitoring `NtDuplicateObject` calls that target game process handles
- Tracking which processes hold handles to the game - any unexpected holder is suspicious

**BYOVD detection:**
- Driver signature/hash blocklists - Microsoft maintains a Vulnerable Driver Blocklist (HVCI)
- Monitoring driver loads via `PsSetLoadImageNotifyRoutine` - alert on known vulnerable drivers
- Certificate revocation for known-bad driver signatures

**Handle inheritance detection:**
- Monitoring process creation with inherited handles via `PsSetCreateProcessNotifyRoutine`
- Checking handle tables of child processes for inherited game handles

**General:**
- Periodic handle table audits - enumerate all handles to the game process kernel-side and verify each holder is legitimate
- `NtQuerySystemInformation(SystemHandleInformation)` from the AC driver

## Historical Timeline

| Period | Development |
|--------|-------------|
| 2017 | `ObRegisterCallbacks` becomes standard in kernel ACs. Direct `OpenProcess` stops working for cheats. |
| 2017-2018 | Handle duplication from system processes becomes the primary workaround. |
| 2018-2019 | BYOVD attacks gain popularity. Capcom.sys is the poster child. |
| 2019-2020 | Microsoft begins building the Vulnerable Driver Blocklist. AC vendors maintain their own lists. |
| 2020+ | Cat-and-mouse continues. New vulnerable drivers are found regularly. Some cheats ship their own custom-signed drivers using leaked/stolen EV certificates. |
| 2022+ | HVCI (Hypervisor-protected Code Integrity) blocks unsigned/vulnerable driver loading on newer systems. The bar rises. |

## Known Variants

- **Physical memory mapping** - some vulnerable drivers map physical RAM directly. The cheat reads/writes physical addresses, bypassing all virtual memory protections.
- **KDMapper** - uses a vulnerable driver to manually map an unsigned driver into kernel memory, which then provides handle-free memory access.
- **Process snapshot abuse** - `PssCaptureSnapshot` with debug privileges creates a readable memory clone.
- **Named pipe handle passing** - pass handles between processes through named pipes or shared memory, obscuring the duplication chain.
- **EFI bootkit** - modify the boot chain to load a kernel module before AC drivers initialize, pre-empting handle monitoring entirely.

## References

- Microsoft, "Vulnerable Driver Blocklist" - official list and HVCI documentation
- `KDMapper` by TheCruZ - open-source vulnerable driver exploitation framework
- Various BYOVD research papers (2019-2022)
- Microsoft documentation on `ObRegisterCallbacks` and `OB_OPERATION_HANDLE_DUPLICATE`
- LOLDrivers project - curated list of living-off-the-land vulnerable drivers
