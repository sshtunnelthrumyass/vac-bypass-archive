# 08 - Driver-Based Memory Read

## Summary

Driver-based memory reading uses a kernel-mode driver to read game process memory directly from Ring 0, bypassing all usermode protections and most handle-based monitoring. The driver can attach to the game's address space (or walk page tables manually) and copy memory without ever acquiring a usermode handle to the process.

This is the dominant technique for external cheats (ESPs, radars) that need to read game state without injecting into the game process. It's been the backbone of kernel-level cheat development since ~2016.

## Mechanism

### Method 1: MmCopyVirtualMemory / KeStackAttachProcess

The most straightforward approach. The driver:

1. Receives a read request from the usermode cheat (via IOCTL, shared memory, or a mapped section)
2. Gets a reference to the target process via `PsLookupProcessByProcessId`
3. Calls `MmCopyVirtualMemory` to copy memory from the target's address space to the caller's buffer

Alternatively, the driver can:
1. Attach to the target's address space with `KeStackAttachProcess`
2. Read memory directly (it's now accessible in the current context)
3. Detach with `KeUnstackDetachProcess`

Both approaches read memory at the kernel level - no usermode handle, no `ReadProcessMemory`, nothing for `ObRegisterCallbacks` to intercept.

### Method 2: Physical Memory Translation

For maximum stealth, some drivers skip the Windows memory manager entirely:

1. Walk the target process's page tables (CR3 -> PML4 -> PDPT -> PD -> PT -> physical page)
2. Map the target physical page into the driver's address space via `MmMapIoSpace` or MDL mapping
3. Read directly from the physical page

This bypasses not just handle monitoring but also any hooks on `MmCopyVirtualMemory` or `KeStackAttachProcess`.

### Method 3: DMA (Direct Memory Access)

Hardware DMA devices (PCIe cards, Thunderbolt adapters) can read physical RAM directly through the PCIe bus, without involving the CPU at all. The OS - and any anti-cheat running on it - has no visibility into DMA reads.

Commercial DMA devices for game cheating exist (FPGA-based PCIe cards). The host PC's RAM is read by a second machine connected via the DMA device.

## Implementation Sketch

```cpp
// Kernel driver - IOCTL-based memory read service
// Method 1: MmCopyVirtualMemory

struct ReadRequest {
    ULONG targetPid;
    ULONG64 address;
    ULONG64 buffer;
    ULONG size;
};

NTSTATUS HandleReadIoctl(PIRP irp) {
    auto req = (ReadRequest*)irp->AssociatedIrp.SystemBuffer;

    PEPROCESS targetProcess;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T bytesRead;
    status = MmCopyVirtualMemory(
        targetProcess,               // source process
        (PVOID)req->address,          // source address
        PsGetCurrentProcess(),        // destination process (caller)
        (PVOID)req->buffer,           // destination buffer
        req->size,                    // size
        KernelMode,                   // previous mode
        &bytesRead);

    ObDereferenceObject(targetProcess);
    return status;
}
```

```cpp
// Method 2: Manual page table walk (simplified, x64 4-level paging)

ULONG64 TranslateVirtToPhys(ULONG64 cr3, ULONG64 virtualAddr) {
    ULONG64 pml4Idx = (virtualAddr >> 39) & 0x1FF;
    ULONG64 pdptIdx = (virtualAddr >> 30) & 0x1FF;
    ULONG64 pdIdx   = (virtualAddr >> 21) & 0x1FF;
    ULONG64 ptIdx   = (virtualAddr >> 12) & 0x1FF;
    ULONG64 offset  = virtualAddr & 0xFFF;

    // Read PML4 entry
    ULONG64 pml4e = ReadPhysical(cr3 + pml4Idx * 8);
    if (!(pml4e & 1)) return 0; // not present

    // Read PDPT entry
    ULONG64 pdpte = ReadPhysical((pml4e & 0xFFFFFFFFF000) + pdptIdx * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) return (pdpte & 0xFFFFC0000000) + (virtualAddr & 0x3FFFFFFF); // 1GB page

    // Read PD entry
    ULONG64 pde = ReadPhysical((pdpte & 0xFFFFFFFFF000) + pdIdx * 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80) return (pde & 0xFFFFFFE00000) + (virtualAddr & 0x1FFFFF); // 2MB page

    // Read PT entry
    ULONG64 pte = ReadPhysical((pde & 0xFFFFFFFFF000) + ptIdx * 8);
    if (!(pte & 1)) return 0;

    return (pte & 0xFFFFFFFFF000) + offset;
}
```

## Why It Works

A kernel driver operates at Ring 0 - the same privilege level as the anti-cheat's kernel component. There's no architectural privilege boundary between them. The question isn't "can the driver read memory" (it can, trivially) but "can the AC detect and stop it."

The driver doesn't need a usermode handle. `ObRegisterCallbacks` is irrelevant. The driver doesn't call any hooked usermode APIs. If it uses physical memory translation, it doesn't even call hookable kernel APIs.

For DMA-based reads, the reading hardware operates outside the CPU entirely. The OS has zero visibility unless an IOMMU is configured to block the access - and most consumer systems don't configure IOMMU restrictions by default.

## Detection Surface

**Driver loading detection:**
- `PsSetLoadImageNotifyRoutine` - notified when any driver loads
- Driver signature enforcement (DSE) - only signed drivers load (but can be bypassed via BYOVD, DSE disable, or test signing)
- Driver certificate validation - check the signer against a blocklist

**Kernel API hooking / monitoring:**
- Hook `MmCopyVirtualMemory`, `KeStackAttachProcess`, `PsLookupProcessByProcessId` - detect suspicious callers
- Monitor `MmMapIoSpace` calls for physical address ranges that correspond to the game's pages
- Problem: the cheat driver can bypass these hooks with the same techniques (direct syscalls at kernel level, manual page table walks)

**Memory forensics:**
- Scan kernel memory for known cheat driver signatures
- Enumerate loaded drivers via `ZwQuerySystemInformation` and cross-reference against a whitelist
- Look for manually mapped kernel modules (same concept as usermode manual mapping, applied at Ring 0)

**DMA detection:**
- IOMMU enforcement - configure VT-d / AMD-Vi to restrict which PCIe devices can access which physical memory ranges
- Monitor PCIe configuration space for unexpected devices
- Measure memory access patterns - DMA reads have different latency characteristics than CPU reads (detectable via performance counters in some cases)

**Behavioral detection:**
- Monitor process communication patterns - a usermode process that knows game state (player positions, health) but never opened a handle to the game must be getting it somewhere
- Anti-cheat can modify game memory in known ways and check if the cheat reacts, confirming it has read access through some channel

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2016 | Custom kernel drivers for memory reading become common. Initially just wrapping `MmCopyVirtualMemory` behind an IOCTL. |
| 2017-2018 | Anti-cheats add kernel-level driver monitoring. Cheat drivers move to physical memory translation to avoid API hooks. |
| 2018-2019 | BYOVD becomes mainstream - cheat loaders exploit signed vulnerable drivers to load unsigned kernel code. `KDMapper` released. |
| 2019-2020 | DMA-based cheats emerge in competitive scenes. FPGA PCIe cards read RAM at hardware level. |
| 2020-2021 | Anti-cheats push for Secure Boot, HVCI, and IOMMU enforcement to block unsigned drivers and DMA attacks. |
| 2021+ | Microsoft Vulnerable Driver Blocklist expands. HVCI becomes default on new Windows installs. The barrier to kernel access rises steadily. |
| 2023+ | DMA cheats targeted with IOMMU policies and PCIe device monitoring. Some tournament environments use custom BIOS settings to lock down DMA. |

## Known Variants

- **IOCTL-based** - standard pattern: usermode client sends requests, driver fulfills them
- **Shared memory** - driver and cheat communicate through a shared mapped section, avoiding IOCTL monitoring
- **Physical-only** - driver maps physical RAM and walks page tables, never touching Windows MM APIs
- **DMA hardware** - external PCIe/Thunderbolt device reads RAM over the bus
- **Firmware-based** - SMM (System Management Mode) or UEFI runtime services used as a read primitive, sitting below the OS entirely
- **Manually mapped driver** - the cheat driver itself is loaded without the Windows driver loader, hiding from `PsSetLoadImageNotifyRoutine`

## References

- `KDMapper` by TheCruZ - driver manual mapping via vulnerable driver exploitation
- LOLDrivers project - catalog of exploitable signed drivers
- Microsoft, "Hypervisor-protected Code Integrity (HVCI)" - documentation on driver signature enforcement
- Microsoft, "Kernel DMA Protection" - IOMMU-based DMA restriction
- Various PCLeech / DMA attack research (Ulf Frisk)
- Intel SDM - page table structure and physical memory addressing
