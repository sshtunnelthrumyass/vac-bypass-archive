# 03 - Hypervisor-Based Hiding

## Summary

Hypervisor-based hiding exploits hardware virtualization (Intel VT-x / AMD-V) to create a thin virtual machine monitor (VMM) that sits *beneath* the operating system. From this position, the hypervisor can intercept and manipulate any kernel-level operation - including anti-cheat integrity checks - while remaining fundamentally invisible to any software running inside the guest, which includes the OS and the anti-cheat.

This is the nuclear option. It's the hardest to implement, the hardest to detect, and represents a privilege boundary that software-only anti-cheats cannot cross.

## Mechanism

### The Privilege Stack

Normal execution:

```
Ring 3 (User)    ->  Game, Cheat, Anti-Cheat usermode
Ring 0 (Kernel)  ->  OS Kernel, Anti-Cheat driver
```

With a hypervisor:

```
Ring 3 (User)    ->  Game, Cheat (usermode component)
Ring 0 (Kernel)  ->  OS Kernel, Anti-Cheat driver
VMX Root         ->  Hypervisor (cheat's VMM) <- controls everything above
```

The hypervisor runs in VMX root mode, which is architecturally *more privileged* than Ring 0. The OS kernel - including any anti-cheat driver - runs as a guest inside the hypervisor's VM. The guest doesn't know it's virtualized (or can be made to not know).

### What the Hypervisor Can Do

From VMX root, the hypervisor controls:

- **Memory visibility** - EPT (Extended Page Tables) control what physical memory the guest can see. The hypervisor can hide its own memory, hide the cheat's memory, or present fake memory contents to integrity checks.
- **Instruction interception** - VM exits on specific instructions (CPUID, RDMSR, CR access) let the hypervisor fake hardware responses.
- **Read/write interception** - EPT violations trigger on guest memory access, allowing the hypervisor to serve different data depending on who's reading. The anti-cheat reads clean memory; the cheat reads modified memory.

### EPT Shadowing (The Key Technique)

This is where it gets interesting for cheat hiding. The hypervisor maintains two EPT mappings:

1. **Clean EPT** - maps physical memory normally. This is what the anti-cheat sees.
2. **Dirty EPT** - maps modified pages (cheat hooks, patched game code). This is what the game executes.

When the anti-cheat reads a hooked code page to verify integrity, the hypervisor intercepts the read via an EPT violation and serves the clean, unmodified page. When the game executes that same page, it runs the hooked version.

This is sometimes called a "split TLB" or "EPT shadow" attack.

```
Anti-cheat reads 0x7FF601000:  EPT -> clean physical page  -> checksum passes [OK]
Game executes   0x7FF601000:  EPT -> dirty physical page  -> hook runs
```

## Implementation Sketch

```cpp
// Extremely simplified - real hypervisors are thousands of lines
struct VmState {
    PVOID eptClean;       // EPT pointer for integrity checks
    PVOID eptDirty;       // EPT pointer for execution
    ULONG64 hookPage;     // GPA of the page we're shadowing
    PVOID cleanCopy;      // Clean copy of the original page
    PVOID dirtyPage;      // Page with our hooks installed
};

// EPT violation handler - called on every EPT fault
void HandleEptViolation(VmState* vm, ULONG64 guestPhysical, bool isExecute) {
    if (guestPhysical == vm->hookPage) {
        if (isExecute) {
            // Game is executing - give it the hooked page
            SwitchEpt(vm, vm->eptDirty);
        } else {
            // Something is reading (probably AC integrity check)
            // Give it the clean page
            SwitchEpt(vm, vm->eptClean);
        }
    }
}

// CPUID handler - hide virtualization from detection
void HandleCpuid(VcpuContext* ctx) {
    __cpuid(ctx->regs, ctx->eax);

    if (ctx->eax == 1) {
        // Clear the hypervisor present bit (ECX bit 31)
        ctx->ecx &= ~(1 << 31);
    }
}
```

## Why It Works

The x86 virtualization architecture was designed so that a VMM has *complete* control over the guest. This isn't a bug - it's the entire point of hardware virtualization. The problem is that "complete control" includes the ability to lie to every piece of software in the guest, including security software.

An anti-cheat running in Ring 0 cannot detect a well-implemented hypervisor because:

1. Every detection mechanism the AC could use (CPUID, MSR reads, timing checks, memory scans) can be intercepted and spoofed by the VMM
2. The AC's own memory accesses go through EPT, so the VMM controls what the AC sees
3. The AC cannot execute code in VMX root - that's architecturally enforced by the CPU

The only reliable detection requires either running your own hypervisor first (race condition), using a hardware IOMMU with attestation, or checking for timing anomalies that the hypervisor's VM exit overhead introduces.

## Detection Surface

**Timing-based detection:**
- VM exits add latency (~1-10us per exit). Tight timing loops measuring CPUID, RDTSC, or MSR access can detect the overhead.
- Problem: the hypervisor can intercept RDTSC/RDTSCP and adjust the returned value to hide the delay.
- Counter-counter: use external timing references (NTP, network round-trip, hardware timers) that the hypervisor can't easily fake.

**Hypervisor presence indicators:**
- CPUID leaf 0x1 ECX bit 31 (hypervisor present) - but easily cleared by the VMM
- CPUID leaf 0x40000000 (hypervisor vendor string) - also fakeable
- VMX MSR availability - but the VMM can trap and hide these

**Hardware-level detection:**
- IOMMU / VT-d attestation (if the platform supports it)
- TPM-based measured boot - detects if the boot chain was altered to load a hypervisor
- Secure boot enforcement - prevents unsigned hypervisor drivers from loading (but doesn't help if the attacker has a signed driver or exploits a vulnerability)

**Behavioral heuristics:**
- Performance counter anomalies - PMCs can sometimes reveal VM exit patterns
- Cache-based side channels - EPT switching causes TLB flushes that are measurable
- The hypervisor has to be loaded somehow - the driver loading and VMX initialization leave kernel traces before the guest is fully encapsulated

## Historical Timeline

| Period | Development |
|--------|-------------|
| 2006 | Intel VT-x and AMD-V released. Academic research on "blue pill" attacks begins (Joanna Rutkowska). |
| 2007-2015 | Hypervisor-based rootkits remain largely academic. Too complex for most cheat developers. |
| 2016-2017 | Projects like `hvpp`, `hyperbone`, and `SimpleSvm` lower the barrier. First cheat-oriented hypervisors appear on private forums. |
| 2018 | `DdiMon` and `HyperPlatform` demonstrate EPT hooking. Cheat developers adopt the technique for game function hooks. |
| 2019-2020 | EPT shadowing for integrity check evasion becomes the gold standard for high-end private cheats targeting kernel-level ACs. |
| 2021+ | Anti-cheats begin deploying their own hypervisors (Riot's Vanguard explored this) or requiring Secure Boot / TPM attestation to reduce the attack surface. |

## Known Variants

- **Blue Pill style** - load the hypervisor at runtime, virtualizing the running OS beneath it. No reboot required.
- **Boot-loaded VMM** - hypervisor loads during boot via a signed driver or EFI module, establishing control before the OS starts.
- **Nested virtualization abuse** - run inside an existing hypervisor (Hyper-V, VMware) and manipulate the nested EPT tables.
- **EPT hook-only** - use the hypervisor solely for stealthy function hooking (no full cheat logic in VMX root). The hook redirects execution to usermode or kernel cheat code.
- **Memory cloaking** - the hypervisor hides entire memory regions from the guest, making allocated cheat memory completely invisible to all guest-level scans.

## References

- Joanna Rutkowska, "Introducing Blue Pill" (2006) - foundational hypervisor rootkit concept
- Satoshi Tanda, `HyperPlatform` - open-source research hypervisor with EPT hooking
- Petr Benes, `hvpp` - minimal VT-x hypervisor
- tandasat, `SimpleSvm` - AMD-V hypervisor for research
- Intel SDM Vol. 3, Chapters 23-33 - VMX architecture specification
- Various UC/GH threads on EPT-based game hooking (2018-present)
