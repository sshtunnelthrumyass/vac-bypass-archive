# 07 - Timing Attack Evasion

## Summary

Anti-cheat systems use timing measurements to detect anomalies - hooked functions take longer to execute, virtualized instructions have VM exit overhead, and suspicious code paths introduce measurable latency. Timing attack evasion encompasses techniques that manipulate, spoof, or neutralize these timing-based detections.

This is a meta-technique: it doesn't inject or hide anything directly, but it protects other techniques from being detected through timing analysis.

## Mechanism

### What Anti-Cheats Measure

**Function execution timing:**
The AC measures how long critical functions take to execute. A hooked `NtQueryVirtualMemory` that detours through cheat code will take measurably longer than the clean version. The AC benchmarks the function, calls it repeatedly, and flags statistical outliers.

**Instruction-level timing:**
`RDTSC` (Read Time-Stamp Counter) and `QueryPerformanceCounter` are used to time individual operations. `CPUID` followed by `RDTSC` gives a serialized timestamp. Under a hypervisor, `CPUID` causes a VM exit (~500-2000 cycles), which is measurable.

**Integrity check timing:**
The AC hashes memory regions at intervals. If a hooked page is being decrypted/re-encrypted on access (to evade integrity checks), the hash computation takes longer than it should for a simple memory read.

### Evasion Methods

**1. TSC Offsetting**

The hypervisor (if one is used) can intercept `RDTSC`/`RDTSCP` and subtract the accumulated VM exit overhead from the returned value. The guest sees a smooth, monotonically increasing counter with no gaps.

```
Real TSC:    1000 -> [VM exit: 800 cycles] -> 1800
Reported:    1000 -> 1000 + (1800 - 1000 - 800) = 1000
Adjusted:    1000 -> 1200  (reports only guest execution time)
```

**2. QPC Spoofing**

`QueryPerformanceCounter` reads from a shared page (`KUSER_SHARED_DATA`) or issues `RDTSC`. By hooking the shared page (via EPT if using a hypervisor, or via memory write) or intercepting `RDTSC`, the returned values can be smoothed.

**3. Statistical Noise Injection**

Instead of trying to hide timing overhead entirely, add artificial jitter to legitimate measurements so the AC's statistical model can't distinguish cheat overhead from normal variance. If clean function calls already vary by +/-500 cycles, adding 200 cycles of cheat overhead doesn't cross any threshold.

**4. Measurement Window Avoidance**

Cheats can detect when the AC is running its timing checks (by monitoring AC thread scheduling, or hooking the AC's timing functions) and temporarily disable hooks/patches during the measurement window. "Be clean when they're looking."

**5. Hardware Timer Manipulation**

On platforms where the cheat has kernel or hypervisor access, hardware timers (HPET, ACPI PM timer, local APIC timer) can be intercepted or adjusted to present consistent timing across all measurement sources.

## Implementation Sketch

```cpp
// TSC offset compensation in a hypervisor VMX exit handler
struct VcpuState {
    ULONG64 tscOffset;    // accumulated VM exit overhead
    ULONG64 lastExitTsc;  // TSC at last VM exit entry
};

void HandleVmExit(VcpuState* vcpu) {
    ULONG64 exitStart = __rdtsc();

    // ... handle the exit reason ...

    ULONG64 exitEnd = __rdtsc();
    vcpu->tscOffset += (exitEnd - exitStart);
}

void HandleRdtsc(VcpuState* vcpu, GuestRegs* regs) {
    ULONG64 realTsc = __rdtsc();
    ULONG64 adjustedTsc = realTsc - vcpu->tscOffset;

    regs->rax = adjustedTsc & 0xFFFFFFFF;
    regs->rdx = (adjustedTsc >> 32) & 0xFFFFFFFF;
}
```

```cpp
// Usermode - detect AC timing checks by monitoring thread scheduling
class TimingGuard {
    std::atomic<bool> acIsChecking{false};

    void MonitorAcThread() {
        // Watch the AC module's known timing-check function
        // When it's scheduled, set the flag
        while (running) {
            if (IsAcTimingThreadActive()) {
                acIsChecking = true;
                // Temporarily unhook / restore clean state
                RestoreCleanHooks();
                WaitForAcTimingComplete();
                ReinstallHooks();
                acIsChecking = false;
            }
            Sleep(1);
        }
    }
};
```

## Why It Works

Timing-based detection relies on the assumption that the AC's measurement infrastructure is trusted. But:

1. In usermode, the cheat runs at the same privilege level as the AC - any timing API the AC calls can be hooked
2. In kernel mode, the cheat's driver (if present) can hook the same primitives
3. In VMX root, the hypervisor controls what the hardware appears to report

The fundamental problem is that you can't reliably measure time from inside a system that an adversary controls. External timing sources (network NTP, hardware attestation) are harder to fake but impractical for continuous monitoring.

## Detection Surface

**Cross-reference multiple timing sources:**
- Compare `RDTSC` against `QueryPerformanceCounter` against `KUSER_SHARED_DATA.SystemTime` against network time
- Discrepancies between sources suggest manipulation
- Problem: a sophisticated hypervisor can intercept all of these

**Statistical anomaly detection:**
- Build a model of expected timing distributions during clean execution
- Look for impossible values (negative deltas, zero-variance sequences) rather than just threshold violations
- Smoothed TSC offsets sometimes produce unnaturally consistent timing

**Hardware-based timing:**
- TPM monotonic counters can't be intercepted by a hypervisor
- PCIe device timestamps (if available) operate outside the VMM's control
- These are impractical for fine-grained measurement but can detect gross manipulation

**Detecting TSC interception:**
- The VMX `RDTSC exiting` bit causes VM exits on RDTSC - this adds measurable overhead to other operations that the hypervisor might not be compensating for
- Nested timing checks (measure the time it takes to measure time) can sometimes reveal interception

## Historical Timeline

| Period | Development |
|--------|-------------|
| ~2018 | Anti-cheats begin using `RDTSC` measurements to detect hypervisors and hooked functions. |
| 2018-2019 | Cheat hypervisors add TSC offset compensation. Basic QPC hooking in usermode cheats. |
| 2019-2020 | Anti-cheats add multi-source timing comparisons. Cheats respond by intercepting all sources. |
| 2020-2021 | Statistical models replace threshold-based detection. Cheats add jitter injection. |
| 2021+ | The arms race continues. No definitive winner - timing-based detection is useful but not reliable against a determined adversary with hypervisor control. |

## Known Variants

- **TSC scaling** - use the VMX TSC scaling feature (available on newer Intel CPUs) to adjust the guest's TSC rate transparently
- **Shared data page shadowing** - EPT-shadow `KUSER_SHARED_DATA` to control what system time values the guest reads
- **Selective interception** - only compensate TSC for known AC threads, leave other threads alone to maintain realistic system-wide timing behavior
- **NTP poisoning** - intercept NTP responses to control the system's external time reference (rarely used, fragile)

## References

- Intel SDM Vol. 3, Chapter 25 - VMX timer controls, TSC offsetting
- Various hypervisor research papers on timing side channels
- Academic literature on timing channel covert communication (related techniques)
- Anti-cheat vendor blog posts on timing-based hypervisor detection
