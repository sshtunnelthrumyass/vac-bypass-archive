# Detection Matrix

Cross-reference of techniques against detection methods. Shows which detection approach catches which technique, and at what reliability.

## Key

- ✅ **Reliable** - catches the technique consistently in known implementations
- ⚠️ **Partial** - catches some variants or implementations, bypassed by others
- ❌ **Ineffective** - doesn't meaningfully detect this technique
- 🔄 **Arms race** - effectiveness depends on which generation of technique vs. detection

## Matrix

| Detection Method | Manual Map | Syscalls | Hypervisor | DLL Hollow | Thread Hijack | Handle Elev. | Timing Evasion | Driver Read |
|---|---|---|---|---|---|---|---|---|
| **PEB module list scan** | ✅ detects absence | ❌ | ❌ | ❌ passes | ❌ | ❌ | ❌ | ❌ |
| **Memory region enumeration** | ⚠️ finds unbacked RX | ❌ | ❌ hidden by EPT | ❌ file-backed | ❌ | ❌ | ❌ | ❌ |
| **PE header scanning** | ⚠️ if not wiped | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **On-disk vs in-memory hash** | ❌ no disk file | ❌ | ❌ | ✅ catches it | ❌ | ❌ | ❌ | ❌ |
| **ntdll hook integrity** | ❌ | ❌ bypasses hooks | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Syscall return address check** | ❌ | ⚠️ catches direct, not indirect | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **InstrumentationCallback** | ❌ | 🔄 catches some | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Stack walk / unwinding** | ⚠️ during init | 🔄 catches bad spoofs | ❌ | ❌ | ⚠️ if caught mid-exec | ❌ | ❌ | ❌ |
| **ObRegisterCallbacks** | ❌ no handle needed | ❌ | ❌ | ❌ | ❌ | ⚠️ catches direct only | ❌ | ❌ |
| **Handle table auditing** | ❌ | ❌ | ❌ | ❌ | ❌ | 🔄 | ❌ | ❌ |
| **RDTSC timing checks** | ❌ | ❌ | ⚠️ detects naive VMMs | ❌ | ❌ | ❌ | 🔄 | ❌ |
| **Multi-source timing** | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | 🔄 | ❌ |
| **Thread creation monitoring** | ⚠️ if CRT used | ❌ | ❌ | ❌ | ✅ avoids it | ❌ | ❌ | ❌ |
| **Thread context monitoring** | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ |
| **Driver load notification** | ❌ | ❌ | ⚠️ driver must load | ❌ | ❌ | ⚠️ BYOVD driver | ❌ | ⚠️ if not manually mapped |
| **Vulnerable driver blocklist** | ❌ | ❌ | ❌ | ❌ | ❌ | 🔄 | ❌ | 🔄 |
| **HVCI enforcement** | ❌ | ❌ | ⚠️ blocks some | ❌ | ❌ | ✅ blocks unsigned | ❌ | ✅ blocks unsigned |
| **Secure Boot / TPM** | ❌ | ❌ | ⚠️ measured boot | ❌ | ❌ | ⚠️ | ❌ | ⚠️ |
| **IOMMU / VT-d** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ blocks DMA |
| **Kernel API hooks** | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ⚠️ bypassable |
| **ETW tracing** | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ |
| **Behavioral / heuristic** | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |

## Observations

**No single detection catches everything -** defense needs layered detection. Multiple independent signals covering each other's blind spots.

**Usermode-only detection is insufficient.** Techniques 02 (syscalls), 03 (hypervisor), 06 (handle elevation), and 08 (driver read) are largely invisible to usermode-only monitoring. This is why modern anti-cheats require kernel drivers.

**Hardware-level enforcement is the most reliable.** HVCI, Secure Boot, IOMMU, and TPM attestation create barriers that can't be bypassed with clever code - they require hardware-level attacks or vulnerabilities. Anti-cheat enforcement keeps pushing closer to hardware.

Behavioral detection is the catch-all. When direct detection fails, observing what the cheat *does* (impossible game state knowledge, superhuman reactions, statistically unlikely behavior) catches what technical evasion hides. This is the VACNet / machine learning approach.

## Coverage Gaps

The worst gaps are techniques with no ✅ in their column -

- Hypervisor + timing evasion - no reliable detection from within the guest
- Manually mapped kernel driver + physical memory reads - invisible to most kernel monitoring
- DMA without IOMMU - undetectable by any software-only method
