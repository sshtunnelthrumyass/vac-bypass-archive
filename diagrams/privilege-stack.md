# Privilege Stack & Technique Mapping

```
+-------------------------------------------------------------+
|                     HARDWARE / DMA                          |
|                                                             |
|  Technique 08 (DMA variant): PCIe/Thunderbolt memory read   |
|  Detection: IOMMU / VT-d enforcement                        |
|---------------------------------------------------------------|
|                  VMX ROOT (Ring -1)                          |
|                                                             |
|  Technique 03: Hypervisor-based hiding                      |
|  Technique 07: Timing evasion (TSC manipulation)            |
|  Detection: Measured boot, TPM attestation, timing checks   |
|---------------------------------------------------------------|
|                  KERNEL (Ring 0)                             |
|                                                             |
|  Technique 06: Handle elevation (BYOVD drivers)             |
|  Technique 08: Driver-based memory read                     |
|  Detection: Driver blocklist, HVCI, PsSetLoadImage          |
|---------------------------------------------------------------|
|                  USERMODE (Ring 3)                           |
|                                                             |
|  Technique 01: Manual mapping                               |
|  Technique 02: Syscall proxying                             |
|  Technique 04: DLL hollowing                                |
|  Technique 05: Thread hijacking                             |
|  Detection: Memory scans, integrity checks, stack walks,    |
|             InstrumentationCallback, ETW                     |
|---------------------------------------------------------------+
```

## Technique Interaction Map

```
                    +--------------+
                    |  Cheat Code   |
                    |--------+-------+
                           |
              +------------+------------+
              |            |            |
         +----v----+  +---v----+  +---v-----+
         | Inject  |  | Read   |  | Execute |
         | Method  |  | Method |  | Method  |
         |------+----+  |-----+----+  |-----+-----+
              |            |            |
    +---------+--+    +---+-----+    +-+----------+
    |         |  |    |   |     |    | |          |
  Manual   DLL  |  Handle Driver  Thread  APC   Instr.
  Map     Hollow|  Elev.  Read   Hijack  Queue  Callback
  (01)    (04)  |  (06)  (08)   (05)
                |
           Syscall Proxy (02) <- protects API calls from hooks
           Hypervisor (03)    <- protects everything from integrity checks
           Timing Evasion (07) <- protects hypervisor from timing detection
```

## Detection Layer Coverage

```
Layer 0 - Hardware
  |--- IOMMU blocks DMA reads
  |--- TPM verifies boot chain integrity
  |--- Secure Boot prevents unsigned bootloaders

Layer 1 - Hypervisor / Firmware
  |--- HVCI blocks unsigned kernel code
  |--- Credential Guard isolates secrets
  |--- AC hypervisor (if deployed) monitors EPT

Layer 2 - Kernel
  |--- ObRegisterCallbacks monitors handle creation
  |--- PsSetLoadImageNotifyRoutine monitors driver loads
  |--- Kernel API hooks (MmCopyVirtualMemory, etc.)
  |--- Handle table auditing

Layer 3 - Usermode
  |--- ntdll hook monitoring
  |--- InstrumentationCallback
  |--- Module integrity checks (on-disk vs in-memory)
  |--- Memory region scanning
  |--- Thread stack walks
  |--- ETW event tracing

Layer 4 - Behavioral
  |--- VACNet / ML-based player behavior analysis
  |--- Statistical anomaly detection
  |--- Canary value monitoring
  |--- Overwatch / Replay review
```
