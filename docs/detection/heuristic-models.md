# Heuristic Detection Models

When direct technical detection fails - and against advanced techniques, it often does - behavioral and statistical heuristics become the primary detection layer. This document outlines heuristic approaches that don't target specific bypass techniques but instead detect the *effects* of cheating.

## 1. Memory Access Pattern Analysis

### Concept

A cheat that reads game memory (player positions, health, entity lists) produces a characteristic access pattern: frequent, periodic reads to specific offsets within game structures. Even if the read mechanism is invisible (driver, DMA), the *knowledge* the cheat gains is observable.

### Implementation Approach

The anti-cheat places canary values in game structures - dummy fields that no legitimate game code reads. If a process demonstrates knowledge of these fields (by reacting to changes), it has unauthorized memory access.

```
Canary deployment:
  Entity struct offset 0x340 -> unused field, populated with random nonce
  Anti-cheat changes nonce every N ticks
  If an external tool's behavior correlates with nonce changes -> detection
```

### Limitations

Only works for read-and-react cheats (ESP, aimbot). Doesn't catch passive recording or offline analysis.

## 2. Thread Scheduling Anomaly Detection

### Concept

Cheats that hijack threads, inject APCs, or use instrumentation callbacks alter the scheduling and execution patterns of game threads. A thread that briefly executes in unexpected memory, or a thread whose scheduling pattern shows periodic interruptions consistent with hook execution, stands out.

### Implementation Approach

Sample thread instruction pointers and call stacks at random intervals (via kernel timer DPCs or NMI-based profiling). Build a baseline model of where each thread normally executes. Flag deviations.

```
Expected: GameThread-3 executes in game.exe .text 99.7% of samples
Observed: GameThread-3 executes in 0x1A000000 (unbacked) for 0.3% of samples
Signal:   anomalous thread execution location
```

### Limitations

Timing-dependent. Fast cheats that execute and restore within microseconds may dodge sampling.

## 3. Handle Table Integrity Monitoring

### Concept

Periodically audit the system handle table for handles to the game process. Every handle holder should be either a system process or an AC-whitelisted process. Unknown holders are suspicious.

### Implementation Approach

From the AC kernel driver:

1. Call `ZwQuerySystemInformation(SystemHandleInformation)` to enumerate all handles system-wide
2. Filter for handles to the game's EPROCESS
3. Cross-reference each holder PID against a whitelist
4. Flag unknown holders, especially those with `PROCESS_VM_READ` or `PROCESS_VM_WRITE`

### Limitations

Handle elevation variants (duplication, inheritance) create handles that appear to come from legitimate processes. Physical memory access bypasses handles entirely.

## 4. Driver Stack Verification

### Concept

Audit all loaded kernel drivers against a known-good list. Any driver that isn't part of the OS, the anti-cheat, or the hardware vendor's driver package is suspicious.

### Implementation Approach

1. Enumerate drivers via `ZwQuerySystemInformation(SystemModuleInformation)`
2. Hash each driver's image
3. Compare against a whitelist (signed drivers with known certificates)
4. Flag unknown or blocklisted drivers
5. Also scan for manually mapped kernel modules (executable memory in kernel space not associated with any loaded module)

### Limitations

Manually mapped drivers don't appear in the module list. EFI-loaded modules may also evade enumeration. BYOVD drivers are signed and appear legitimate until specifically blocklisted.

## 5. Cross-Process Communication Detection

### Concept

External cheats must communicate with their usermode component. This communication - via IOCTLs, shared sections, named pipes, or sockets - creates observable IPC patterns.

### Implementation Approach

Monitor for:
- New device objects being created by recently loaded drivers
- Shared memory sections mapped into both the cheat process and the game (or a driver)
- Unusual IOCTL patterns to non-standard devices
- Local socket connections with high-frequency small payloads (characteristic of a memory read service)

### Limitations

Communication can be hidden through unconventional channels (CPU MSRs, shared physical pages, network loopback through VPN tunnels). Sophisticated cheats minimize and obfuscate IPC.

## 6. Combining Signals: Scoring Model

No single heuristic is reliable alone. A scoring model combines weak signals into a strong detection:

```
Score = 0

IF unbacked executable memory in game process        -> +30
IF unknown handle holder with VM access               -> +25  
IF recently loaded unknown driver                     -> +20
IF thread execution anomaly detected                  -> +20
IF canary field access correlation                    -> +40
IF process created from temp/download directory       -> +10
IF unsigned binary interacting with game              -> +15
IF timing anomaly on critical functions               -> +15

IF score >= 70 -> flag for review
IF score >= 90 -> high-confidence detection
```

The threshold should be tuned against false positive rates. Legitimate software (OBS, Discord overlay, debugging tools) can trigger some individual signals.

## 7. Machine Learning Approaches

### Player Behavior Analysis (VACNet model)

Instead of detecting the cheat software, detect cheating behavior:

- Aim patterns (angle snap, inhuman reaction time, target acquisition curves)
- Information usage (pre-aiming through walls, tracking non-visible players)
- Movement patterns (inhuman movement prediction, perfect counter-strafing)
- Statistical anomalies over many games (win rate, K/D variance, headshot percentage)

This is the direction VAC moved with VACNet, and it's architecturally the strongest approach because it detects the *output* of cheating regardless of the *mechanism*.

### Limitations

- Requires large datasets and careful model training
- False positives on legitimate skilled players
- Subtle cheats (low-FOV aimbot, info-only ESP) produce weak behavioral signals
- Latency - behavioral detection works over many games, not per-match
