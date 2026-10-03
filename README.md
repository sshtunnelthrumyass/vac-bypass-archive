# VAC Bypass Technique Archive

A structured, documented archive of anti-cheat evasion techniques - historical and current - observed across Valve Anti-Cheat (VAC) protected titles. Each technique is broken down into how it works, why it works (or worked), how it gets detected, and what eventually killed it.

This isn't a cheat development resource. It's an analytical reference for anti-cheat engineers, security researchers, and anyone studying the cat-and-mouse dynamics between game security systems and the people trying to break them.

---

## Why This Exists

Most anti-cheat evasion knowledge lives in fragmented forum posts, deleted threads, and private discords. When a technique gets burned, the details disappear. That's bad for defenders - you can't build good detections for things you don't understand, and you can't learn from history if nobody wrote it down.

This repo tries to fix that. Every technique documented here is either already public knowledge, already detected, or both. Nothing here is novel. The value is in the organization, the analysis, and the detection notes.

## Structure

```
docs/
|---- techniques/          # One file per technique, full breakdown
|   |---- 01-manual-mapping.md
|   |---- 02-syscall-proxying.md
|   |---- 03-hypervisor-hiding.md
|   |---- 04-dll-hollowing.md
|   |---- 05-thread-hijacking.md
|   |---- 06-handle-elevation.md
|   |---- 07-timing-attack-evasion.md
|   |---- 08-driver-based-read.md
|---- detection/           # Detection strategies and signature patterns
|   |---- detection-matrix.md
|   |---- heuristic-models.md
samples/                 # Minimal proof-of-concept code (research only)
diagrams/                # Architecture and flow diagrams
```

## Technique Status Overview

| # | Technique | Era | Status | Detection Difficulty |
|---|-----------|-----|--------|---------------------|
| 01 | Manual Mapping | 2014-present | Partially detected | Medium |
| 02 | Syscall Proxying | 2018-present | Active cat-and-mouse | High |
| 03 | Hypervisor-Based Hiding | 2019-present | Mostly undetected at user level | Very High |
| 04 | DLL Hollowing | 2016-2021 | Largely burned | Low |
| 05 | Thread Hijacking | 2015-present | Detected via stack walks | Medium |
| 06 | Handle Elevation | 2017-present | Kernel callbacks catch most | Medium |
| 07 | Timing Attack Evasion | 2020-present | Niche, hard to generalize | High |
| 08 | Driver-Based Read | 2016-present | Arms race with kernel AC | High |

## Each Technique Doc Covers

- **Mechanism** - what it actually does at the OS/memory level
- **Implementation sketch** - pseudocode or minimal C++ showing the core logic
- **Why it works** - what assumption in the AC it exploits
- **Detection surface** - what artifacts it leaves, what an AC can look for
- **Historical timeline** - when it appeared, when it got caught, what mutated
- **Known variants** - forks and evolutions of the base technique
- **References** - forum posts, papers, talks, repos where this was discussed publicly

## Ground Rules

1. Everything here is already public. If you've been in UC, GH, or any RE community for more than a year, you've seen all of this before. The contribution is structure, not novelty.

2. No working loaders, injectors, or cheat binaries. Samples are minimal, illustrative, and incomplete by design. They demonstrate a concept, not a product.

3. Detection is the point. Every technique file spends as much time on "how do you catch this" as "how does this work." If you're here to build cheats, you're reading the wrong repo.

4. PRs welcome if you've got corrections, better detection strategies, or historical context I missed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Intended Audience

- Anti-cheat engineers studying evasion patterns
- Security researchers working on userland/kernel integrity
- Game security teams building detection heuristics
- Students learning about OS internals through adversarial examples

## Disclaimer

This repository documents publicly known techniques for educational and defensive research purposes. The author does not condone cheating in online games. All documented techniques target the understanding of anti-cheat evasion for the purpose of building better detections.

## License

MIT - see [LICENSE](LICENSE).
