# VAC Bypass Technique Archive

Documented archive of anti-cheat evasion techniques observed across VAC-protected titles. Covers how each technique works, why it works (or worked), how it gets caught, and what killed it.

Not a cheat dev resource. This is an analytical reference for people working on the detection side, or anyone studying how game security and evasion interact.

---

## Why this exists

Most of this knowledge lives in fragmented forum posts, deleted threads, and private discords. When a technique gets burned, the write-ups vanish. That's a problem if you're trying to build detections for something you don't fully understand, or trying to learn from patterns that already played out.

Everything documented here is already public knowledge, already detected, or both. Nothing is novel. The point is putting it all in one place with structure and detection analysis attached.

## Repo layout

```
docs/
  techniques/           # one file per technique, full breakdown
    01-manual-mapping.md
    02-syscall-proxying.md
    03-hypervisor-hiding.md
    04-dll-hollowing.md
    05-thread-hijacking.md
    06-handle-elevation.md
    07-timing-attack-evasion.md
    08-driver-based-read.md
  detection/            # detection strategies and signature patterns
    detection-matrix.md
    heuristic-models.md
samples/                # minimal PoC code (defensive/research only)
diagrams/               # architecture and flow diagrams
```

## Technique overview

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

## What each doc covers

Each technique file walks through:

- Mechanism - what it does at the OS/memory level
- Implementation sketch - pseudocode or minimal C++ showing the core idea
- Why it works - what assumption in the AC it exploits
- Detection surface - artifacts it leaves, what an AC can scan for
- Historical timeline - when it showed up, when it got caught, how it evolved
- Known variants - forks and mutations of the base technique
- References - forum posts, papers, talks, repos where this got discussed

## Ground rules

1. Everything here is already public. If you've spent time on UC, GH, or any RE community, you've seen all of this. The point is structure, not novelty.

2. No working loaders, injectors, or cheat binaries. Samples are minimal and incomplete on purpose. They show a concept, not a product.

3. Detection is the point. Every technique doc spends just as much time on "how do you catch this" as "how does this work." If you're here to build cheats, wrong repo.

4. PRs welcome for corrections, better detection strategies, or historical context I missed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Who this is for

- Anti-cheat engineers studying evasion patterns
- Security researchers working on userland/kernel integrity
- Game security teams building detection heuristics
- Students learning OS internals through adversarial examples

## Disclaimer

Documents publicly known techniques for educational and defensive research. The author does not condone cheating in online games. All techniques are documented for the purpose of building better detections.

