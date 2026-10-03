# Contributing

PRs welcome, especially corrections, better detection strategies, and historical context.

## What helps

- Corrections - if a technique description is wrong or outdated, fix it
- Detection improvements - better ways to catch something, new artifacts to look for
- Historical context - "this actually first appeared in X forum in Y year" type stuff
- New techniques - if it's already public and documented elsewhere, it belongs here
- Variant documentation - mutations of existing techniques that behave differently enough to matter

## What doesn't

- Working cheat code, loaders, or injectors
- Links to active cheat providers or sales channels
- Anything that isn't already public knowledge
- Speculation without evidence

## Format

Follow the existing technique doc structure. Each one needs:

1. One-paragraph summary
2. Mechanism (OS-level explanation)
3. Implementation sketch (pseudocode or minimal C++)
4. Detection surface
5. Historical timeline
6. Known variants
7. References

Keep it technical. No filler. Say what it does, how it works, how you catch it.

## Process

1. Fork
2. Branch (`technique/your-technique-name` or `fix/what-you-fixed`)
3. Write
4. PR with a one-line description of what changed and why
