# Browser Recover And Shell Reduction

Use this file only after the browser request boundary is already real and the next blocker is shell opacity.

## Owns

- choosing the smallest layer to open
- deciding whether the task needs semantic explanation, key-operator extraction, or a minimal rebuild
- preserving black-box reuse when deeper deobfuscation is unnecessary

## First Layer Selection

| Symptom | First layer to open |
| --- | --- |
| callable path still hidden | outer container |
| large dispatcher or VM flow | dispatcher layer |
| parameters visible but state carrier opaque | state carrier |
| logic appears after `worker` or `wasm` bridge | bridge layer |
| write-back point known but algorithm opaque | core operator |

## Recovery Levels

### Level A

Recover only the critical operator or helper needed to explain the target field.

### Level B

Recover dispatcher flow plus critical state carriers when operator meaning depends on state flow.

### Level C

Build the smallest verifiable fragment or interpreter only when levels A and B cannot support the next stage.

## Prefer Black-Box Reuse When

- input and output boundaries are already known
- the target module or bridge entry is found
- the blocker is container logic, not business logic

## Escalate Deeper When

- replay is unstable because of hidden shared state
- the bridge contract itself is opaque
- the module contains another VM or protocol shell that still blocks progress

## Completion Standard

Stop recover when the current reduction depth is already enough for runtime fit or validation.
