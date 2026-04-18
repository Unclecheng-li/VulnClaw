# Browser Runtime Fit And Risk

Use this file when the browser boundary and shell are already clear but browser execution and local or controlled execution diverge.

## Diagnose Before Patching

Classify the first meaningful divergence as one or more of:

- missing object
- missing state
- anti-debugging
- unstable source
- risk branch

## First-Divergence Table

Always compare browser normal state and local execution using a concrete checkpoint table before adding patches.

Minimum comparison rows:

- input parameters
- cookie and storage state
- fixed time and randomness
- first stable intermediate value
- first abnormal intermediate value
- final branch or response

## Risk And Anti-Debug Refinement

When debugging changes behavior or a risk branch is suspected, answer:

- where the fork begins
- whether the issue is debug friction or a real consumer-driven risk branch
- which exact missing state or fingerprint surface triggers the split

Keep the anti-debug handling minimal. Remove only the smallest obstacle needed to keep observation going.

## Environment Fit Rules

- keep `required objects` and `required state` separate
- record why each dependency is necessary
- fix time, randomness, and seed sources before further comparison
- do not claim pure computation while upstream response, `HttpOnly` state, challenge flow, or browser lifecycle state remain open

## Completion Standard

Stop runtime when:

- the divergence class is explicit
- the first divergent checkpoint is known
- missing object and missing state are not mixed
- the next action is clearly patch, state restore, or validation
