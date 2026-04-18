# Android Dynamic Hooking And Replay

Use this file only after Android static triage has narrowed the request path, or after the runtime-first Android external URL workflow has proven that screenshots, logs, and packet checks are not enough.
Do not enter this branch while Burp or Charles already has a usable replay baseline.

## Hook Order

Prefer these points in order:

1. final request object construction
2. interceptor methods
3. request execution entrypoint
4. sign or token generator
5. native boundary

## Capture For Each Hook

- class and method
- URL
- HTTP method
- headers
- body or serialized payload
- sign input tuple
- sign output or encrypted result

## Escalation Rules

- use `scrcpy_vision` when the next runtime hook or packet trigger depends on navigating app UI, entering data, or confirming the visible screen state
- use `adb_mcp` log review before deeper reverse if a runtime exception may explain the blocker
- use Frida to confirm or bridge static gaps
- keep proxy capture active throughout dynamic work so every hook result can be compared to live HTTP/HTTPS or WebSocket traffic
- treat SSL pinning bypass as a support step, not the first step

## UI-Driven Runtime Loop

When the app path is not obvious from static code alone:

1. use `scrcpy_vision` to tap, input, scroll, or navigate toward the suspected trigger
2. capture a screenshot or UI tree after each important transition
3. analyze the current state and decide the next test action before acting again
4. keep packet capture ready so the UI trigger can be tied to one or more concrete requests
5. only then place hooks or move to replay if the relevant packet and runtime values are real
6. if packets are still encrypted or absent, reverse Java first and escalate to native only when Java no longer answers the blocker

Detailed reference: `references/android-ui-driven-observation-and-packet-loop.md`

## Replay Goal

Dynamic work is complete when you can produce:

- a stable replay recipe
- the mandatory runtime inputs
- a clear answer about which fields are safe to mutate in Burp

If a stable replay recipe already exists from captured traffic alone, skip this file and move straight into network-layer testing.
