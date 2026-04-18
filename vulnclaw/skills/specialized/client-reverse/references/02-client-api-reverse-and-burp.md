# 02 Client API Reverse And Burp Workflow

This integrated file merges the client-side reverse workflow, MCP execution order, tool-selection rules, and evidence expectations needed to move from opaque client traffic to reproducible Burp replay.

## Use This File When

- Burp cannot directly replay the request
- the client computes `sign`, `token`, `nonce`, `timestamp`, encrypted body, or device-bound fields
- the request sequence is stateful or tied to runtime values
- you need a reliable workflow from runtime packet capture to blocker-driven reverse recovery to replay

## Core Objective

Recover the full request-production recipe:

- where the request is assembled
- where crypto or signing is applied
- which runtime values are mandatory
- which state transitions must happen before replay

The first priority is not reverse for its own sake. The first priority is to capture the real HTTP/HTTPS request or WebSocket message that the client emits, confirm whether it is already usable, and only then reverse the missing blocker.

## Front Rule For Authorized Android App Pentest

When the task is to pentest an authorized Android app, do not start with `jadx`, `ida_pro_mcp`, or APK-first reverse analysis.
Start in this order instead:

1. confirm the target app is actually installed on the connected Android device
2. get `burp` or `charles` ready before driving the feature
3. use `scrcpy_vision` to open the app and drive real business features
4. after each important action, inspect `burp` or `charles` for HTTP/HTTPS requests or WebSocket messages
5. if packets are already visible and usable, move directly into `03-web-security-integrated.md` and test the server-side surface
6. repeat the UI action -> packet capture -> Web security analysis loop for the next business feature
7. escalate into `jadx`, `frida_mcp`, or `ida_pro_mcp` only when packets are absent, encrypted, opaque, still not replayable, or when runtime anomalies clearly point to a client-side blocker

For this Android pentest path, reverse engineering is a blocker-resolution step, not the default entrypoint.

## Recommended Read Path

1. Read `Goal`, `Stages`, and the platform-specific section for Android, desktop, or browser JS.
2. Read `Priority` and `Primary Chains` to choose the smallest MCP chain.
3. If the target is browser JS, continue into `browser-js-signing-workflow.md`.
4. If the target is Android external URL testing, continue into `android-external-url-runtime-first-workflow.md`.
5. If the target is Android reverse or crypto recovery, continue into `android-signing-and-crypto-workflow.md`.
6. If Android runtime progress depends on app UI state, continue into `android-ui-driven-observation-and-packet-loop.md`.
7. Read `Rule` and `reporting-and-evidence.md` content before switching to Burp.
8. After replay is stable, move into `03-web-security-integrated.md` or `04-ai-and-mcp-security-integrated.md`.

## Replay Readiness Checklist

- you can name the builder, signer, or serializer location
- you know which cookies, headers, tokens, timestamps, or device values are required
- you know whether request ordering matters
- you have one working replay outside the client
- you know which fields are safe to mutate during later testing

## Platform Branch Rules

### Browser JS

- decide the stage from engineering state, not from clue words alone
- stay in `locate` until the request, sink, and upstream dependency chain are real
- only enter `recover` after the boundary is proven
- only enter `runtime` when the boundary is clear but browser and local execution diverge
- only enter `validation` when the remaining work is checkpoint proof

Detailed branch file: `references/browser-js-signing-workflow.md`
Stage references: `references/browser-locate-and-request-chain.md`, `references/browser-recover-and-shell-reduction.md`, `references/browser-runtime-fit-and-risk.md`, `references/browser-validation-and-handoff.md`
Record template: `references/browser-request-chain-template.md`

### Android

- for external URL testing, start with live app interaction and packet visibility, not reverse engineering
- first confirm the target app is installed on a connected device and can actually be launched
- use `scrcpy_vision` to navigate, inspect screenshots, and decide the next action
- check `burp` or `charles` for HTTP/HTTPS requests or WebSocket messages after each important action
- use `adb_mcp` to review logs after important actions
- once packets are visible and replayable, move directly into `03-web-security-integrated.md` and keep the UI-action to packet to Web-analysis loop going for the next business feature
- reverse Java only when packets are absent, encrypted, still opaque, or otherwise blocked
- escalate into JNI or `.so` work only when Java stops exposing the required inputs or outputs
- use `frida_mcp` when hook-based plaintext recovery is faster than reimplementation

Detailed branch files: `references/android-external-url-runtime-first-workflow.md`, `references/android-signing-and-crypto-workflow.md`
Phase references: `references/android-static-triage-and-callflow.md`, `references/android-dynamic-hooking-and-replay.md`, `references/android-ui-driven-observation-and-packet-loop.md`, `references/android-native-signature-analysis.md`
Record template: `references/android-signature-reverse-template.md`

## Included Sources

- references/client-reverse-workflow.md
- references/mcp-first-methodology.md
- references/tool-selection-map.md
- references/reporting-and-evidence.md

---

## Source: client-reverse-workflow.md

Path: references/client-reverse-workflow.md

# Complex Client Reverse Workflow

## Goal

Recover the real request-production chain so the interface can be reproduced outside the client.

## Stages

1. classify the client
2. choose the smallest platform branch that can prove the request chain
3. for Android app pentests, confirm app presence on the device and try runtime packet capture before any reverse step
4. dynamically confirm signer, serializer, and state values only when runtime packet proof is no longer enough
5. statically recover the missing blocker only after runtime visibility, plaintext, or replay stalls
6. rebuild the request recipe
7. replay in Burp
8. move into Web or AI attack testing only after replay is stable

## Android

- start by confirming the target app exists on the connected device, then use `scrcpy_vision`, logs, and proxy visibility for external URL testing
- move to `jadx` only when packets are missing, encrypted, or blocked
- reverse Java before native
- use `frida_mcp` when runtime hook proof or plaintext recovery is faster than deeper reverse
- dump and analyze `.so` only after Java has stopped answering the blocker
- move to `burp`, then into Web security analysis once replay is stable

## Native desktop

- locate files with `everything_search`
- reverse code with `ida_pro_mcp`
- capture runtime values with `frida_mcp`
- move to `burp`

## Browser JS

- inspect live requests with `chrome_devtools`
- choose the current stage from `locate`, `recover`, `runtime`, or `validation`
- trace initiators and signer functions with `js_reverse`
- replay with `burp`

## Android sign and crypto

- enter this branch only after runtime-first packet checks prove reverse is required, or when the task is already an explicit Android sign or crypto reverse problem
- decompile and triage in `jadx`
- trace request flow from manifest and entry components
- locate request builder, interceptor, signer, encryptor, and JNI handoff
- confirm final on-wire values with `frida_mcp` or `charles` only after static triage narrows the target
- replay with `burp`

## Android external URL runtime-first

- drive the app with `scrcpy_vision`
- inspect screenshots for visible anomalies and state changes
- review logs with `adb_mcp`
- verify whether `burp` or `charles` sees traffic
- only then decide whether Java reverse, Frida hooks, or dumped `.so` analysis is necessary

## Detailed Branches

- browser JS staged flow: `browser-js-signing-workflow.md`
- Android external URL runtime-first flow: `android-external-url-runtime-first-workflow.md`
- Android sign and crypto flow: `android-signing-and-crypto-workflow.md`

For staged browser work, continue into `references/browser-js-signing-workflow.md`.
For Android external URL testing, continue into `references/android-external-url-runtime-first-workflow.md`.
For Android blocker recovery or explicit sign and crypto reverse work, continue into `references/android-signing-and-crypto-workflow.md`.


---

## Source: mcp-first-methodology.md

Path: references/mcp-first-methodology.md

# MCP-First Methodology

This file is a navigation aid. The full methodology lives in `references/methodology/MCP.md`.

## Priority

1. Read the raw `MCP.md`
2. Select the minimal MCP chain for the target
3. Capture the real HTTP/HTTPS request or WebSocket message before deeper reverse
4. Restore the request lifecycle before Burp replay

## Primary Chains

### Android

- `scrcpy_vision`
- `burp`
- `charles`
- `adb_mcp`
- `jadx` only when packets are blocked
- `frida_mcp`
- `ida_pro_mcp`

### Native or packed desktop

- `everything_search`
- `ida_pro_mcp`
- `frida_mcp`
- `burp`

### Browser JS reverse

- `chrome_devtools`
- `js_reverse`
- `burp`


---

## Source: tool-selection-map.md

Path: references/tool-selection-map.md

# Tool Selection Map

## Reverse Layer

- `jadx`
- `ida_pro_mcp`
- `frida_mcp`
- `scrcpy_vision`
- `adb_mcp`
- `charles`
- `js_reverse`
- `chrome_devtools`
- `burp`

## Support Layer

- `everything_search`
- `context7`
- `fetch`
- `memory`
- `sequential_thinking`

## Platform Sequences

### Browser JS sign or anti-bot

- boundary and request proof: `chrome_devtools` -> `js_reverse`
- browser/local divergence: `js_reverse`
- replay confirmation: `burp`

### Android sign or encrypt

- runtime-first app-presence check and packet check: `scrcpy_vision` -> `adb_mcp` -> `charles` / `burp`
- Java recovery when blocked: `jadx`
- UI-state steering and screenshot-guided next actions: `scrcpy_vision`
- device state and runtime context: `adb_mcp`
- narrow Java or JNI hooks: `frida_mcp`
- dumped `.so` analysis when required: `ida_pro_mcp`
- wire validation or Charles-assisted observation: `charles`
- replay confirmation: `burp`

## Rule

Do not start in reverse when the relevant HTTP/HTTPS request or WebSocket message has not even been checked in Burp or Charles.
For Android app pentests, first confirm the target app is installed on the connected device before deeper workflow branching.
For Android external URL testing, do not reverse first when screenshot, logs, and packet visibility can answer the question.
Do not choose browser references by clue words before the current stage is known.


---

## Source: reporting-and-evidence.md

Path: references/reporting-and-evidence.md

# Reporting And Evidence

Minimum output:

- scope and client type
- chosen MCP chain
- static findings
- runtime proof
- recovered request recipe
- Burp-ready baseline request
- security finding and mitigation



