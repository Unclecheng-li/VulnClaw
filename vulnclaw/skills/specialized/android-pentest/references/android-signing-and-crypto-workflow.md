# Android Signing And Crypto Workflow

Use this file when the target request is produced in an Android app and the main task is to recover sign, token, encrypt, decrypt, JNI, or request-sequencing logic so the request can be explained or replayed outside the APK.
This is not the default entrypoint for a general authorized Android app pentest.

## Core Rule

Do not jump straight into Frida or `.so` reversing.

If the task is a general authorized Android app pentest and you do not yet know whether reverse is required, do not start here.
First confirm the app is installed on the connected device, prepare Burp or Charles, use `scrcpy_vision` to drive real business features, and check after each important action whether HTTP/HTTPS requests or WebSocket messages are already visible and usable.
Start from `references/android-authorized-app-pentest-sop.md` or `references/android-external-url-runtime-first-workflow.md`, and only return here after screenshot review, logs, and packet visibility checks show that reverse is necessary.

Start with static triage in `jadx` and answer:

- which network stack is in use
- where the request is built
- where headers, body, and sign fields are written
- whether the sign or crypto path is visible in Java or handed to JNI

Use runtime work only after static evidence narrows the target.
If live traffic is already visible and replayable, prioritize network-layer testing first and use this file only to resolve the remaining signer, crypto, or sequencing blocker.

## Intake Contract

Start from this block:

```text
APK / package / target feature:
Target request / field / API path:
Trigger action:
Current symptom:
Known evidence:
Goal:
Constraints:
```

Then decide:

- is the task static triage, runtime confirmation, JNI analysis, or replay proof
- is the target request already captured or still inferred
- is the app using Java-only logic, mixed Java/JNI logic, or mostly native logic

## Static-First Workflow

### Phase 1: Entry and architecture

Read:

- `AndroidManifest.xml`
- application class
- launcher activity or target component
- package structure around `api`, `network`, `data`, `repository`, `service`, `retrofit`, `http`

Goal:

- locate entry components
- identify the app package
- identify the likely network stack and dependency injection setup

Detailed reference: `references/android-static-triage-and-callflow.md`

### Phase 2: Request-chain and call-flow proof

Trace:

```text
Activity / Fragment / Service
-> ViewModel / Presenter / UseCase
-> Repository / DataSource
-> ApiService / RequestBuilder / Interceptor
-> Signer / Encryptor / Serializer
```

Use strings, Retrofit annotations, interceptor classes, request builders, and constants as anchors.

Prove:

- request method and path
- header and body writers
- request ordering or preflight dependencies
- the exact class or method where sign inputs come together

### Phase 3: Sign and crypto locator

Search for:

- `sign`, `token`, `encrypt`, `decrypt`, `cipher`, `aes`, `rsa`, `hmac`, `md5`, `sha`
- `Interceptor`, `intercept`, `addInterceptor`
- `native`, `System.loadLibrary`, `System.load`
- hardcoded URLs, header names, key names, and device identifiers

Classify the current sign path:

- Java-only
- Java wrapper around native
- native-first
- still unknown

### Phase 4: JNI handoff triage

If Java calls native code, prove:

- which Java method declares `native`
- which library is loaded
- whether the native function is statically exported or dynamically registered
- which parameters are passed into the native boundary
- which return value comes back into the request chain

Do not start deep native reversing until the Java-side boundary is already concrete.

Detailed reference: `references/android-native-signature-analysis.md`

### Phase 5: UI-driven trigger proof

If the request depends on what screen the app is showing or which gesture submits the data, use `scrcpy_vision` after static triage has already narrowed the target.

Run this loop:

1. navigate or tap toward the suspected trigger
2. capture a screenshot or UI tree
3. analyze what screen is visible now, which controls matter, and which next action is most likely to expose the target request
4. perform the next input, tap, swipe, or back action
5. watch for the packet or state transition that proves the request path

Do not treat screenshot reasoning as a replacement for static proof. It is a runtime steering layer that helps you reach the right trigger and connect visible UI state to the request chain.

Detailed reference: `references/android-ui-driven-observation-and-packet-loop.md`

## Dynamic Escalation Rules

Escalate only when static proof is no longer enough.

### Prefer these hook points in order

1. final request object construction
2. interceptor methods
3. request execution entrypoint
4. sign or token generator
5. native boundary

For each hook, capture:

- class and method
- URL
- headers
- body or serialized payload
- sign input tuple
- sign output or encrypted result

### SSL pinning and packet capture

Treat SSL pinning bypass as a support step, not the first move.
Treat Burp or Charles as the runtime baseline that stays active so recovered signer behavior can be compared to real traffic.

Use them when:

- Java hooks still do not expose final request values
- the custom transport hides fields until after TLS setup
- you need to verify that replay matches runtime traffic

Detailed reference: `references/android-dynamic-hooking-and-replay.md`

## Native and Signature Decisions

Only escalate past Java and JNI boundary proof when the user needs:

- offline reproduction
- deeper algorithm recovery
- unidbg-based execution
- `.so` patching or native control-flow analysis

Before that, answer these questions:

- is the signature generated in Java or native code
- what exact inputs feed the signature
- which inputs are constants versus runtime values
- can replay call the app or hook the boundary instead of reimplementing the algorithm

## Android Tool Order

1. `burp` or `charles`
2. `jadx`
3. `adb_mcp`
4. `frida_mcp`
5. `ida_pro_mcp` when dumped `.so` analysis is required

The order may compress, but the logic stays the same: network visibility first, static proof second, runtime recovery third, deeper native analysis last.

## Replay Exit Criteria

Do not move into Burp mutation work until you can explain:

- where the request is built
- where sign or encryption is applied
- which runtime inputs are mandatory
- whether device identity, timestamp, nonce, token, or sequence must be preserved
- whether replay can call the app, reuse a hook point, or must reimplement the logic

If Burp or Charles already has a stable replay baseline and the remaining blocker is narrow, resolve only that blocker instead of expanding reverse scope.

## Output Contract

Deliver:

- app architecture summary
- call-flow map from entry component to request execution
- request-builder and signer location
- Java versus JNI conclusion
- runtime hook point and observed values when runtime work was needed
- Burp-ready replay recipe or the exact remaining blocker

Record template: `references/android-signature-reverse-template.md`

## Recommended Read Order Inside This Branch

1. `android-static-triage-and-callflow.md`
2. `android-dynamic-hooking-and-replay.md` only when static proof is not enough
3. `android-native-signature-analysis.md` when JNI or `.so` becomes part of the real sign path
4. `android-signature-reverse-template.md` when you need a persistent record or replay handoff
