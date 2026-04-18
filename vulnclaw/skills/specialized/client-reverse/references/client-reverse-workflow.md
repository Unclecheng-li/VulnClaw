# Complex Client Reverse Workflow

## Goal

Recover the real request-production chain so the interface can be reproduced outside the client.

## Stages

1. classify the client
2. choose the smallest platform branch that can prove the request chain
3. statically find request and crypto code
4. dynamically confirm signer, serializer, and state values only when static proof is no longer enough
5. rebuild the request recipe
6. replay in Burp
7. move into Web or AI attack testing only after replay is stable

## Android

- start in `jadx`
- finish manifest, package, network stack, request-builder, signer, and JNI triage first
- use `scrcpy_vision` to steer UI-dependent runtime paths when the next packet depends on what is visible on screen
- verify on-wire behavior with `adb_mcp` and `charles`
- hook signer or builder with `frida_mcp` only after the static target is narrow enough
- move to `burp`

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

## Detailed Branches

- browser JS staged flow: `browser-js-signing-workflow.md`
- Android sign and crypto flow: `android-signing-and-crypto-workflow.md`
- Android UI-driven packet trigger flow: `android-ui-driven-observation-and-packet-loop.md`
