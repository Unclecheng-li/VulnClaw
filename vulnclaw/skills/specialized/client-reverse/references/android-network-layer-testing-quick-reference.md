# Android Network-Layer Testing Quick Reference

Use this file when the Android request is already visible or close to visible and you want one short operator card for network-layer testing instead of switching repeatedly between the Android runtime docs and the Web testing docs.

## Core Rule

For an authorized Android app pentest, network-layer testing starts as soon as one real HTTP/HTTPS request or WebSocket message is reproducible outside the app.

Do not keep reversing just because deeper recovery is possible.
If Burp or Charles already has a usable baseline request, switch to server-side testing first and only return to reverse when replay, plaintext, or state recovery stalls.

## Minimal Entry Conditions

Before payload mutation or exploitation work, confirm:

- the target app is installed and the triggering business flow is known
- the triggering UI action is known
- Burp or Charles has captured the real request or message
- the request can be replayed outside the app at least once
- required cookies, headers, tokens, timestamps, nonces, device values, or sequence prerequisites are noted
- you know which fields are safe to change first

If these conditions are not met, go back to:

- `android-authorized-app-pentest-sop.md`
- `android-external-url-runtime-first-workflow.md`
- `android-ui-driven-observation-and-packet-loop.md`
- `02-client-api-reverse-and-burp.md`

## Network-Layer Loop

Use this loop for each business feature:

1. capture one clean baseline request or WebSocket message
2. replay it unchanged in Burp to prove the baseline is stable
3. classify the surface: REST, GraphQL, WebSocket, file upload, auth flow, payment flow, admin/API gateway, or mixed
4. mutate the smallest safe field first
5. compare status code, body, timing, side effects, and server state
6. preserve evidence and note whether the change was accepted, normalized, rejected, or blocked by signer or sequencing logic
7. if the baseline breaks, stop fuzzing and restore replay before continuing

The operating sequence is:

`baseline capture -> stable replay -> small mutation -> compare response and side effect -> expand by bug class`

## What To Test First

### Auth and session

- remove or swap tokens, cookies, device identifiers, and tenant or user identifiers
- replay requests across users, roles, and sessions
- test horizontal and vertical authorization
- test whether old tokens, stale connections, or downgraded roles still work

### Business logic

- change object IDs, amounts, quantities, prices, discounts, coupon state, or workflow steps
- skip prerequisite steps
- replay requests out of order
- repeat the same request to look for race or double-spend style behavior

### Input and injection

- test the request fields that cross trust boundaries into query, render, parse, template, file, or command contexts
- prioritize fields that reach search, filter, sort, rich text, file metadata, XML, or server-side fetch behavior

### Protocol-specific behavior

- for GraphQL, test introspection, field overreach, nested object access, and resolver auth
- for WebSocket, test message auth, room or channel access, stale authorization, and message tampering
- for upload flows, test file type checks, metadata trust, parser reachability, and storage-path exposure

## Safe Mutation Order

Start from the lowest-risk mutations first:

1. duplicate the baseline unchanged
2. remove optional-looking parameters
3. modify one non-crypto business field
4. modify one identity or authorization field
5. modify one sequencing field such as nonce, timestamp, cursor, or step token
6. only then test larger payload families

Do not change many fields at once.
If the request is signed or stateful, multi-field changes hide the real blocker.

## Stop Conditions

Stop network-layer mutation and return to recovery when:

- the baseline request no longer replays consistently
- every mutation fails because a hidden signer, serializer, or state transition is missing
- the payload is still encrypted or opaque
- the response behavior suggests the app is adding unseen runtime values
- WebSocket frames or HTTP bodies are not plaintext enough to reason about safely

Escalation order:

1. Java recovery with `jadx`
2. runtime hook recovery with `frida_mcp`
3. `.so` dump and `ida_pro_mcp` only when Java and hooks still do not answer the blocker

## Best Follow-On References

- `03-web-security-integrated.md` for server-side bug classes and payload families
- `web-modern-protocols.md` for CORS, GraphQL, WebSocket, OAuth/OIDC, and request smuggling
- `web-logic-auth.md` for IDOR, auth bypass, reset flows, payment logic, and workflow abuse
- `web-file-infra.md` for upload, traversal, inclusion, and infrastructure issues

## Evidence To Keep

For each tested feature, keep:

- the screen state and UI action that produced the baseline request
- one clean baseline request or message
- the first successful replay outside the app
- the exact mutated field and observed difference
- whether the issue is auth, logic, injection, protocol, file, or infrastructure related
- whether reverse recovery was needed again and why
