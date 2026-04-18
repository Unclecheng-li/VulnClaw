# Android UI-Driven Observation And Packet Loop

Use this file when Android runtime progress depends on what is visible in the app, which button or field the operator should touch next, or which UI action is needed to trigger the HTTP/HTTPS request or WebSocket message that will later enter Burp and the pentest workflow.

## Core Rule

This file is a runtime steering layer.

For Android external URL testing, start here before reverse engineering: drive the app, inspect the screenshot, review logs, and check whether HTTP/HTTPS requests or WebSocket messages are already visible.
Only after those checks fail should you fall back to Java recovery, native dump, or runtime hooks.

The runtime sequence stays the same:

`app presence -> packet path ready -> UI action -> screenshot/log check -> packet capture -> replay -> pentest`

## When To Use This File

- the next request trigger is hidden behind login, navigation, wizard steps, dialogs, or feature toggles
- the target request only appears after a visible UI transition
- you need to reason from the current screenshot before deciding the next tap, text input, swipe, or back action
- you need to correlate a specific screen action with one or more packets before replay work starts
- the app is testable, but the operator still needs a disciplined observe-decide-act loop instead of blind random clicking

## Primary MCP Chain

1. `scrcpy_vision`
2. `charles` or `burp`
3. `adb_mcp`
4. `jadx` only when packets are absent, encrypted, or blocked
5. `frida_mcp`
6. `ida_pro_mcp` when dumped `.so` analysis is required

## Observe-Decide-Act Loop

### Step 1: Prepare the runtime view

- list devices and confirm the right `serial`
- confirm the target app package is installed on the device
- make sure packet capture is already ready if the next action may trigger the target request
- wake or unlock the screen if needed
- get the physical screen resolution before any coordinate-based tap or swipe
- start the app or bring it to the target feature

Typical `scrcpy_vision` helpers:

- `android_devices_list`
- `android_apps_list`
- `android_screen_wake`
- `android_screen_unlock`
- `android_shell_exec` with `wm size`
- `android_app_start`
- `android_activity_current`

If the next step will use raw coordinates, first run `android_shell_exec` with `wm size` and record the current resolution.
Do not reuse old coordinates from a different device, orientation, display mode, or screenshot scale.
Do not jump into `jadx`, `frida_mcp`, or `ida_pro_mcp` until you have confirmed the app is present and tried to trigger the target packet from the live UI.

### Step 2: Create a visual checkpoint

Capture the current state before taking the next action:

- use `android_vision_snapshot` for a single screen image
- use `android_ui_dump` when you need `resource-id`, text, class, or bounds
- use `android_ui_findElement` when you already know a likely button, text label, or content description

Do not rely on coordinates alone when the UI can still be described structurally.

### Step 3: Analyze the current screen

From the screenshot and UI tree, answer:

- what page or dialog is currently visible
- which controls are actionable now
- which field probably maps to the target request path
- what blocker is present: login, consent, captcha-like gate, empty form, step gate, cooldown, or missing prerequisite
- what next action is most likely to produce the packet you want

The output of this step should be explicit, for example:

- current screen state
- candidate next actions
- chosen next action
- why this action is the best next probe

Also decide whether the screenshot already suggests an abnormal condition:

- visible error message or warning
- auth failure or forced login
- network timeout, TLS warning, or certificate issue
- blank page, crash dialog, or repeated retry state
- redirect to an unexpected domain or WebView target

### Step 4: Execute the next UI action

Use `scrcpy_vision` to perform the chosen move:

- `android_input_tap`
- `android_input_text`
- `android_input_swipe`
- `android_input_longPress`
- `android_input_keyevent`
- `android_input_dragDrop`

Before sending any coordinate-based action such as `android_input_tap`, `android_input_swipe`, `android_input_longPress`, `android_input_dragDrop`, or `android_input_pinch`, confirm the current screen resolution first.
Prefer `android_ui_findElement` or `android_ui_dump` when possible; only fall back to raw coordinates after resolution has been confirmed.

If the action changes the screen significantly, return to Step 2 and take a new checkpoint before chaining more actions.

### Step 4.5: Review logs before reversing

After important UI transitions, check logs with `adb_mcp`:

- look for crashes, TLS errors, serialization failures, auth errors, WebView warnings, or network stack exceptions
- treat logs as a cheap discriminator before escalating into reverse work
- if logs already explain the failure or blocker, fix the test path first instead of reversing immediately

### Step 4.8: Check network evidence immediately

Before taking more UI actions or escalating into reverse:

- query `charles` or inspect `burp` for the latest HTTP/HTTPS requests or WebSocket messages
- decide whether the expected request already exists in plaintext or replayable form
- if a usable packet already exists, stop UI exploration and move to replay and pentest
- if no packet exists, return to screenshot reasoning instead of defaulting to reverse

### Step 5: Tie UI action to packet capture

After the action:

- query `charles` or inspect `burp` for the latest HTTP/HTTPS requests or WebSocket messages
- decide whether the expected packet appeared
- if it appeared, mark the triggering screen state and exact UI action that produced it
- if it did not appear, go back to screenshot analysis instead of blindly continuing

The goal is to produce a clear mapping:

`screen state -> user action -> observed packet`

### Step 6: Promote the packet into replay analysis

Once the target packet is real:

- inspect it in `charles` or `burp`
- determine host, path, method, headers, cookies, tokens, body shape, and sequencing
- if it is already usable, move directly into replay and security testing
- hand it off to `03-web-security-integrated.md` for API, HTTP/HTTPS, or WebSocket security analysis
- only correlate it with builder or signer logic if encryption, signatures, or replay blockers remain
- use `frida_mcp` only if runtime-only values are still missing

At this point the work leaves UI steering and enters replay and pentest mode. When one business flow has been tested, return to the app and repeat the loop for the next feature instead of defaulting to reverse engineering.
If the packet is already replayable, reverse work is optional and should not delay network-layer testing.

## Escalation Order When Packets Are Blocked

Only escalate beyond UI steering when one of these is true:

- no packet appears in `burp` or `charles`
- a packet appears but the payload is encrypted or unusable
- replay fails because mandatory plaintext values are still hidden

Escalation order:

1. reverse Java first with `jadx`
2. use `frida_mcp` to hook Java or native boundaries when hook-based plaintext recovery is faster than deeper reverse
3. if Java and hooks still do not expose enough, dump the relevant `.so`
4. analyze the dumped `.so` with `ida_pro_mcp`

The goal is not reverse for its own sake. The goal is to make HTTP/HTTPS requests or WebSocket messages visible, plaintext recoverable, or replay stable.

## Handoff To Pentest Workflow

Do not start payload mutation only because you captured a packet once.

First confirm:

- which visible UI action produced the packet
- whether the packet depends on login state, toggles, or prior screens
- whether the packet contains sign, token, nonce, timestamp, device ID, or session values that must be preserved
- whether replay is stable outside the app
- which fields are safe to change without breaking the request

Then branch:

- `03-web-security-integrated.md` for normal API and Web testing
- `04-ai-and-mcp-security-integrated.md` if the packet reaches AI, agent, or MCP-exposed surfaces
- `05-tools-and-operations-integrated.md` when you need the next operator tool family

## Evidence Contract

Keep these artifacts:

- the screen state that mattered
- the chosen next action and why it was selected
- the packet triggered by that action
- the mapping from screen action to request
- any abnormal screenshot or log evidence that justified escalation
- any runtime-only values or hook points needed for replay
- the point where the task switched from UI steering to Burp and pentest analysis

## Anti-Pattern Warnings

- do not start by randomly clicking through the app without checkpoints
- do not trust screenshot reasoning alone when logs or packet evidence can resolve uncertainty
- do not open `jadx` or `ida_pro_mcp` before confirming the target app is installed and trying to trigger the packet from the live app
- do not reverse first when screenshots, logs, and HTTP/HTTPS or WebSocket visibility can already answer the problem
- do not jump into Burp payload testing before the request is reproducible
- do not send coordinate taps or swipes before checking the current resolution, or stale coordinates may drift and hit the wrong place
