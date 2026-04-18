# Android External URL Runtime-First Workflow

Use this file when you are testing an Android app feature that reaches an external URL or remote API and you do not yet know whether reverse engineering is necessary.

This branch is packet-first and runtime-first, not reverse-first.

## Front Rule For Authorized Android App Pentest

For an authorized Android app pentest, the opening move is not APK analysis.
Before `jadx`, `frida_mcp`, or `ida_pro_mcp`, always do this first:

1. confirm the target app is installed on the connected device
2. get `burp` or `charles` ready so the next request or message is observable
3. open the app with `scrcpy_vision`
4. simulate real business clicks and navigation
5. after each important action, inspect screenshots, logs, and `burp` or `charles`
6. if packets are visible and usable, move directly into `03-web-security-integrated.md`
7. only if traffic is missing, encrypted, opaque, still not replayable, or runtime evidence clearly points to a client-side blocker should reverse work begin

This rule is the default for Android pentest work. Reverse is not the first step unless the task itself is already a known decryption or reverse-only problem.

## Core Rule

Do not start by reversing the interface.

First:

1. confirm the target app is installed on a connected device
2. prepare `burp` or `charles` so the next request or message can be observed
3. drive the app with `scrcpy_vision`
4. inspect the screenshot for visible anomalies
5. review logs with `adb_mcp`
6. check whether `burp` or `charles` already receives HTTP/HTTPS requests or WebSocket messages

Only if packets are encrypted, absent, still opaque, or still unusable for replay should you escalate into reverse engineering.

## When To Use This File

- the goal is to test an Android app's external URL or API behavior
- you are still in black-box or gray-box mode and want to know whether reverse work is necessary
- the request may already be visible once the right screen action is found
- you need a disciplined way to decide when to escalate from runtime observation into Java, native, or hook-based recovery

## Primary MCP Chain

1. `scrcpy_vision`
2. `burp` or `charles`
3. `adb_mcp`
4. `jadx` only when runtime visibility is insufficient
5. `frida_mcp`
6. `ida_pro_mcp` for dumped `.so` analysis

## Runtime-First Loop

### Step 1: Confirm device and app presence

Use `scrcpy_vision` to:

- list connected devices and confirm the right `serial`
- verify the target app package is installed on the device
- confirm whether the app is already foregrounded or needs to be launched

Typical helpers:

- `android_devices_list`
- `android_apps_list`
- `android_activity_current`
- `android_app_start`

Do not jump to `jadx`, `frida_mcp`, or `ida_pro_mcp` before you have confirmed that the target app is actually present and launchable on the test device.

### Step 2: Prepare packet visibility first

Before driving the target feature:

- ensure Burp or Charles is already the active capture path
- confirm proxy and certificate assumptions are in place
- decide whether the next trigger should produce HTTP/HTTPS, WebSocket, or both

Do not start business-flow driving until the next request can actually be observed.

### Step 3: Drive the app to the target feature

Use `scrcpy_vision` to:

- wake or unlock the device
- get the current screen resolution before any coordinate-based action
- start the app
- tap into the target feature
- input text, swipe, or navigate until the external URL should be triggered

Typical helpers:

- `android_devices_list`
- `android_screen_wake`
- `android_screen_unlock`
- `android_shell_exec` with `wm size`
- `android_app_start`
- `android_input_tap`
- `android_input_text`
- `android_input_swipe`

If you are about to use coordinates instead of UI element lookup, first query the current resolution with `android_shell_exec` and `wm size`.
This prevents desktop or app clicks from drifting when device resolution, orientation, scaling, or screenshot size differs from your assumption.

Before triggering the business flow, ensure Burp or Charles is already in a state where the next request can be observed.

### Step 4: Inspect the screenshot before reversing

After each important action, take a visual checkpoint:

- use `android_vision_snapshot`
- use `android_ui_dump` when UI structure matters

Check whether the screenshot already shows something abnormal:

- visible error dialog or warning
- login or permission blocker
- white screen, crash, spinner loop, or timeout
- certificate warning or network error
- redirect to an unexpected page, host, or WebView destination

Do not reverse just because the feature failed once. First determine whether the failure is already explained by the visible state.

### Step 5: Review logs for cheap evidence

Use `adb_mcp` log review after important actions:

- check for TLS failures
- serialization or parsing errors
- auth failures or token expiry
- WebView, okhttp, retrofit, or custom network stack exceptions
- crash traces or JNI load failures

If logs already explain the issue, fix the test path first instead of escalating into reverse work.

### Step 6: Check Burp and Charles

Now decide whether traffic is already visible:

- inspect `burp` history if Burp is the active proxy
- inspect `charles` if Charles is the active capture path
- confirm whether the HTTP/HTTPS request or WebSocket message exists, whether the body or frames are plaintext, and whether replay looks realistic

Three cases:

1. packet is visible and usable
2. packet is visible but encrypted or still opaque
3. packet is missing entirely

### Step 7: Branch by packet visibility

#### Case 1: Packet is visible and usable

- do not reverse first
- move directly into replay and security testing
- use `burp` as the testing baseline
- preserve the screen action that produced the packet
- continue into `03-web-security-integrated.md` to test the HTTP/HTTPS or WebSocket surface
- after finishing one server-side probe set, return to the app and repeat the loop for the next business action if needed

#### Case 2: Packet is visible but encrypted or opaque

- reverse Java first with `jadx`
- locate URL builders, interceptors, signers, encryptors, and serialization logic
- if Java is insufficient, use `frida_mcp` to hook the relevant Java or native boundary and recover plaintext or arguments

#### Case 3: Packet is missing entirely

- re-check screenshot state and logs
- verify proxy and certificate assumptions
- if the app path is correct but traffic is still hidden, reverse Java first
- if Java points into native code or still does not explain the missing traffic, dump the relevant `.so`

## Escalation Order

When runtime-first visibility is not enough, escalate in this order:

1. Java reverse with `jadx`
2. Java or native hook recovery with `frida_mcp`
3. dump the relevant `.so`
4. analyze the dumped `.so` with `ida_pro_mcp`

Native work is a blocker-resolution step, not the default starting point.

## Reverse Objectives

Reverse only until one of these goals is met:

- plaintext request data is recovered
- the HTTP/HTTPS request or WebSocket message becomes visible in `burp` or `charles`
- the encryption or signer boundary is understood well enough for replay
- hook-based decryption or argument capture makes the interface testable

## Handoff To Pentest

Move into pentest only after at least one of these is true:

- Burp or Charles already has a usable baseline request
- Frida hooks recover plaintext inputs or outputs reliably
- Java or native reverse has exposed the exact blocker and replay path

If Burp or Charles already has a usable baseline request, that is the preferred handoff condition.
Do not keep reversing only because static recovery also seems possible.

Then continue into:

- `03-web-security-integrated.md` for API and Web testing
- `04-ai-and-mcp-security-integrated.md` if the target request reaches AI, agent, or MCP surfaces
- `05-tools-and-operations-integrated.md` when you need the next operator tool family

## Evidence Contract

Keep:

- the screen state that triggered the external URL
- screenshot anomalies that influenced the next step
- relevant log anomalies
- whether `burp` or `charles` saw traffic
- the reason reverse escalation was or was not necessary
- Java findings, hook points, or dumped `.so` evidence when escalation happened

## Anti-Patterns

- do not open `jadx` or `ida_pro_mcp` before confirming the target app is installed on the connected device and attempting runtime packet capture
- do not reverse the app before checking screenshot, logs, and HTTP/HTTPS or WebSocket visibility
- do not dump `.so` first when Java or hooks might solve the blocker faster
- do not move into payload testing before the request is reproducible or plaintext is recoverable
- do not send coordinate clicks or swipes before confirming the current screen resolution
