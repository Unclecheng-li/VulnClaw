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

## Platform Sequences

### Browser JS sign or anti-bot

- boundary and request proof: `chrome_devtools` -> `js_reverse`
- browser/local divergence: `js_reverse`
- replay confirmation: `burp`

### Android external URL or sign/encrypt

- proxy or capture readiness first: `burp` / `charles`
- runtime-first visibility and packet check: `scrcpy_vision` -> `adb_mcp`
- Java recovery when blocked: `jadx`
- UI-state steering and screenshot-guided next actions: `scrcpy_vision`
- device state and runtime context: `adb_mcp`
- narrow Java or JNI hooks: `frida_mcp`
- dumped `.so` analysis when required: `ida_pro_mcp`
- wire validation or Charles-assisted observation: `charles`
- replay confirmation: `burp`

## Support Layer

- `everything_search`
- `context7`
- `fetch`
- `memory`
- `sequential_thinking`

## Rule

Do not start payload testing in Burp when the request is still opaque.
For Android external URL testing, do not reverse first when screenshots, logs, and packet visibility can answer the problem.
Do not choose browser references by clue words before the current stage is known.
