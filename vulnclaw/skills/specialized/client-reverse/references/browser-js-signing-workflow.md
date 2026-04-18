# Browser JS Signing Workflow

Use this file when the target request is produced in the browser and the current blocker is sign generation, token flow, cookie hops, worker or wasm indirection, anti-bot logic, or browser versus local divergence.

## Mission

Keep browser JS reverse on a staged spine:

`intake -> evidence -> locate -> recover -> runtime -> validation -> replay`

Do not pick the next step from clue words alone. Pick it from engineering state.

## Intake Contract

Start from this block:

```text
URL or target page:
Target request / field / cookie / message:
Trigger action:
Current symptom:
Known evidence:
Goal:
Constraints:
```

Then answer:

- is the target request real or still guessed
- is the write boundary proven, partial, or unknown
- is the blocker shell reduction, runtime divergence, or checkpoint proof
- what artifact must be updated next

## Evidence Rule

Do not enter stage work if the real request chain is still guessed. First capture a real sample and prove:

- the target request or message
- the trigger action
- the first dependent upstream request or response when state is involved
- whether the current sample is normal state, risk state, or still mixed

Keep a persistent request-chain record. At minimum, preserve:

- request sample
- sink or write boundary
- upstream hops
- runtime notes
- replay prerequisites

## Stage Selection

### `locate`

Enter when the request, sink, write boundary, or upstream dependency chain is still unproven.

Own these questions:

- where the target value is finally written
- which action, callback, or response triggers the write
- what upstream state feeds the write
- where normal and risk paths fork

Default boundary model:

```text
writer <- builder <- entry <- source
```

Stop when the next blocker is no longer request discovery.

Detailed reference: `references/browser-locate-and-request-chain.md`

### `recover`

Enter only after the boundary is real enough and the next blocker is shell opacity.

Typical blockers:

- webpack bootstrap
- worker bridge
- wasm loader
- dispatcher flattening
- string tables
- helper indirection
- JSVMP-style shells

Reduce only the layer that blocks progress. Stop as soon as you have a readable or callable logic contract.

Detailed reference: `references/browser-recover-and-shell-reduction.md`

### `runtime`

Enter when the boundary and shell are already clear but browser execution and local execution diverge.

Classify the first meaningful divergence before patching:

- missing object
- missing state
- anti-debugging
- unstable source
- risk branch

Use a first-divergence comparison table and keep the runtime dependency set minimal.

Detailed reference: `references/browser-runtime-fit-and-risk.md`

### `validation`

Enter when the remaining work is equivalence proof.

Compare checkpoints, not just the final output:

- request body before sign
- sign input tuple
- sign output
- encrypted payload
- header set
- cookie or storage mutation

The result must state what is proven, what is still open, and which evidence supports each claim.

Detailed reference: `references/browser-validation-and-handoff.md`

## Topic Routing Inside The Browser Branch

After the stage is selected, apply the matching topic lens:

| Current blocker | Use inside the stage |
| --- | --- |
| `sign`, `token`, dynamic headers, encrypted fields | crypto entry locating and boundary observation |
| `worker`, `wasm`, `webpack/runtime`, loader callbacks | bridge and shell reduction |
| `hasDebug`, endless `debugger`, branch flips | anti-debug and runtime diagnosis |
| `cookie` hops, WebSocket, protobuf, SSE, ack or renewal | protocol and state-chain expansion |
| `basearr`, browser/local mismatch, missing browser state | minimal environment fit |

## Browser Tool Order

1. `chrome_devtools` to capture the real request and initiator
2. `js_reverse` to trace boundary, shell, runtime, or checkpoints
3. `burp` only after one replay path is stable

## Handoff Discipline

Whenever the stage changes, output a compact handoff card:

```text
--- Stage Handoff ---
From: {previous stage}
To: {next stage}
Proven: {request, boundary, upstream chain, runtime or recovery facts}
Open: {questions the next stage must answer}
Invalidated: {stale assumptions or "none"}
```

Do not carry guesses forward as facts.

## Replay Exit Criteria

Do not move into Burp fuzzing until you can explain:

- where the target field is written
- which inputs are stable constants
- which inputs come from cookies, storage, upstream responses, or browser lifecycle
- whether request order or navigation state matters
- which fields are safe to mutate

## Output Contract

Deliver:

- current stage and why it is the correct stage
- request-chain proof
- sink or write boundary
- recovered shell or runtime conclusions when applicable
- a Burp-ready baseline request or a precise statement of the remaining blocker

Record template: `references/browser-request-chain-template.md`

## Recommended Read Order Inside This Branch

1. `browser-locate-and-request-chain.md` when the boundary is not real yet
2. `browser-recover-and-shell-reduction.md` when shell opacity is the blocker
3. `browser-runtime-fit-and-risk.md` when browser/local execution diverges
4. `browser-validation-and-handoff.md` when the remaining work is proof or stage transfer
5. `browser-request-chain-template.md` when you need a persistent record or handoff artifact
