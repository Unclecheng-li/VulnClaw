# Browser Locate And Request Chain

Use this file when the browser-side target request, sink, write boundary, or upstream state chain is still not concrete enough for shell reduction or runtime work.

## Owns

- proving the real target request from a live sample
- proving the sink or write boundary
- proving the trigger action or callback
- walking the upstream dependency chain
- separating normal-state and risk-state chains

## Boundary Model

Use this model and keep each layer distinct:

```text
writer <- builder <- entry <- source
```

- `writer`: final write into body, header, query, cookie, storage, or message envelope
- `builder`: transform, sign, encrypt, serialize, or package layer
- `entry`: UI action, callback, event, or response that starts the chain
- `source`: upstream response, storage, cookie, browser state, time, randomness, or user input

## Default Order

1. capture a real target request sample
2. observe the sink first
3. walk backward through `writer <- builder <- entry <- source`
4. expand upstream when the current source depends on prior requests or state
5. split normal-state and risk-state chains if both appear

## Strong First Observation Points

| Sink type | First point to prove |
| --- | --- |
| request body field | final serialization or submit write point |
| header field | request construction or header-set call |
| JS-written cookie | cookie setter |
| response-driven cookie dependency | response packet and first dependent request |
| WebSocket frame | final envelope before `send` |
| worker reply | `postMessage` bridge contract |

## Completion Standard

Stop locate when:

- the request sample is real
- the sink is real
- `writer`, `builder`, `entry`, and `source` are concrete enough for the next step
- the next blocker is shell opacity, runtime divergence, or checkpoint proof rather than request discovery

## Do Not Do

- broad deobfuscation before the boundary is real
- environment patching while the sink is still guessed
- relying on keyword hits as proof
