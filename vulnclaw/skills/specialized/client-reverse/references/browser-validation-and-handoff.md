# Browser Validation And Handoff

Use this file when the remaining browser-side work is checkpoint proof, equivalence proof, or stage handoff.

## Checkpoints To Compare

Do not compare only the final output. Compare:

- pre-sign payload
- sign input tuple
- sign output
- encrypted payload
- final request body
- final headers
- cookie or storage mutation when it affects later requests

## Proof Rules

Each checkpoint must state:

- fixed input sample
- browser-side value
- local or recovered-side value
- whether the checkpoint matches
- what evidence supports the comparison
- what gap remains if it does not match

## Handoff Card

When the stage changes, emit:

```text
--- Stage Handoff ---
From: {previous stage}
To: {next stage}
Proven: {request, boundary, upstream chain, recovery or runtime facts}
Open: {questions for the next stage}
Invalidated: {stale assumptions or "none"}
```

## Completion Standard

Validation is complete only when the next operator can see:

- what is equivalent
- what is not equivalent
- what evidence supports each statement
- what remains open
