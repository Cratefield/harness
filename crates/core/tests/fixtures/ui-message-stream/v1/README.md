# UI message stream fixtures, v1

These are the exact bytes `cratefield_core::sse` writes for four scripted
runs of the Vercel AI SDK v6 "UI message stream" chat protocol (issue
#860): one `data: <json>` line per chunk, each event closed by a blank
line, the stream closed by a literal `data: [DONE]`. A response carrying
them names the dialect with the `x-vercel-ai-ui-message-stream: v1`
header.

`crates/core/tests/ui_message_stream.rs` regenerates every file from the
encoder and asserts the committed bytes still match, byte for byte. After
a deliberate protocol change, rewrite them with:

```sh
UPDATE_UI_MESSAGE_FIXTURES=1 cargo test -p cratefield-core --test ui_message_stream
```

Review a fixture diff like an API change: these bytes are a
cross-language contract, not test scratch.

## Who reads the other half

The sibling `<case>.message.json` files — owned by the Node test in
`packages/ui-message-contract`, not generated here — carry the same
chunks as parsed JSON. That test replays each `<case>.sse` through the
AI SDK's own UI message stream parser and proves the Rust bytes decode
into exactly the chunks the encoder meant. This directory is where the
two halves of issue #860 meet: the Rust side commits the bytes, the Node
side proves they parse.

## The cases

| case | exercises |
| --- | --- |
| `text-and-reasoning` | a plain `TextDelta` stream through `text_stream_chunks`: reasoning and text parts taking turns, two deltas growing one part, usage carried as nothing, `finish` with `stop`, no `messageId` (the field is omitted, not null) |
| `tool-loop` | two steps through the real `run_tool_loop_stream`: streamed tool arguments, tool output riding as parsed JSON, the output landing after the step that called it closes, the second step reopening, `messageId` set |
| `error-mid-stream` | a provider failure mid-answer: the open part closes, the wire gets the fixed masked sentence (`An error occurred.`), the real error only in the log, no `finish-step` |
| `custom-parts` | hand-built chunks a caller pushes directly: a source, a `data-weather` part (the optional `transient` left off), a tool call that fails after being announced, `finish` with `other` |
