// Contract tests for the Rust UI-message-stream encoder (crates/core sse).
// Every committed <case>.sse under
// crates/core/tests/fixtures/ui-message-stream/v1/ must be framed as valid
// SSE, parse with the real Vercel AI SDK v6 pipeline with zero validation
// errors, and rebuild exactly the committed <case>.message.json UIMessage.
//
// Regenerate the .message.json snapshots after an intentional encoder
// change with: UPDATE_UI_MESSAGE_FIXTURES=1 npm test -w @cratefield/ui-message-contract

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseJsonEventStream } from "@ai-sdk/provider-utils";
import { uiMessageChunkSchema, readUIMessageStream } from "ai";

const FIXTURE_DIR = new URL(
  "../../../crates/core/tests/fixtures/ui-message-stream/v1/",
  import.meta.url,
);
const UPDATE = process.env.UPDATE_UI_MESSAGE_FIXTURES === "1";

async function discoverCases() {
  try {
    return (await readdir(FIXTURE_DIR))
      .filter((name) => name.endsWith(".sse"))
      .map((name) => name.replace(/\.sse$/, ""))
      .sort();
  } catch {
    return [];
  }
}

// (a) Framing: file ends with "data: [DONE]\n\n", and every line of every
// event is either an SSE comment or a data: line — the encoder emits no
// event:/id:/retry: fields and no stray text.
function assertFraming(name, sse) {
  assert.ok(
    sse.endsWith("data: [DONE]\n\n"),
    `${name}.sse must end with "data: [DONE]\\n\\n"`,
  );
  const events = sse.split("\n\n").slice(0, -1);
  assert.ok(events.length > 0, `${name}.sse contains no events`);
  for (const [i, event] of events.entries()) {
    for (const line of event.split("\n")) {
      if (line === "" || line.startsWith(":")) continue;
      assert.ok(
        line.startsWith("data:"),
        `${name}.sse event ${i}: non-comment lines must be data: lines, got ${JSON.stringify(line)}`,
      );
    }
  }
  assert.equal(events.at(-1), "data: [DONE]", `${name}.sse final event must be "data: [DONE]"`);
}

// Raw JSON payloads of all data: lines, in order (structure only — the
// schema-validated path goes through parseJsonEventStream below).
function dataPayloads(sse) {
  const payloads = [];
  for (const event of sse.split("\n\n").slice(0, -1)) {
    for (const line of event.split("\n")) {
      if (!line.startsWith("data:")) continue;
      const raw = line.slice(5).trim();
      if (raw === "[DONE]") continue;
      payloads.push(JSON.parse(raw));
    }
  }
  return payloads;
}

// AI SDK pipeline: bytes -> parseJsonEventStream against uiMessageChunkSchema
// (throw on the first validation failure, like DefaultChatTransport does) ->
// validated chunks.
function validatedChunkStream(sse) {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(sse));
      controller.close();
    },
  });
  return parseJsonEventStream({ stream: body, schema: uiMessageChunkSchema }).pipeThrough(
    new TransformStream({
      transform(result, controller) {
        if (!result.success) {
          throw new Error(`chunk failed uiMessageChunkSchema validation: ${result.error}`);
        }
        controller.enqueue(result.value);
      },
    }),
  );
}

const cases = await discoverCases();

test("ui-message-stream fixtures discovered", () => {
  assert.ok(
    cases.length > 0,
    `no *.sse fixtures found in ${fileURLToPath(FIXTURE_DIR)}`,
  );
});

for (const name of cases) {
  test(`${name}: UI message stream contract`, async (t) => {
    const sse = await readFile(new URL(`${name}.sse`, FIXTURE_DIR), "utf8");
    const messagePath = new URL(`${name}.message.json`, FIXTURE_DIR);

    await t.test("framing", () => assertFraming(name, sse));

    // What the encoder itself declares as errors on the wire. The AI SDK
    // surfaces `error` chunks only through readUIMessageStream's onError
    // (as Error(errorText)); it does not add a part for them.
    const encodedErrors = dataPayloads(sse)
      .filter((chunk) => chunk?.type === "error")
      .map((chunk) => chunk.errorText);
    if (name === "error-mid-stream") {
      assert.equal(encodedErrors.length, 1, `${name}.sse must encode exactly one error chunk`);
    }

    // (b) Parse + rebuild in one pass. Validation failures throw out of the
    // transform and fail the test; onError collects surfaced errors.
    const surfacedErrors = [];
    let finalMessage;
    try {
      const messages = readUIMessageStream({
        stream: validatedChunkStream(sse),
        onError: (error) => surfacedErrors.push(error),
      });
      for await (const message of messages) finalMessage = message;
    } catch (error) {
      assert.fail(`${name}.sse: AI SDK failed to consume the stream: ${error}`);
    }
    assert.ok(finalMessage, `${name}.sse rebuilt no UIMessage`);
    // JSON round-trip normalizes undefined-valued keys (e.g. metadata) so
    // the in-memory message matches what the snapshot stores.
    const rebuilt = JSON.parse(JSON.stringify(finalMessage));

    await t.test("error surfacing", () => {
      const expected = name === "error-mid-stream" ? encodedErrors : [];
      assert.deepEqual(
        surfacedErrors.map((error) => String(error.message)),
        expected,
        `${name}.sse must surface exactly ${JSON.stringify(expected)} via onError`,
      );
    });

    // (c) The rebuilt UIMessage equals the committed snapshot.
    await t.test("rebuilt message matches fixture", async () => {
      if (UPDATE) {
        await writeFile(messagePath, `${JSON.stringify(rebuilt, null, 2)}\n`);
        return;
      }
      let committed;
      try {
        committed = await readFile(messagePath, "utf8");
      } catch {
        assert.fail(
          `${name}.message.json is missing next to the fixture — run with UPDATE_UI_MESSAGE_FIXTURES=1 to write it`,
        );
      }
      assert.deepEqual(JSON.parse(committed), rebuilt);
    });
  });
}
