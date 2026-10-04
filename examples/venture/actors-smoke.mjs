// Actors against the ACTORS Durable Object, under `wrangler dev` (issue #583).
//
// `cargo test` cannot reach a Durable Object at all — it is a runtime object,
// not a Rust type you can construct — so this is the acceptance criterion the
// issue writes out, and every assertion here is one a native run could not make:
// that fifty calls at once really do serialise on the object, that an alarm
// really does fire against a real clock, and that an unsigned call really is
// refused by the object rather than by a check in the caller.
const BASE = process.env.BASE ?? "http://127.0.0.1:8787";
// Unique per run so concurrent CI runs (and reruns on one machine) cannot
// collide in the object's storage, which outlives the process.
const RUN = `${Date.now()}`;

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

const fail = (why) => {
  console.error(`FAIL: ${why}`);
  process.exit(1);
};

const json = async (res) => {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    fail(`expected JSON, got ${res.status} ${text}`);
  }
};

const inc = async (key) =>
  json(await fetch(`${BASE}/v1/actors/counter/${key}/inc`, { method: "POST" }));
const readCounter = async (key) =>
  json(await fetch(`${BASE}/v1/actors/counter/${key}`));

// 1. Fifty increments at once, against one key. The object runs one message at
//    a time, so they land as fifty distinct values — a lost update would show
//    up as a repeated number and a missing one, which is exactly what this
//    checks: the replies, sorted, are 1..50 with nothing doubled.
const counter = `c-${RUN}`;
const replies = await Promise.all(
  Array.from({ length: 50 }, () => inc(counter)),
).then((rows) => rows.map((row) => row.value).sort((a, b) => a - b));
const want = Array.from({ length: 50 }, (_, i) => i + 1);
if (JSON.stringify(replies) !== JSON.stringify(want)) {
  fail(`fifty concurrent increments did not serialise to 1..50; got ${JSON.stringify(replies)}`);
}
if ((await readCounter(counter)).value !== 50) {
  fail("a read after the fifty did not see 50");
}

// 2. A second key is its own actor: it starts at 1 while the first sits at 50.
const other = `c-other-${RUN}`;
if ((await inc(other)).value !== 1) {
  fail("a fresh key did not start at 1: two keys share one actor");
}
if ((await readCounter(counter)).value !== 50) {
  fail("bumping a second key moved the first");
}

// 3. The alarm. The value is readable the moment it is stored, and gone once a
//    real one-second alarm fires — which waits out the clock rather than
//    asserting on a duration the object was told, because only the object knows
//    when it actually woke.
const expiring = `e-${RUN}`;
const putRes = await fetch(`${BASE}/v1/actors/expiring/${expiring}`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ value: "tick", ttl_ms: 1000 }),
});
if (putRes.status !== 200) {
  fail(`storing an expiring value answered ${putRes.status}`);
}
const stored = (await json(await fetch(`${BASE}/v1/actors/expiring/${expiring}/read`))).value;
if (stored !== "tick") {
  fail(`an expiring value was not readable immediately; got ${JSON.stringify(stored)}`);
}
const deadline = Date.now() + 15000;
let expired = false;
while (Date.now() < deadline) {
  const now = (await json(await fetch(`${BASE}/v1/actors/expiring/${expiring}/read`))).value;
  if (now === "") {
    expired = true;
    break;
  }
  await settle(250);
}
if (!expired) {
  fail("the alarm never fired: the value outlived its ttl by 15s");
}

// 4. The object refuses an unsigned call, and the refusal is the object's. This
//    POST walks straight to the ACTORS stub with no signature header; the driver
//    checks the signature before it reads a byte of the frame, so this is a 403
//    and never a 400 or a 404 — the difference between refusing the caller and
//    refusing the request it sent.
//
//    No body on the POST: the object answers before it reads one, and a request
//    stream left unread when the response is sent is a quirk `wrangler dev`
//    logs as an uncaught error (the body is never parsed either way, so leaving
//    it off changes nothing about what is refused).
const unsigned = await fetch(`${BASE}/actors/unsigned/u-${RUN}`, {
  method: "POST",
});
if (unsigned.status !== 403) {
  fail(`an unsigned call was answered ${unsigned.status}, not 403`);
}

console.log(
  "actors smoke: fifty serialised increments, two independent keys, an expiring value the alarm erases, and a 403 for an unsigned call",
);
