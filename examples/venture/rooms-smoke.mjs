// Two sockets against the room Durable Object, under `wrangler dev` (issue #103).
//
// `cargo test` cannot reach a Durable Object at all — it is a runtime object,
// not a Rust type you can construct — so this is the acceptance criterion the
// issue writes out: two sockets, not one, because everything that matters here
// is what one socket sees when the other does something.
const BASE = process.env.BASE ?? "ws://127.0.0.1:8787";
const ROOM = `smoke-${Date.now()}`;

const open = (member) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(`${BASE}/rooms/${ROOM}?member=${member}`);
    // The port carries bytes — a module owns its own protocol, so the driver
    // never decides a frame is text — and a browser WebSocket hands those back
    // as a Blob unless told otherwise. Reading `String(e.data)` gives you
    // "[object Blob]", which is a passing-looking assertion about nothing.
    ws.binaryType = "arraybuffer";
    ws.seen = [];
    const decoder = new TextDecoder();
    ws.addEventListener("message", (e) =>
      ws.seen.push(
        typeof e.data === "string" ? e.data : decoder.decode(new Uint8Array(e.data)),
      ),
    );
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", reject);
    setTimeout(() => reject(new Error(`${member} never opened`)), 15000);
  });

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

const fail = (why) => {
  console.error(`FAIL: ${why}`);
  process.exit(1);
};

const alice = await open("alice");
await settle(300);
const bob = await open("bob");
await settle(500);

// 1. Join is broadcast to the room, so alice learns bob arrived.
if (!alice.seen.some((m) => m === "joined:bob")) {
  fail(`alice did not see bob join; saw ${JSON.stringify(alice.seen)}`);
}

// 2. A message from one socket reaches the other, tagged with who sent it —
//    which is the member identity surviving the trip through the socket tag.
alice.send("hello");
await settle(500);
if (!bob.seen.some((m) => m === "alice:hello")) {
  fail(`bob did not see alice's message; saw ${JSON.stringify(bob.seen)}`);
}

// 3. The alarm fires, once, and reaches both. The handler arms it on join, so
//    two joins must not produce two ticks per second.
await settle(1500);
const ticks = bob.seen.filter((m) => m === "tick").length;
if (ticks < 1) fail(`no alarm tick reached bob; saw ${JSON.stringify(bob.seen)}`);
if (ticks > 1) fail(`the alarm fired ${ticks} times, it is a one-shot`);

// 4. Leaving is broadcast to whoever is left.
bob.close();
await settle(800);
if (!alice.seen.some((m) => m === "left:bob")) {
  fail(`alice did not see bob leave; saw ${JSON.stringify(alice.seen)}`);
}

alice.close();
console.log("rooms smoke: join, message, alarm and leave all crossed two sockets");
