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
    const giveUp = setTimeout(() => reject(new Error(`${member} never opened`)), 15000);
    ws.addEventListener("open", () => {
      clearTimeout(giveUp);
      resolve(ws);
    });
    ws.addEventListener("error", (e) => {
      clearTimeout(giveUp);
      reject(e);
    });
  });

const settle = (ms) => new Promise((r) => setTimeout(r, ms));

// Wait for something to have happened rather than for a duration to have
// passed. The alarm assertions below are about *how many* ticks one arming
// produces, and a fixed sleep turns a slow cold start into a red build with no
// code change behind it.
const until = async (ws, want, ms = 10000) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (ws.seen.includes(want)) return true;
    await settle(50);
  }
  return false;
};

const fail = (why) => {
  console.error(`FAIL: ${why}`);
  process.exit(1);
};

const alice = await open("alice");
const bob = await open("bob");

// 1. Join is broadcast to the room, so alice learns bob arrived.
if (!(await until(alice, "joined:bob"))) {
  fail(`alice did not see bob join; saw ${JSON.stringify(alice.seen)}`);
}

// 2. A message from one socket reaches the other, tagged with who sent it —
//    which is the member identity surviving the trip through the socket tag.
alice.send("hello");
if (!(await until(bob, "alice:hello"))) {
  fail(`bob did not see alice's message; saw ${JSON.stringify(bob.seen)}`);
}

// 2b. `members()` answers by member, not by socket, and `room_id()` answers at
//     all — two context methods nothing else here reaches, and all three of the
//     defects found in them shipped because no test called them.
alice.send("who");
if (!(await until(alice, "members:alice,bob"))) {
  fail(`members() did not answer with both, once each; saw ${JSON.stringify(alice.seen)}`);
}
alice.send("where");
// Waited for, like every other assertion here. Checking `seen` on the line
// after `send` tests how fast the loop is, not what the room answered — and it
// failed that way once, against code that was working.
const sawRoom = async () => {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (alice.seen.some((m) => m.startsWith("room:") && m.length > "room:".length)) return true;
    await settle(50);
  }
  return false;
};
if (!(await sawRoom())) {
  fail(`room_id() answered empty or not at all; saw ${JSON.stringify(alice.seen)}`);
}

// 3. The shared clock ticks, and keeps ticking. An alarm is one-shot, so a
//    clock is only a clock if the handler re-arms it — a room that ticked once
//    and stopped would pass a "fires exactly once" assertion and be useless to
//    the twenty people it exists for.
if (!(await until(bob, "tick"))) {
  fail(`no alarm tick reached bob; saw ${JSON.stringify(bob.seen)}`);
}
const before = bob.seen.filter((m) => m === "tick").length;
await settle(1400);
const after = bob.seen.filter((m) => m === "tick").length;
if (after <= before) {
  fail(`the clock stopped after ${before} tick(s): on_alarm did not re-arm`);
}

// 4. Leaving is broadcast to whoever is left.
bob.close();
if (!(await until(alice, "left:bob"))) {
  fail(`alice did not see bob leave; saw ${JSON.stringify(alice.seen)}`);
}

alice.close();
// 5. The guards on the upgrade path, which are the difference between a room
//    and an open door: no upgrade header, and a room name nobody should be able
//    to mint an object for.
// Plain GETs: `fetch` will not send an `upgrade` header at all, which is why
// the name is checked before the header on the other side — an unbounded name
// must be refused whether or not the caller sent one.
const status = async (path) =>
  (await fetch(`${BASE.replace("ws://", "http://")}${path}`)).status;
if ((await status(`/rooms/${ROOM}`)) !== 426) {
  fail("a plain GET was not refused: a curl can fake a join");
}
if ((await status(`/rooms/${"x".repeat(200)}`)) !== 400) {
  fail("an unbounded room name was accepted: that is an unbounded object bill");
}
if ((await status("/rooms/Not A Room")) !== 400) {
  fail("a room name with spaces and capitals was accepted");
}

console.log(
  "rooms smoke: join, message, members, room id, a clock that keeps ticking, leave, and the upgrade guards",
);
