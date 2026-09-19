// The issue #438 canary harness: boots the compiled canary Worker under
// miniflare (real workerd, real local D1) and asserts every canary route
// round-trips bytes. Any non-200 is a failure and its body is printed
// verbatim (the Worker answers 500 with the stage and expected/got hex).
//
// Usage:
//   npm install            (once; installs the pinned miniflare)
//   worker-build --release (once; writes build/worker/shim.mjs)
//   node run.mjs
import { Miniflare } from "miniflare";
import { existsSync } from "node:fs";

const shim = new URL("./build/worker/shim.mjs", import.meta.url).pathname;
if (!existsSync(shim)) {
    console.error(`FAIL setup: ${shim} is missing — run \`worker-build --release\` first`);
    process.exit(2);
}

const mf = new Miniflare({
    modules: true,
    scriptPath: shim,
    compatibilityDate: "2024-11-01",
    // worker-build's bundle is an ES module with a `.js` extension (the
    // default rule would parse it as CommonJS), and the wasm arrives as a
    // default import to be compiled by workerd.
    modulesRules: [
        { type: "ESModule", include: ["**/*.js", "**/*.mjs"] },
        { type: "CompiledWasm", include: ["**/*.wasm"] },
    ],
    d1Databases: { DB: "d1-blob-canary" },
});

let failures = 0;
try {
    const routes = [
        ["GET", "/health"],
        ["POST", "/blob"],
        ["POST", "/session"],
        ["POST", "/secrets"],
    ];
    for (const [method, path] of routes) {
        try {
            const res = await mf.dispatchFetch(`http://d1-blob-canary.test${path}`, { method });
            const body = await res.text();
            const ok = res.status === 200 && body.includes('"ok":true');
            if (!ok) failures++;
            console.log(
                `${ok ? "PASS" : "FAIL"} ${method} ${path} -> ${res.status} ${body}`,
            );
        } catch (err) {
            failures++;
            console.log(`FAIL ${method} ${path} -> dispatch error: ${err}`);
        }
    }
} finally {
    await mf.dispose();
}

if (failures > 0) {
    console.log(`FAIL ${failures} canary route(s) failed`);
    process.exit(1);
}
console.log("PASS all d1-blob-canary routes round-tripped bytes through real D1");
