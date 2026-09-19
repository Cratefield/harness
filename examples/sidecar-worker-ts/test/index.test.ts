// Behaviour tests, run with `bun test` against the real handler — the same
// `fetch` entry point `wrangler deploy` bundles. They pin the mount
// contract from this side: the stamps, the unstamped probe, the surface
// shape rules, the 202 event answer, and the gateway guard's refusals.
// What they cannot prove is a real host forwarding over a real binding —
// that is the Rust template's conformance kit, and it is called out in the
// README as something this example does not have parity with.

import { describe, expect, it } from "bun:test";
import sidecar from "../src/index";
import type { Env, EventContext } from "../src/index";
import { HARNESS_API } from "../src/http";
import { MODULE_NAME, MODULE_TABLES, MODULE_VERSION } from "../src/module";
import { SURFACE_API } from "../src/surface";
import { SECRET, mintToken, mintValidToken, nowSecs } from "./token";

const ORIGIN = "https://sidecar.test";
const MOUNT = `/v1/${MODULE_NAME}`;
const GUARD_ON = { SIDECAR_REQUIRE_GATEWAY: "1" };
const GUARD_OFF = { SIDECAR_REQUIRE_GATEWAY: "0" };

/** Collects `waitUntil` work so a test can wait for handlers to run. */
class TestCtx implements EventContext {
	readonly promises: Promise<unknown>[] = [];
	waitUntil(promise: Promise<unknown>): void {
		this.promises.push(promise);
	}
}

function call(
	path: string,
	init: RequestInit = {},
	envVars: Partial<Env> = {},
): { response: Promise<Response>; ctx: TestCtx } {
	const env: Env = { SIDECAR_GATEWAY_SECRET: SECRET, ...envVars };
	const ctx = new TestCtx();
	return { response: sidecar.fetch(new Request(`${ORIGIN}${path}`, init), env, ctx), ctx };
}

async function body(response: Response): Promise<Record<string, unknown>> {
	return (await response.json()) as Record<string, unknown>;
}

describe("the module mount", () => {
	it("stamps every answer and echoes the caller's request id", async () => {
		const { response } = call(`${MOUNT}/ping`, { headers: { "x-request-id": "req-abc-123" } });
		const res = await response;
		expect(res.status).toBe(200);
		expect(res.headers.get("x-harness-api")).toBe(String(HARNESS_API));
		expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
		expect(res.headers.get("x-request-id")).toBe("req-abc-123");
		const json = await body(res);
		expect(json["module"]).toBe(MODULE_NAME);
		expect(json["version"]).toBe(MODULE_VERSION);
	});

	it("answers a validated write-shaped route", async () => {
		const { response } = call(`${MOUNT}/echo`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ text: "hello" }),
		});
		const res = await response;
		expect(res.status).toBe(200);
		const json = await body(res);
		expect(json["echoed"]).toBe("hello");
		// The honest part: nothing is stored, because there is no data
		// access yet (#153/#155).
		expect(json["stored"]).toBe(false);
	});

	it("answers a bad body with the host's problem shape, not a bare string", async () => {
		const { response } = call(`${MOUNT}/echo`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ wrong: true }),
		});
		const res = await response;
		expect(res.status).toBe(400);
		expect(res.headers.get("content-type")).toBe("application/problem+json");
		// Stamped like any other answer — the host checks the stamps on
		// forwarded errors too.
		expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
		const json = await body(res);
		expect(json["type"]).toBe("https://factory0.ventures/problems/validation-failed");
	});

	it("404s sensibly inside, beside, and at the root of the prefix", async () => {
		for (const path of [`${MOUNT}/nope`, MOUNT, "/v1/notes-nope/ping"]) {
			const { response } = call(path, { headers: { "x-request-id": "req-404" } });
			const res = await response;
			expect(res.status).toBe(404);
			expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
			expect(res.headers.get("x-request-id")).toBe("req-404");
			const json = await body(res);
			expect(json["type"]).toBe("https://factory0.ventures/problems/not-found");
		}
	});
});

describe("/__health", () => {
	it("answers without a gateway stamp and names the module", async () => {
		// No SIDECAR_REQUIRE_GATEWAY, no token, no stamps required of the
		// caller — probes must probe.
		const { response } = call("/__health", {}, { SIDECAR_REQUIRE_GATEWAY: "0" });
		const res = await response;
		expect(res.status).toBe(200);
		expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
		const json = await body(res);
		expect(json["harness_api"]).toBe(HARNESS_API);
		const modules = json["modules"] as Record<string, unknown>[];
		expect(modules.length).toBe(1);
		expect(modules[0]?.["name"]).toBe(MODULE_NAME);
		expect(modules[0]?.["version"]).toBe(MODULE_VERSION);
		// The table-collision check reads this; an explicit empty list is a
		// decision, not an omission.
		expect(Array.isArray(modules[0]?.["tables"])).toBe(true);
		expect(modules[0]?.["tables"]).toEqual([...MODULE_TABLES]);
	});
});

describe("/__surface", () => {
	it("satisfies the shape rules the host's merge enforces", async () => {
		const { response } = call("/__surface", {}, { SIDECAR_REQUIRE_GATEWAY: "0" });
		const res = await response;
		expect(res.status).toBe(200);
		const json = await body(res);
		expect(json["surface_api"]).toBe(SURFACE_API);
		expect(json["harness_api"]).toBe(HARNESS_API);
		const modules = json["modules"] as Record<string, unknown>[];
		// Exactly one entry, named exactly the mount name: a sidecar speaks
		// for one module, and the host rejects a document that names
		// anything else or names it twice.
		expect(modules.length).toBe(1);
		expect(modules[0]?.["name"]).toBe(MODULE_NAME);
		expect(typeof modules[0]?.["version"]).toBe("string");
		const actions = modules[0]?.["actions"] as Record<string, unknown>[];
		const views = modules[0]?.["views"] as Record<string, unknown>[];
		expect(actions.length).toBeLessThanOrEqual(64);
		expect(views.length).toBeLessThanOrEqual(64);
		// The host drops the body over 256 KiB before validating it.
		expect(JSON.stringify(json).length).toBeLessThan(256 * 1024);
		// `Surface::validate`'s essentials, mirrored: paths relative and
		// slash-led, views referencing declared actions.
		const names = new Set(actions.map((action) => action["name"]));
		for (const action of actions) {
			expect(typeof action["path"]).toBe("string");
			expect(action["path"] as string).toMatch(/^\//);
		}
		for (const view of views) {
			expect(names.has(view["action"] as string)).toBe(true);
		}
	});
});

describe("/__events", () => {
	// The host stamps every event forward (sidecar.rs `EventForwarder`),
	// so these carry a valid stamp even with the gate off — the route
	// authenticates the stamp on the secret's account, not the gate's.
	it("answers 202 and runs the handler after the response", async () => {
		const { response, ctx } = call("/__events", {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-request-id": "req-evt",
				"x-harness-gateway": await mintValidToken(),
			},
			body: JSON.stringify({ event: "note-echoed", payload: { n: 1 } }),
		});
		const res = await response;
		expect(res.status).toBe(202);
		expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
		expect(res.headers.get("x-request-id")).toBe("req-evt");
		const json = await body(res);
		expect(json["accepted"]).toBe(true);
		expect(json["handlers"]).toBe(1);
		expect(ctx.promises.length).toBe(1);
		// The handler has not necessarily run yet — that is the point of
		// 202. Waiting here proves the deferred work completes cleanly.
		await Promise.all(ctx.promises);
	});

	it("counts zero handlers as accepted-but-unheard, not as a quiet success", async () => {
		const { response } = call("/__events", {
			method: "POST",
			headers: { "x-harness-gateway": await mintValidToken() },
			body: JSON.stringify({ event: "nobody-listens", payload: null }),
		});
		const res = await response;
		expect(res.status).toBe(202);
		const json = await body(res);
		expect(json["accepted"]).toBe(false);
		expect(json["handlers"]).toBe(0);
	});

	it("400s a malformed body in the host's problem shape", async () => {
		for (const bad of [
			"not json at all",
			JSON.stringify(["not", "an", "object"]),
			JSON.stringify({ event: "note-echoed" }),
			JSON.stringify({ payload: {} }),
			JSON.stringify({ event: 7, payload: {} }),
		]) {
			const { response } = call("/__events", {
				method: "POST",
				headers: { "x-harness-gateway": await mintValidToken() },
				body: bad,
			});
			const res = await response;
			expect(res.status).toBe(400);
			const json = await body(res);
			expect(json["type"]).toBe("https://factory0.ventures/problems/validation-failed");
		}
	});

	it("401s an unstamped event forward even with the gate off", async () => {
		// `events_inbound` (crates/core/src/sidecar.rs) verifies the stamp
		// whenever it holds a gateway signer — keyed on the secret, not on
		// `SIDECAR_REQUIRE_GATEWAY`: an unauthenticated event trigger would
		// let a stranger forge the payloads handlers act on.
		const { response } = call("/__events", {
			method: "POST",
			body: JSON.stringify({ event: "note-echoed", payload: 1 }),
		}, GUARD_OFF);
		const res = await response;
		expect(res.status).toBe(401);
		const json = await body(res);
		expect(json["type"]).toBe("https://factory0.ventures/problems/sidecar-unauthorized");
	});

	it("404s an event forward when no usable secret is configured", async () => {
		// "Absent is safer than open" (harness.rs `inbound_events_route`):
		// without the secret the route does not exist here at all.
		const { response } = call("/__events", {
			method: "POST",
			body: JSON.stringify({ event: "note-echoed", payload: 1 }),
		}, { SIDECAR_REQUIRE_GATEWAY: "0", SIDECAR_GATEWAY_SECRET: undefined });
		const res = await response;
		expect(res.status).toBe(404);
		const json = await body(res);
		expect(json["type"]).toBe("https://factory0.ventures/problems/not-found");
	});
});

describe("the gateway guard", () => {
	it("passes a valid host-minted token on the module and the surface", async () => {
		// The guard only decides "through or not"; the route behind it still
		// answers with its own status, so /__events stays a 202 here.
		const expectations: Record<string, number> = {
			[`${MOUNT}/ping`]: 200,
			["/__surface"]: 200,
			["/__events"]: 202,
		};
		for (const [path, expected] of Object.entries(expectations)) {
			const init: RequestInit =
				path === "/__events"
					? { method: "POST", body: JSON.stringify({ event: "note-echoed", payload: 1 }) }
					: {};
			const { response } = call(
				path,
				{ ...init, headers: { "x-harness-gateway": await mintValidToken() } },
				GUARD_ON,
			);
			const res = await response;
			expect(res.status).toBe(expected);
		}
	});

	it("401s a missing token on every guarded path", async () => {
		for (const path of [`${MOUNT}/ping`, "/__surface", "/__events"]) {
			const init: RequestInit = path === "/__events" ? { method: "POST", body: "{}" } : {};
			const { response } = call(path, init, { SIDECAR_REQUIRE_GATEWAY: "1" });
			const res = await response;
			expect(res.status).toBe(401);
			const json = await body(res);
			expect(json["type"]).toBe("https://factory0.ventures/problems/sidecar-unauthorized");
		}
	});

	it("401s an expired token", async () => {
		const expired = await mintToken({ purpose: "sidecar-gateway", exp: nowSecs() - 1 });
		const { response } = call(
			`${MOUNT}/ping`,
			{ headers: { "x-harness-gateway": expired } },
			GUARD_ON,
		);
		expect((await response).status).toBe(401);
	});

	it("401s a tampered MAC", async () => {
		const token = await mintValidToken();
		const [payload, mac] = token.split(".");
		const flipped = mac?.slice(0, -1) + (mac?.endsWith("A") ? "B" : "A");
		const { response } = call(
			`${MOUNT}/ping`,
			{ headers: { "x-harness-gateway": `${payload}.${flipped}` } },
			GUARD_ON,
		);
		expect((await response).status).toBe(401);
	});

	it("401s a token minted for a different purpose", async () => {
		const wrong = await mintToken({ purpose: "confirm-link", exp: nowSecs() + 120 });
		const { response } = call(
			`${MOUNT}/ping`,
			{ headers: { "x-harness-gateway": wrong } },
			GUARD_ON,
		);
		expect((await response).status).toBe(401);
	});

	it("accepts the admin purpose the host mints after its own admin check", async () => {
		// `gateway_grant` (crates/core/src/sidecar.rs) tries the admin
		// purpose first on any guarded path; admin-ness only decides whether
		// the sidecar re-materializes its own bearer, and this Worker has no
		// admin plane. The test pins the parity so a future admin route
		// inherits a proof, not an anecdote.
		const admin = await mintToken({ purpose: "sidecar-gateway-admin", exp: nowSecs() + 120 });
		const { response } = call(
			`${MOUNT}/ping`,
			{ headers: { "x-harness-gateway": admin } },
			GUARD_ON,
		);
		expect((await response).status).toBe(200);
	});

	it("fails closed — 503 — when required with no secret or a too-short one", async () => {
		for (const envVars of [
			{ SIDECAR_GATEWAY_SECRET: undefined },
			{ SIDECAR_GATEWAY_SECRET: "too short" },
		]) {
			const { response } = call(`${MOUNT}/ping`, {}, { SIDECAR_REQUIRE_GATEWAY: "1", ...envVars });
			const res = await response;
			expect(res.status).toBe(503);
			const json = await body(res);
			expect(json["type"]).toBe("https://factory0.ventures/problems/sidecar-unavailable");
		}
	});

	it("never closes /__health — probes must probe", async () => {
		const { response } = call("/__health", {}, { SIDECAR_REQUIRE_GATEWAY: "1" });
		const res = await response;
		expect(res.status).toBe(200);
		expect(res.headers.get("x-harness-module")).toBe(MODULE_NAME);
	});
});
