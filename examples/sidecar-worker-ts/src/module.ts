// The module this sidecar serves — the file you edit, written for someone
// who has never read the harness internals.
//
// The Rust template (`examples/sidecar-module-template`) serves its module
// through the harness crate; here the contract is spelled out in plain
// TypeScript instead. What the host holds this Worker to, on every request
// it forwards:
//
// - it is mounted at `/v1/<module name>` **with the prefix intact** — the
//   host forwards the caller's original URI, so this Worker serves its
//   routes under its own `/v1/notes/...`, not at `/`;
// - every answer carries `x-harness-api` and `x-harness-module` (the
//   envelope in `http.ts` does it once, so no route can forget);
// - a body that does not deserialize is a problem answer, not a bare
//   string.
//
// **This module deliberately does no data access.** The Tables contract it
// is meant to reach data through is not landed: declared tables are #153
// and the generated `@cratefield/client` is #155. Until then there is no
// honest way to touch the database from TypeScript — hand-rolling a
// stand-in client here would teach a shape that is about to change. The
// routes below answer out of thin air on purpose.

import { HARNESS_API, json } from "./http";
import { PROBLEMS, problem } from "./problems";

/**
 * Mounted at `/v1/notes` on whichever Worker serves this harness. One
 * module per sidecar; the mount name on the host (`HARNESS_SIDECARS`) must
 * be exactly this string.
 */
export const MODULE_NAME = "notes";

/**
 * Declared to the host through `/__health` and `/__surface` so the probe
 * and the merge can name what answered. Kept next to the routes, as the
 * Rust template keeps `CARGO_PKG_VERSION`.
 */
export const MODULE_VERSION = "0.1.0";

/** The port names this module refuses to run without: none yet. Data access arrives with #153/#155. */
export const MODULE_REQUIRES: readonly string[] = [];

/**
 * Tables this module owns: **an explicit, positive none.** The host's
 * `/__health` probe reads this list and reports a collision if the host
 * serves a module claiming the same table — a claim of nothing is a
 * decision, not an omission. Declare tables here the day #153 gives the
 * Tables contract a way to.
 */
export const MODULE_TABLES: readonly string[] = [];

/** Events this module emits: none. */
export const MODULE_EMITS: readonly string[] = [];

/**
 * Inbound events this Worker hears. The host delivers each event once,
 * after its own bus — never retried, no queue (ADR 0017) — and expects a
 * `202` whose body says how many local handlers the event found. An event
 * nobody hears is exactly the silent failure the events contract exists to
 * prevent, so zero handlers must read back as `accepted: false`, not as a
 * quiet success.
 */
export const EVENT_HANDLERS: ReadonlyMap<string, (payload: unknown) => void> = new Map([
	[
		"note-echoed",
		(payload) => {
			// The demo handler: log and nothing more. Replace it with the
			// work your module actually does when an event arrives.
			console.log(JSON.stringify({ event: "note-echoed", payload }));
		},
	],
]);

/**
 * `GET /v1/notes/ping` — proof of life, no data. The surface declares it
 * (`surface.ts`) so the host's renderer can show it; keep the surface and
 * the routes in step, because the merge trusts the declaration.
 */
export async function ping(request: Request): Promise<Response> {
	return json(request, 200, {
		module: MODULE_NAME,
		version: MODULE_VERSION,
		harness_api: HARNESS_API,
		ok: true,
		time: new Date().toISOString(),
	});
}

/**
 * `POST /v1/notes/echo` — turns a body around without storing it. Exists
 * so the example exercises a validated write-shaped route end to end
 * (problem on a bad body, JSON on a good one) while staying honest about
 * storing nothing.
 */
export async function echo(request: Request): Promise<Response> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(await request.text());
	} catch {
		return problem(request, PROBLEMS.validationFailed, "body must be JSON");
	}
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!("text" in parsed) ||
		typeof (parsed as { text: unknown }).text !== "string"
	) {
		return problem(
			request,
			PROBLEMS.validationFailed,
			'body must be `{"text": "<string>"}`',
		);
	}
	const { text } = parsed as { text: string };
	// Nothing is stored — see the note on #153/#155 at the top of this file.
	return json(request, 200, { echoed: text, stored: false });
}

/**
 * One route table for the whole module: surface declaration (`surface.ts`)
 * and dispatch (`index.ts`) both read it, so they cannot drift apart.
 * Paths are relative to `/v1/<module name>` and must start with `/`, same
 * rule `Surface::validate` enforces on the host side.
 */
export interface ModuleRoute {
	readonly name: string;
	readonly method: string;
	readonly path: string;
	readonly handle: (request: Request) => Promise<Response>;
}

export const MODULE_ROUTES: readonly ModuleRoute[] = [
	{ name: "ping", method: "GET", path: "/ping", handle: ping },
	{ name: "echo", method: "POST", path: "/echo", handle: echo },
];

/**
 * `/v1/notes/<path>` → its route, or `undefined`. The prefix is stripped
 * here only after the entry point has matched it in full — a request for
 * `/v1/notes` (the module root) or `/v1/notes-nope` (a different prefix)
 * never reaches this table.
 */
export function matchRoute(
	method: string,
	pathRelativeToModule: string,
): ModuleRoute | undefined {
	return MODULE_ROUTES.find(
		(route) => route.method === method && route.path === pathRelativeToModule,
	);
}
