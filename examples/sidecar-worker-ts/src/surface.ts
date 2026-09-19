// The two self-descriptions the host reads over the mount, both served by
// this Worker under their own paths:
//
// - `GET /__health` — the probe. The host's probe (`probe_one_sidecar` in
//   crates/core/src/harness.rs) reads `x-harness-api` and
//   `x-harness-module` from the response headers, falls back to
//   `harness_api` and `modules[0].name`/`modules[0].version` in this body,
//   and reads `modules[*].tables` for collisions. The verdict it reports is
//   `ok` / `mismatch` / `unreachable` / `table-collision`, so a body that
//   disagrees with the stamps reads as a broken mount even when the Worker
//   answers.
// - `GET /__surface` — the renderer's view of the module. The host parses
//   the body into its `SurfaceDocument` (`sanitize_sidecar_document` in
//   crates/core/src/surface.rs) and rejects the whole document if the
//   contracts disagree, the mounted module is not named exactly once, or
//   the declaration breaks `Surface::validate`'s rules.

import { HARNESS_API } from "./http";
import { MODULE_EMITS, MODULE_NAME, MODULE_REQUIRES, MODULE_TABLES, MODULE_VERSION } from "./module";

/** SURFACE_API, as in `crates/core/src/surface.rs`. */
export const SURFACE_API = 1;

// ---------------------------------------------------------------------------
// The venture identity.
//
// **These values must match your host Worker's `src/harness.rs` exactly** —
// the same rule, and the same defaults, as the Rust template's. They are not
// checked by the host's merge today (it reads only the contracts and the
// module entry from a sidecar document), but the document cannot be parsed
// without them, and a renderer that ever does read them must find the same
// venture the host serves. One place, loud comment, like the Rust template.
// ---------------------------------------------------------------------------
export const VENTURE_NAME = "my-venture";
export const VENTURE_PUBLIC_URL = "https://api.example.ventures";
/** This Worker's own deployment environment, as the host's `env` reads. */
export const VENTURE_ENV = "dev";

/**
 * The `/__health` body. `sidecars: []` because this Worker serves one
 * module itself and mounts nothing; `tables` is the positive "we own no
 * tables" from `module.ts`, which is what keeps the probe's collision
 * check a check and not a coin flip.
 */
export function healthBody(): Record<string, unknown> {
	return {
		venture: VENTURE_NAME,
		env: VENTURE_ENV,
		harness_api: HARNESS_API,
		modules: [
			{
				name: MODULE_NAME,
				version: MODULE_VERSION,
				requires: MODULE_REQUIRES,
				optional: [],
				tables: MODULE_TABLES,
				emits: MODULE_EMITS,
			},
		],
		sidecars: [],
	};
}

// The wire shapes below mirror the serde types in
// `crates/core/src/surface.rs` field for field: an `Action` is `name`,
// `method`, `path`, `audience`, optional `input`, `outcome`, `captcha` —
// and deliberately nothing else. The host's `RoutePolicy` is not part of
// the document; `captcha` is the only protection signal on the wire.
//
// Audience spelling is kebab-case (`public`, `admin`, `link`, `subject`);
// an outcome is tagged with `kind`; a view is tagged with `kind`.

export interface SurfaceAction {
	name: string;
	method: string;
	path: string;
	audience: "public" | "admin" | "link" | "subject";
	input?: Record<string, unknown>;
	outcome: { kind: "accepted"; message: string } | { kind: "redirect" } | { kind: "json" };
	captcha: boolean;
}

export type SurfaceView =
	| { kind: "form"; action: string }
	| { kind: "status"; action: string }
	| { kind: "table"; source: string; columns: { key: string; label: string }[] };

/**
 * The module's surface, declared once here and checked against
 * `MODULE_ROUTES` by the tests: the same declaration the Rust template
 * derives from its `Surface` builder, minus the data-backed action.
 */
const ACTIONS: SurfaceAction[] = [
	{
		name: "ping",
		method: "GET",
		path: "/ping",
		audience: "public",
		outcome: { kind: "json" },
		captcha: false,
	},
	{
		name: "echo",
		method: "POST",
		path: "/echo",
		audience: "public",
		// A JSON Schema of the request body, the same shape schemars emits
		// for the Rust template's `#[derive(JsonSchema)]` body. It must
		// describe an object — the host refuses an input schema that does
		// not (`Surface::validate`). The `x-cf-*` keywords are the renderer's
		// field hints (crates/core/src/surface.rs); anything else is ignored.
		input: {
			type: "object",
			required: ["text"],
			properties: {
				text: {
					type: "string",
					"x-cf-label": "Text",
					"x-cf-widget": "textarea",
				},
			},
		},
		outcome: { kind: "json" },
		captcha: false,
	},
];

const VIEWS: SurfaceView[] = [
	{ kind: "form", action: "echo" },
	{ kind: "status", action: "ping" },
];

/**
 * The `/__surface` body. Exactly one module entry, named exactly the mount
 * name — a sidecar speaks for one module, and the host rejects a document
 * that names anything else. `venture` is required by the document shape
 * even though the merge discards it; see the venture block above.
 */
export function surfaceBody(): Record<string, unknown> {
	return {
		surface_api: SURFACE_API,
		harness_api: HARNESS_API,
		venture: {
			name: VENTURE_NAME,
			public_url: VENTURE_PUBLIC_URL,
		},
		modules: [
			{
				name: MODULE_NAME,
				version: MODULE_VERSION,
				actions: ACTIONS,
				views: VIEWS,
			},
		],
	};
}
