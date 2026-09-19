// The response envelope every route of this Worker answers with.
//
// The host copies back only the headers of `FORWARDED_RESPONSE_HEADERS`
// (crates/core/src/sidecar.rs) — an allowlist, not a denylist. Everything
// else stops at the host, which is why this module refuses to set anything
// outside it: a header this Worker sets and the host drops is a bug that
// never reproduces locally.
//
// **`set-cookie` is dropped in particular** — a sidecar that could plant
// cookies on the venture's origin would own the caller's session on a
// surface it does not serve (issue #131). Cache what you need inside the
// Worker; there is no cookie jar across this boundary.
export const RESPONSE_HEADER_ALLOWLIST: readonly string[] = [
	"content-type",
	"location",
	"cache-control",
	"etag",
	"last-modified",
	"vary",
	"retry-after",
	"content-disposition",
	"x-harness-api",
	"x-harness-module",
	"x-request-id",
];

// The contract version stamped on every response and checked by the host on
// every forwarded answer — not cached at cold start, because an isolate
// outlives a sidecar redeploy (ADR 0009). `crates/core/src/module.rs`.
export const HARNESS_API = 1;

// Import cycle, deliberately: `module.ts` answers through this envelope and
// this envelope stamps the module's name. Both bindings are read only inside
// function bodies, never at module-evaluation time, so the cycle is inert.
import { MODULE_NAME } from "./module";

/**
 * Wraps a body in the envelope the mount contract requires: the two stamp
 * headers on every response, and the caller's request id echoed back so one
 * trail reaches both Workers' logs.
 *
 * The request id is echoed only when the caller brought one — the host
 * stamps every forwarded request with `x-request-id`
 * (crates/core/src/sidecar.rs), so a request without one did not come
 * through the mount.
 */
export function stamped(
	request: Request,
	status: number,
	body: string,
	contentType: string,
): Response {
	const headers = new Headers({ "content-type": contentType });
	headers.set("x-harness-api", String(HARNESS_API));
	headers.set("x-harness-module", MODULE_NAME);
	const requestId = request.headers.get("x-request-id");
	if (requestId !== null) {
		headers.set("x-request-id", requestId);
	}
	return new Response(body, { status, headers });
}

/** JSON answer with the stamp envelope. */
export function json(request: Request, status: number, body: unknown): Response {
	return stamped(request, status, JSON.stringify(body), "application/json");
}
