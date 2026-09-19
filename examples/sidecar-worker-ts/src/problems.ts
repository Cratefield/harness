// Error answers in the host's problem shape, so a caller sees one error
// format whether a route answered in-process or over the mount.
//
// The shape is RFC 9457 `application/problem+json`, exactly as
// `crates/core/src/problem.rs` emits it: `type` is a stable URI under
// `https://factory0.ventures/problems/`, `instance` is the request id, and
// the body never leaks internals. The slugs below are copied from
// `crates/core/src/problems.rs` — inventing a slug here would give the
// mounted prefix an error vocabulary the host has never heard of.

export interface ProblemDef {
	readonly slug: string;
	readonly status: number;
	readonly title: string;
}

/** The subset of the host's `SLUGS` this Worker can produce. */
export const PROBLEMS = {
	/** A body that did not deserialize (`SLUGS.validation_failed`). */
	validationFailed: {
		slug: "validation-failed",
		status: 400,
		title: "Request validation failed",
	},
	/** A bad or missing gateway token (`SLUGS.sidecar_unauthorized`). */
	sidecarUnauthorized: {
		slug: "sidecar-unauthorized",
		status: 401,
		title: "Unauthorized sidecar caller",
	},
	/** No route matched (`SLUGS.not_found`). */
	notFound: { slug: "not-found", status: 404, title: "Not found" },
	/**
	 * The fail-closed answer when the gateway is required but no usable
	 * secret is configured (`SLUGS.sidecar_unavailable`). A broken deploy
	 * answers loudly on every guarded request, never quietly 200.
	 */
	sidecarUnavailable: {
		slug: "sidecar-unavailable",
		status: 503,
		title: "Sidecar module unavailable",
	},
} as const satisfies Record<string, ProblemDef>;

// The problem `type` base, as in `crates/core/src/problem.rs`.
const PROBLEM_TYPE_BASE = "https://factory0.ventures/problems/";

import { stamped } from "./http";

/**
 * One problem answer. `instance` carries the request id so the trail is
 * findable across both Workers' logs, same as the host's own errors.
 */
export function problem(
	request: Request,
	def: ProblemDef,
	detail?: string,
): Response {
	const body: Record<string, unknown> = {
		type: `${PROBLEM_TYPE_BASE}${def.slug}`,
		title: def.title,
		status: def.status,
	};
	if (detail !== undefined) {
		body.detail = detail;
	}
	const requestId = request.headers.get("x-request-id");
	if (requestId !== null) {
		body.instance = requestId;
	}
	// `stamped`, not `json`: problems cross the mount like any other
	// response, and the host checks the stamps on forwarded errors too.
	return stamped(request, def.status, JSON.stringify(body), "application/problem+json");
}
