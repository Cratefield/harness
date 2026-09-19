// The Worker entry point — usually never touched, like the Rust template's
// `src/lib.rs`. One `fetch` handler: the gateway guard first, then the three
// mount routes, then the module's own routes.
//
// The three paths the host knows this Worker by (`/__health`, `/__surface`,
// `/__events`) and the module prefix (`/v1/notes/...`) are all served here.
// **The prefix is not stripped**: the host forwards the caller's original
// URI, so the module's routes live under this Worker's own
// `/v1/<module name>/...` and nothing is served at `/`.

import {
	enforceGateway,
	gatewayConfig,
	nowSecs,
	usableGatewaySecret,
	verifyGatewayToken,
} from "./gateway";
import { json } from "./http";
import { EVENT_HANDLERS, MODULE_NAME, matchRoute } from "./module";
import { PROBLEMS, problem } from "./problems";
import { healthBody, surfaceBody } from "./surface";

/**
 * The values this Worker reads from the deployment environment. Put secrets
 * in `wrangler secret put` (see `.dev.vars.example` for local development).
 *
 * Deliberately absent: the host's `HARNESS_SECRET`. A sidecar that received
 * it could forge the host's confirm and unsubscribe links; the one shared
 * value across the boundary is `SIDECAR_GATEWAY_SECRET` (issue #131).
 */
export interface Env {
	/** `1`/`true`/`yes`/`on` (case-insensitive) closes the gateway gate. */
	SIDECAR_REQUIRE_GATEWAY?: string;
	/** The secret the host mints gateway stamps with; both sides hold it. */
	SIDECAR_GATEWAY_SECRET?: string;
}

/**
 * The one thing this Worker asks of the runtime context. The real
 * `ExecutionContext` carries more (and the runtime passes one regardless);
* naming the need keeps the tests' stub honest instead of hand-mocking a
 * runtime interface it does not use.
 */
export interface EventContext {
	waitUntil(promise: Promise<unknown>): void;
}

/** The module mount prefix, derived once from the module's own name. */
const MOUNT_PREFIX = `/v1/${MODULE_NAME}`;

export default {
	async fetch(request: Request, env: Env, ctx: EventContext): Promise<Response> {
		const path = new URL(request.url).pathname;

		// The guard runs before any route and answers by itself when it
		// refuses (401) or when the deploy is broken (503, fail closed).
		const refusal = await enforceGateway(request, path, gatewayConfig(env));
		if (refusal !== null) {
			return refusal;
		}

		// Probes and the renderer's merge read these; the guard never closes
		// them (probes must probe).
		if (request.method === "GET" && path === "/__health") {
			return json(request, 200, healthBody());
		}
		if (request.method === "GET" && path === "/__surface") {
			return json(request, 200, surfaceBody());
		}
		if (request.method === "POST" && path === "/__events") {
			// The events route exists only where a usable gateway secret can
			// verify the host's stamp — "absent is safer than open"
			// (crates/core/src/harness.rs, `inbound_events_route`). Without
			// the secret there is no way to tell the host's forward from
			// anyone else's `POST`, so this Worker answers 404 like any
			// other unrouted path rather than serving the route open.
			const secret = usableGatewaySecret(gatewayConfig(env));
			if (secret !== null) {
				return acceptEvent(request, secret, ctx);
			}
		}

		// The module itself. `/v1/notes` (no trailing segment) and
		// `/v1/notes-nope` (a different prefix) fall through to 404 — the
		// prefix must match in full before any route table is consulted.
		if (path === MOUNT_PREFIX || path.startsWith(`${MOUNT_PREFIX}/`)) {
			const route = matchRoute(request.method, path.slice(MOUNT_PREFIX.length));
			if (route !== undefined) {
				return route.handle(request);
			}
		}

		return problem(request, PROBLEMS.notFound);
	},
};

/**
 * `POST /__events` — the sidecar half of event forwarding (ADR 0017).
 *
 * Answers `202` immediately and hands the handlers to `ctx.waitUntil`, so
 * they run **after** the response: a slow subscriber must not hold the
 * host's forward open, and a status that claimed the work was done would be
 * the one lie this route cannot afford. The host reads `202` as "accepted
 * for delivery", never as "done".
 *
 * The body is the host's `EventEnvelope` (`crates/core/src/sidecar.rs`):
 * `{"event": "<name>", "payload": <any JSON>}`, both fields required,
 * unknown fields ignored — the same leniency serde's default gives the
 * host's own inbound route. Inbound only, delivered at most once, never
 * retried, no queue.
 *
 * The stamp check here rides on the **secret**, not on
 * `SIDECAR_REQUIRE_GATEWAY`, exactly as `events_inbound`
 * (crates/core/src/sidecar.rs) verifies whenever it holds a gateway signer:
 * an event trigger a stranger can reach is a payload a handler trusts,
 * with or without the `/v1` gate.
 */
async function acceptEvent(
	request: Request,
	secret: string,
	ctx: EventContext,
): Promise<Response> {
	// The host always stamps its forwards; anything unstamped is not the
	// host, and a stamp that does not verify gets the same answer.
	const presented = request.headers.get("x-harness-gateway");
	const grant =
		presented !== null ? await verifyGatewayToken(presented, secret, nowSecs()) : null;
	if (grant === null) {
		return problem(request, PROBLEMS.sidecarUnauthorized);
	}

	const malformed = () =>
		problem(
			request,
			PROBLEMS.validationFailed,
			'body must be `{"event": "<name>", "payload": …}`',
		);

	let parsed: unknown;
	try {
		parsed = JSON.parse(await request.text());
	} catch {
		return malformed();
	}
	if (typeof parsed !== "object" || parsed === null) {
		return malformed();
	}
	const envelope = parsed as Record<string, unknown>;
	if (
		typeof envelope.event !== "string" ||
		envelope.event.length === 0 ||
		!("payload" in envelope)
	) {
		return malformed();
	}

	// One module, so at most one local handler per event. Zero handlers is
	// logged-and-counted, not a quiet success — the same refusal to be
	// silent the host's inbound route has (`events_inbound`).
	const handler = EVENT_HANDLERS.get(envelope.event);
	const handlers = handler === undefined ? 0 : 1;
	if (handler !== undefined) {
		const payload = envelope.payload;
		ctx.waitUntil(
			(async () => {
				try {
					handler(payload);
				} catch (error) {
					console.error(
						JSON.stringify({
							message: "event handler failed",
							event: envelope.event,
							error: error instanceof Error ? error.message : String(error),
						}),
					);
				}
			})(),
		);
	}

	return json(request, 202, { accepted: handlers > 0, handlers });
}
