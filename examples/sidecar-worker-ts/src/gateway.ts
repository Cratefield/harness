// The gateway guard, sidecar side (issue #131, `crates/core/src/sidecar.rs`).
//
// With `SIDECAR_REQUIRE_GATEWAY` set truthy (`1`/`true`/`yes`/`on`,
// case-insensitive — the same reading the host's `truthy` gives), every
// guarded request must carry a token the host minted with the shared
// `SIDECAR_GATEWAY_SECRET`:
//
// - guarded: everything under `/v1/`, plus exactly `/__surface` and exactly
//   `/__events`;
// - open: `/__health`, `/ui`, `/.well-known` — probes must probe, and the
//   deployment's own pages are its own surface;
// - a token that is missing, malformed, wrong-purpose, expired or tampered
//   is a `401`;
// - requiring the gateway **without a usable secret is a broken deploy**, and
//   it answers a loud `503` on every guarded request — never a quiet `200`
//   that would serve the open internet.
//
// The host mints one token per forwarded request (lifetime 120 s) and sends
// it in `x-harness-gateway`. This Worker never mints: minting is the host's
// half of the boundary.

import { PROBLEMS, problem } from "./problems";
import type { Env } from "./index";

/** As in `crates/core/src/signer.rs`: shorter is refused, not truncated. */
export const MIN_SECRET_BYTES = 32;

/** `GATEWAY_PURPOSE` (crates/core/src/sidecar.rs). */
export const GATEWAY_PURPOSE = "sidecar-gateway";
/**
 * `GATEWAY_ADMIN_PURPOSE`: the host mints it only after its own admin check
 * passed. This Worker has no admin plane to unlock (no data access yet, no
 * admin routes), so the distinction is carried but unused — the grant below
 * still reports it, because a future admin route must be able to demand it.
 */
export const GATEWAY_ADMIN_PURPOSE = "sidecar-gateway-admin";

/** `truthy` in crates/core/src/sidecar.rs, applied to the same values. */
function truthy(raw: string | undefined): boolean {
	return raw !== undefined && ["1", "true", "yes", "on"].includes(raw.toLowerCase());
}

export interface GatewayConfig {
	/** Whether the gate is closed at all. */
	require: boolean;
	/** The shared secret; `require` without a usable one fails closed. */
	secret: string | undefined;
}

export function gatewayConfig(env: Env): GatewayConfig {
	return {
		require: truthy(env.SIDECAR_REQUIRE_GATEWAY),
		secret: env.SIDECAR_GATEWAY_SECRET,
	};
}

/**
 * The shared secret when it is usable: present, not blank, and at least 32
 * bytes — the same test `gateway_signer` applies before it builds a ring
 * (crates/core/src/sidecar.rs). `null` means this deployment has no gateway
 * verification key: for the guard that is a broken deploy (fail closed, 503);
 * for `/__events` it means there is no way to tell the host's forward from
 * anyone else's `POST`, so the route does not exist (see index.ts).
 */
export function usableGatewaySecret(config: GatewayConfig): string | null {
	const secret = config.secret;
	// Blankness is judged on the trimmed value but verification uses the raw
	// bytes, so a secret with padding whitespace stays one secret.
	if (secret === undefined || secret.trim().length === 0) return null;
	if (new TextEncoder().encode(secret).length < MIN_SECRET_BYTES) return null;
	return secret;
}

/** True for the paths the guard closes: `/v1/*`, exactly `/__surface`, exactly `/__events`. */
export function isGuardedPath(path: string): boolean {
	return path.startsWith("/v1/") || path === "/__surface" || path === "/__events";
}

// ------------------------------------------------------------- base64url
//
// The token wire format is `base64url(json) "." base64url(mac)`, no
// padding — the host signs and parses with `URL_SAFE_NO_PAD`
// (crates/core/src/signer.rs). Padding and non-canonical trailing bits are
// refused, mirroring the `base64` crate: a re-encoded payload must never
// slide a MAC past a parser.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));

function b64urlEncode(bytes: Uint8Array): string {
	let out = "";
	for (let i = 0; i < bytes.length; i += 3) {
		const b0 = bytes[i] ?? 0;
		const b1 = bytes[i + 1];
		const b2 = bytes[i + 2];
		out += ALPHABET[b0 >> 2];
		out += ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
		if (b1 === undefined) break;
		out += ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
		if (b2 === undefined) break;
		out += ALPHABET[b2 & 0x3f];
	}
	return out;
}

function b64urlDecode(text: string): Uint8Array | null {
	if (text.includes("=")) return null; // the host never pads
	let buffer = 0;
	let bits = 0;
	const out: number[] = [];
	for (const char of text) {
		const value = LOOKUP.get(char);
		if (value === undefined) return null;
		buffer = (buffer << 6) | value;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push((buffer >> bits) & 0xff);
		}
	}
	// Canonical trailing bits only: what the `base64` crate accepts, this
	// accepts, so one encoding of a payload has one MAC.
	if (bits >= 6 || (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0)) return null;
	return new Uint8Array(out);
}

// ------------------------------------------------------------------ token

interface TokenPayload {
	purpose: string;
	subject: string;
	/** Seconds; absent means "no expiry of its own" — the host's policy always sets one. */
	exp?: number;
	iss?: string;
	kid: string;
}

async function hmacSha256(secret: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		secret as BufferSource,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = await crypto.subtle.sign("HMAC", key, message as BufferSource);
	return new Uint8Array(mac);
}

/**
 * Compares two MACs without leaking where they first differ: the loop runs
 * over the whole input and accumulates, never exits early.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	const length = Math.max(a.length, b.length);
	let diff = a.length ^ b.length;
	for (let i = 0; i < length; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}
	return diff === 0;
}

function parsePayload(json: unknown): TokenPayload | null {
	if (typeof json !== "object" || json === null) return null;
	const { purpose, subject, kid } = json as Record<string, unknown>;
	if (typeof purpose !== "string" || typeof subject !== "string") return null;
	if (typeof kid !== "string" || kid.length === 0 || kid.length > 32) return null;
	const record = json as Record<string, unknown>;
	if (record.exp !== undefined && (typeof record.exp !== "number" || !Number.isSafeInteger(record.exp) || record.exp < 0)) {
		return null;
	}
	if (record.iss !== undefined && typeof record.iss !== "string") return null;
	const payload: TokenPayload = { purpose, subject, kid };
	if (record.exp !== undefined) payload.exp = record.exp;
	if (record.iss !== undefined) payload.iss = record.iss;
	return payload;
}

export type GatewayGrant = { admin: boolean };

/**
 * Verifies one presented token. `null` means "not ours, or expired"; a
 * grant carries whether the host asserted its admin gate.
 *
 * What is checked and what is deliberately not:
 *
 * - the MAC covers **the exact encoded payload bytes as presented** — not a
 *   re-serialization — so a padded or re-ordered re-encoding cannot reuse a
 *   MAC (crates/core/src/signer.rs, `verify`);
 * - the `kid` must parse, as the host parses it, but it does not select the
 *   key: one shared secret, one live key, and the MAC decides;
 * - `purpose` must be one of the two gateway purposes; any other purpose —
 *   a confirm link, an admin session — cannot pass, and vice versa;
 * - `exp` is refused once `now >= exp`, the same instant the host refuses;
 * - `subject` and `iss` are **not** checked: the subject (the mounted
 *   module name) travels for forensics only, and a token is valid at any
 *   sidecar sharing the secret — the host's gateway signer is not
 *   venture-bound, so there is no `iss` to compare.
 */
export async function verifyGatewayToken(
	token: string,
	secret: string,
	nowSecs: number,
): Promise<GatewayGrant | null> {
	const dot = token.indexOf(".");
	if (dot === -1 || token.indexOf(".", dot + 1) !== -1) return null;
	const encodedPayload = token.slice(0, dot);
	const encodedMac = token.slice(dot + 1);
	if (encodedPayload.length === 0 || encodedMac.length === 0) return null;

	const mac = b64urlDecode(encodedMac);
	if (mac === null || mac.length !== 32) return null;
	const payloadBytes = b64urlDecode(encodedPayload);
	if (payloadBytes === null) return null;

	// MAC over the presented substring's exact bytes — `encoded_payload`
	// itself, never a decode/encode round trip. The host signs
	// `Self::mac(&signing.secret, &encoded)` where `encoded` is the
	// base64url *text* (crates/core/src/signer.rs, `sign` and `verify`);
	// hashing the decoded JSON here would reject every host-minted token.
	const expected = await hmacSha256(
		new TextEncoder().encode(secret),
		new TextEncoder().encode(encodedPayload),
	);
	if (!timingSafeEqual(expected, mac)) return null;

	let parsed: unknown;
	try {
		parsed = JSON.parse(new TextDecoder().decode(payloadBytes));
	} catch {
		return null;
	}
	const payload = parsePayload(parsed);
	if (payload === null) return null;

	if (payload.purpose === GATEWAY_ADMIN_PURPOSE) {
		if (payload.exp !== undefined && nowSecs >= payload.exp) return null;
		return { admin: true };
	}
	if (payload.purpose === GATEWAY_PURPOSE) {
		if (payload.exp !== undefined && nowSecs >= payload.exp) return null;
		return { admin: false };
	}
	return null;
}

/**
 * The guard the entry point runs before any route. Returns the refusal, or
 * `null` to let the request through.
 */
export async function enforceGateway(
	request: Request,
	path: string,
	config: GatewayConfig,
): Promise<Response | null> {
	if (!config.require || !isGuardedPath(path)) return null;

	// Fail closed: require without a usable secret (missing, blank, or
	// shorter than the host accepts) is a broken deploy, and the answer is
	// the host's `sidecar-unavailable` problem on every guarded request —
	// with the exact detail the host's own guard logs (sidecar.rs).
	const secret = usableGatewaySecret(config);
	if (secret === null) {
		return problem(
			request,
			PROBLEMS.sidecarUnavailable,
			"this sidecar requires a gateway token but no gateway secret is configured",
		);
	}

	const presented = request.headers.get("x-harness-gateway");
	const grant =
		presented !== null ? await verifyGatewayToken(presented, secret, nowSecs()) : null;
	if (grant === null) {
		return problem(request, PROBLEMS.sidecarUnauthorized);
	}
	// The admin grant would re-materialize this Worker's own admin token for
	// admin paths on a sidecar that has one (sidecar.rs `gateway_guard`);
	// this Worker has no admin plane, so the grant is proof enough.
	return null;
}

/** Unix seconds — the unit `exp` travels in (`signer.rs`'s `now_secs`). */
export function nowSecs(): number {
	return Math.floor(Date.now() / 1000);
}
