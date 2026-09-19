// Minting gateway stamps in the tests, with the same WebCrypto the Worker
// verifies with. No pre-baked fixtures: a token that is minted here and
// then accepted over there is the round trip actually proven.
//
// Wire format, exactly as `crates/core/src/signer.rs` writes it:
// `base64url(json) "." base64url(mac)` — unpadded, and the MAC covers the
// **exact encoded payload bytes** (the base64url text, not the raw JSON).

/** 32 bytes exactly: the floor, and a reminder that shorter is a 503. */
export const SECRET = "gateway-secret-for-tests-0123456789abcdef";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64url(bytes: Uint8Array): string {
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

async function hmacSha256(secret: string, message: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

export function nowSecs(): number {
	return Math.floor(Date.now() / 1000);
}

/**
 * Mints one token. The payload field order — `purpose`, `subject`, `exp`,
 * `kid` — is the host signer's serialization order; it does not matter for
 * verification (the MAC covers the bytes as presented), it only makes the
 * tokens here byte-comparable with a host-minted one.
 */
export async function mintToken(
	payload: {
		purpose: string;
		subject?: string;
		exp?: number;
		iss?: string;
		kid?: string;
	},
	secret: string = SECRET,
): Promise<string> {
	const body: Record<string, unknown> = {
		purpose: payload.purpose,
		subject: payload.subject ?? "notes",
	};
	if (payload.exp !== undefined) body.exp = payload.exp;
	if (payload.iss !== undefined) body.iss = payload.iss;
	body.kid = payload.kid ?? "cur";
	const encodedPayload = b64url(new TextEncoder().encode(JSON.stringify(body)));
	const mac = await hmacSha256(secret, encodedPayload);
	return `${encodedPayload}.${b64url(mac)}`;
}

/** A live, plain-purpose stamp — what the host sends on every forward. */
export function mintValidToken(secret: string = SECRET): Promise<string> {
	return mintToken(
		{ purpose: "sidecar-gateway", exp: nowSecs() + 120 },
		secret,
	);
}
