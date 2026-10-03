// A minimal in-process auth-core: it serves a JWKS and a token endpoint over
// an injected `fetch`, and mints real ES256 tokens with WebCrypto. The point
// is to exercise the client against the shapes the real IdP produces, without
// a network. There is no discovery route: the client derives its endpoints
// from the configured issuer.

import { b64urlEncode, utf8Encode } from '../src/base64url.js';
import { createAuth, type Auth, type AuthConfig } from '../src/index.js';

export interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

export interface FakeIdpOptions {
  issuer?: string;
  clientId?: string;
  kid?: string;
}

export class FakeIdp {
  readonly issuer: string;
  readonly clientId: string;
  kid: string;
  privateKey!: CryptoKey;
  publicJwk!: JsonWebKey;
  readonly calls: RecordedCall[] = [];

  /** Token endpoint status; a non-200 refuses without minting. */
  tokenStatus = 200;
  /** Refuse an authorization_code exchange with a 400. */
  refuseCode = false;
  /** Refuse a refresh_token grant with a 400 (the revoked/exhausted case). */
  refuseRefresh = false;
  /** Claims merged over the defaults in the next access token. */
  accessClaims: Record<string, unknown> | null = null;
  /** Sign with this key instead of the real one (forged-signature tests). */
  signingKey: CryptoKey | null = null;
  /** Put this kid in the header instead of the real one. */
  signingKid: string | null = null;
  /** Extra (possibly bogus) keys published in the JWKS. */
  extraJwks: JsonWebKey[] = [];
  jwksStatus = 200;
  jwksCacheControl: string | null = 'public, max-age=300';
  /** `expires_in` advertised by the token endpoint. */
  accessExpiresIn = 600;
  /** Merged over the token response, to emit malformed or hostile bodies. */
  tokenBodyOverride: Record<string, unknown> | null = null;

  private refreshCounter = 0;

  private constructor(opts: FakeIdpOptions) {
    this.issuer = opts.issuer ?? 'https://auth.example';
    this.clientId = opts.clientId ?? 'client_abc';
    this.kid = opts.kid ?? 'key-1';
  }

  static async create(opts: FakeIdpOptions = {}): Promise<FakeIdp> {
    const idp = new FakeIdp(opts);
    await idp.generate();
    return idp;
  }

  get jwksUrl(): string {
    return `${this.issuer}/.well-known/jwks.json`;
  }

  get authorizeUrl(): string {
    return `${this.issuer}/v1/auth-core/authorize`;
  }

  get tokenUrl(): string {
    return `${this.issuer}/v1/auth-core/token`;
  }

  get logoutUrl(): string {
    return `${this.issuer}/v1/auth-core/logout`;
  }

  get fetch(): typeof fetch {
    return (input, init) => this.handle(input, init);
  }

  /** Generate a fresh ES256 key pair and publish it as the JWKS key. */
  async generate(): Promise<void> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    this.privateKey = pair.privateKey;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
    this.publicJwk = { ...jwk, kid: this.kid, alg: 'ES256', use: 'sig' };
  }

  /** Rotate to a new key id, as the IdP does on a schedule. */
  async rotate(kid: string): Promise<void> {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    this.privateKey = pair.privateKey;
    const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
    this.publicJwk = { ...jwk, kid, alg: 'ES256', use: 'sig' };
    this.kid = kid;
  }

  defaultClaims(): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1000);
    return { iss: this.issuer, sub: 'user_1', aud: this.clientId, exp: now + 600, iat: now, sid: 'sess_1', amr: ['pwd'] };
  }

  /** Sign a JWT, defaulting to the live key and kid. */
  async sign(
    claims: Record<string, unknown>,
    opts: { kid?: string; key?: CryptoKey; alg?: string; typ?: string } = {},
  ): Promise<string> {
    const kid = opts.kid ?? this.kid;
    const header = b64urlEncode(utf8Encode(JSON.stringify({ alg: opts.alg ?? 'ES256', typ: opts.typ ?? 'at+jwt', kid })));
    const payload = b64urlEncode(utf8Encode(JSON.stringify(claims)));
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        opts.key ?? this.privateKey,
        utf8Encode(`${header}.${payload}`),
      ),
    );
    return `${header}.${payload}.${b64urlEncode(signature)}`;
  }

  /** A ready-to-use access token with the default (valid) claims. */
  async mintAccessToken(overrides: Record<string, unknown> = {}): Promise<string> {
    return this.sign({ ...this.defaultClaims(), ...overrides });
  }

  /** The parameters of the most recent token request, or `null`. */
  lastTokenParams(): URLSearchParams | null {
    for (let i = this.calls.length - 1; i >= 0; i -= 1) {
      const call = this.calls[i]!;
      if (call.url === this.tokenUrl) return new URLSearchParams(call.body ?? '');
    }
    return null;
  }

  /** How many requests hit the JWKS endpoint. */
  jwksFetches(): number {
    return this.calls.filter((call) => call.url === this.jwksUrl).length;
  }

  private async handle(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? (typeof input === 'object' && !(input instanceof URL) ? input.method : 'GET');
    const body = typeof init?.body === 'string' ? init.body : null;
    this.calls.push({ url, method, body });

    if (url === this.jwksUrl) {
      if (this.jwksStatus !== 200) return new Response('nope', { status: this.jwksStatus });
      return json({ keys: [this.publicJwk, ...this.extraJwks] }, this.jwksCacheControl);
    }
    if (url === this.tokenUrl) return this.handleToken(body);
    return new Response('not found', { status: 404 });
  }

  private async handleToken(body: string | null): Promise<Response> {
    if (this.tokenStatus !== 200) return refused(this.tokenStatus);
    const params = new URLSearchParams(body ?? '');
    const grant = params.get('grant_type');
    if (grant === 'authorization_code' && !this.refuseCode) return this.issue();
    if (grant === 'refresh_token' && !this.refuseRefresh) return this.issue();
    return refused(400);
  }

  private async issue(): Promise<Response> {
    this.refreshCounter += 1;
    const claims = { ...this.defaultClaims(), ...(this.accessClaims ?? {}) };
    const accessToken = await this.sign(claims, {
      kid: this.signingKid ?? undefined,
      key: this.signingKey ?? undefined,
    });
    return json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessExpiresIn,
      refresh_token: `rt_${this.refreshCounter}`,
      ...(this.tokenBodyOverride ?? {}),
    });
  }
}

function json(body: unknown, cacheControl: string | null): Response {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (cacheControl) headers['Cache-Control'] = cacheControl;
  return new Response(JSON.stringify(body), { headers });
}

function refused(status: number): Response {
  return new Response(JSON.stringify({ type: 'about:blank', title: 'auth/token-request-refused', status }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

/** The three pieces of a running test: the IdP, the client and the config. */
export interface Harness {
  idp: FakeIdp;
  auth: Auth;
  config: AuthConfig;
}

/**
 * Build a client pointing at a fake IdP.
 *
 * `cookieSecret` can be overridden so a second harness can prove that one
 * instance refuses another instance's sealed state.
 */
export async function createHarness(
  opts: { config?: Partial<AuthConfig>; idp?: FakeIdpOptions } = {},
): Promise<Harness> {
  const idp = await FakeIdp.create(opts.idp);
  const config: AuthConfig = {
    issuer: idp.issuer,
    clientId: idp.clientId,
    redirectUri: 'https://app.example/auth/callback',
    cookieSecret: 'test-cookie-secret-that-is-long-enough',
    fetch: idp.fetch,
    ...opts.config,
  };
  return { idp, auth: createAuth(config), config };
}
