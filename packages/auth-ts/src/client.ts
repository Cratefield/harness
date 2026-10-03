// createAuth: the sign-in, callback, verify, refresh and sign-out flow for a
// Cratefield auth-core application, as a set of request/response helpers a
// Worker route calls into.
//
// Create one per isolate at module scope. All the state (the JWKS cache and
// the refresh single-flight maps) lives on the returned object, so a
// per-request `createAuth` would re-fetch the key set on every request.

import { FETCH_TIMEOUT_MS, sanitizeReturnTo, timingSafeEqual } from './util.js';
import { codeChallengeS256, createCodeVerifier } from './pkce.js';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  REFRESH_MAX_AGE_SECS,
  STATE_COOKIE,
  STATE_MAX_AGE_SECS,
  appendSetCookie,
  deleteCookie,
  readCookie,
  sealState,
  serializeCookie,
  unsealState,
} from './cookies.js';
import { JwksCache, verifyToken, type Claims } from './jwt.js';
import { b64urlEncode } from './base64url.js';

/** Configuration for {@link createAuth}. */
export interface AuthConfig {
  /** The issuer URL, exactly as it appears in every token's `iss`. */
  issuer: string;
  /** This app's registered client id; every token's `aud` must equal it. */
  clientId: string;
  /** Confidential clients only; sent as `client_secret_post` in the token body. */
  clientSecret?: string;
  /** The registered callback URL; must match the one used at authorize. */
  redirectUri: string;
  /** Seals the state cookie. Must be at least 32 characters. */
  cookieSecret: string;
  /** Where the browser goes after sign-out; must be registered with the IdP. */
  postLogoutRedirectUri?: string;
  /** Injectable for tests; defaults to the ambient `fetch`. */
  fetch?: typeof fetch;
}

/** The result of a refresh attempt. */
export interface RefreshResult {
  /** The new token's claims, or `null` when the session could not be renewed. */
  claims: Claims | null;
  /** The new access token, present only on success. */
  accessToken?: string;
  /** `Set-Cookie` headers to apply to the response (the new or cleared session). */
  headers: Headers;
}

/** The auth operations, bound to one issuer and one client. */
export interface Auth {
  startSignIn(opts?: { returnTo?: string; uiLocales?: string }): Promise<{ url: string; headers: Headers }>;
  handleCallback(request: Request): Promise<Response>;
  verify(input: Request | string): Promise<Claims | null>;
  refresh(request: Request): Promise<RefreshResult>;
  signOut(): Promise<Response>;
}

/**
 * How long a successful refresh stays valid for requests still carrying the
 * old token.
 *
 * The grace hands the rotated pair to anyone presenting the old token inside
 * the window, which suppresses the IdP's reuse detection for that window — a
 * deliberate trade against false-positive session revocation from requests
 * the browser sent before it stored the rotated cookie. Kept short (10 s) so
 * the blind spot stays smaller than the round trip it exists to cover.
 */
const REFRESH_GRACE_MS = 10_000;

/** Default access-token lifetime when the token response omits `expires_in`. */
const DEFAULT_EXPIRES_IN = 600;

/** Longest access-cookie `Max-Age` accepted from the IdP, seconds. */
const MAX_ACCESS_COOKIE_SECS = 3600;

/** Minimum cookie secret length; the key is a SHA-256 of it either way. */
const MIN_COOKIE_SECRET_CHARS = 32;

/**
 * The auth-core module path. Endpoints are derived from the configured issuer
 * rather than fetched from the discovery document: pinning them means a
 * tampered or spoofed discovery response cannot aim the authorizer or the
 * token redeemer at another host, nor substitute a JWKS. Mirrors the Rust
 * client, which composes its `jwks_uri` the same way.
 */
const MODULE_PREFIX = '/v1/auth-core';

/**
 * The characters allowed in a token we are about to write into `Set-Cookie`.
 *
 * Tokens are base64url-ish in practice; this rejects anything that could
 * break out of the cookie header (CR/LF, `;`, whitespace) before it is set.
 */
const TOKEN_CHARSET = /^[A-Za-z0-9._~+/=-]+$/;

/** What a refresh stores before headers are rebuilt per caller. */
interface StoredRefresh {
  claims: Claims | null;
  accessToken?: string;
  cookies: string[];
}

/** Create the auth helper. Throws on a configuration error, at startup. */
export function createAuth(config: AuthConfig): Auth {
  return new AuthClient(config);
}

class AuthClient implements Auth {
  private readonly fetchImpl: typeof fetch;
  private readonly authorizeUrl: string;
  private readonly tokenUrl: string;
  private readonly logoutUrl: string;
  private readonly jwksUri: string;
  private readonly jwks: JwksCache;
  /**
   * In-flight refresh per old refresh token, so N concurrent requests that
   * all still carry the same rotated token make one call to the IdP rather
   * than N — the IdP revokes a session when a consumed token is replayed.
   */
  private readonly refreshInflight = new Map<string, Promise<StoredRefresh>>();
  /**
   * Recently succeeded refreshes, keyed by the *old* refresh token. Requests
   * the browser sent before it processed the new `Set-Cookie` still carry the
   * old value; replaying it would revoke the session, so they get the result
   * already produced instead. Cross-isolate races cannot be solved here; the
   * IdP is the one place that sees them (see the WEB-APPS doc).
   */
  private readonly refreshGrace = new Map<string, { stored: StoredRefresh; expiresAtMs: number }>();

  constructor(private readonly config: AuthConfig) {
    if (config.cookieSecret.length < MIN_COOKIE_SECRET_CHARS) {
      throw new Error(`cookieSecret must be at least ${MIN_COOKIE_SECRET_CHARS} characters`);
    }
    // The issuer is compared byte-for-byte against the `iss` claim, so it must
    // be the exact, slash-less base URL; a trailing slash would also double up
    // in the derived endpoints.
    let issuerUrl: URL;
    try {
      issuerUrl = new URL(config.issuer);
    } catch {
      throw new Error('issuer must be an absolute http(s) URL');
    }
    if (issuerUrl.protocol !== 'https:' && issuerUrl.protocol !== 'http:') {
      throw new Error('issuer must be an absolute http(s) URL');
    }
    if (config.issuer.endsWith('/')) {
      throw new Error('issuer must not end with a slash');
    }
    this.fetchImpl = config.fetch ?? fetch;
    this.authorizeUrl = `${config.issuer}${MODULE_PREFIX}/authorize`;
    this.tokenUrl = `${config.issuer}${MODULE_PREFIX}/token`;
    this.logoutUrl = `${config.issuer}${MODULE_PREFIX}/logout`;
    this.jwksUri = `${config.issuer}/.well-known/jwks.json`;
    this.jwks = new JwksCache(this.fetchImpl);
  }

  async startSignIn(opts: { returnTo?: string; uiLocales?: string } = {}): Promise<{
    url: string;
    headers: Headers;
  }> {
    const nowMs = Date.now();

    const state = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const verifier = createCodeVerifier();
    const challenge = await codeChallengeS256(verifier);
    const sealed = await sealState(
      {
        state,
        verifier,
        returnTo: sanitizeReturnTo(opts.returnTo),
        exp: Math.floor(nowMs / 1000) + STATE_MAX_AGE_SECS,
      },
      this.config.cookieSecret,
    );

    const url = new URL(this.authorizeUrl);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);
    // The IdP ignores parameters it does not know, so a caller-chosen locale
    // can ride along harmlessly.
    if (opts.uiLocales) url.searchParams.set('ui_locales', opts.uiLocales);

    const headers = new Headers();
    appendSetCookie(headers, serializeCookie(STATE_COOKIE, sealed, STATE_MAX_AGE_SECS));
    return { url: url.toString(), headers };
  }

  async handleCallback(request: Request): Promise<Response> {
    const nowMs = Date.now();
    const url = new URL(request.url);

    const sealed = readCookie(request, STATE_COOKIE);
    const payload = sealed ? await unsealState(sealed, this.config.cookieSecret) : null;
    if (!payload) return refusal();
    if (payload.exp < Math.floor(nowMs / 1000)) return refusal();

    const queryState = url.searchParams.get('state');
    if (typeof queryState !== 'string' || !timingSafeEqual(queryState, payload.state)) {
      return refusal();
    }
    // The IdP was asked to deny (or had an error). Treat as a refusal, not a
    // crash, and never echo its `error_description` to the browser.
    if (url.searchParams.has('error')) return refusal();
    const code = url.searchParams.get('code');
    if (!code) return refusal();

    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', this.config.redirectUri);
    body.set('code_verifier', payload.verifier);
    body.set('client_id', this.config.clientId);
    if (this.config.clientSecret) body.set('client_secret', this.config.clientSecret);

    let tokens: { accessToken: string; refreshToken: string; expiresIn: number };
    try {
      const response = await this.postToken(this.tokenUrl, body);
      // A clean 4xx is the IdP refusing this code: a refusal. A 5xx, a
      // timeout or a malformed body is an outage, not the user's mistake —
      // answer 502, but still clear the one-shot state cookie so a reload
      // starts a fresh sign-in (the code is single-use and already spent).
      if (!response.ok) return response.status >= 500 ? unavailable() : refusal();
      tokens = await this.readTokens(response);
    } catch {
      return unavailable();
    }

    // Verify before trusting: an access token we cannot verify is not a
    // session, however good the response looked.
    const claims = await this.verify(tokens.accessToken);
    if (!claims) return refusal();

    const headers = new Headers();
    appendSetCookie(headers, serializeCookie(ACCESS_COOKIE, tokens.accessToken, tokens.expiresIn));
    appendSetCookie(headers, serializeCookie(REFRESH_COOKIE, tokens.refreshToken, REFRESH_MAX_AGE_SECS));
    appendSetCookie(headers, deleteCookie(STATE_COOKIE));
    headers.set('Location', sanitizeReturnTo(payload.returnTo));
    headers.set('Cache-Control', 'no-store');
    return new Response(null, { status: 302, headers });
  }

  async verify(input: Request | string): Promise<Claims | null> {
    const token = extractToken(input);
    if (!token) return null;
    try {
      const nowMs = Date.now();
      await this.jwks.ensureFresh(this.jwksUri, nowMs);

      const nowSecs = Math.floor(nowMs / 1000);
      let outcome = await verifyToken(token, this.jwks.current(), this.config.issuer, this.config.clientId, nowSecs);
      if (!outcome.ok && outcome.unknownKid !== undefined) {
        // Either the issuer rotated or someone is inventing key ids. One
        // rate-limited refetch, then decide for good.
        await this.jwks.refetch(this.jwksUri, nowMs);
        outcome = await verifyToken(token, this.jwks.current(), this.config.issuer, this.config.clientId, nowSecs);
      }
      return outcome.ok ? outcome.claims : null;
    } catch {
      // Bad token, or an issuer that could not be reached: both are "no
      // claims" to a caller whose only recourse is to start a sign-in.
      return null;
    }
  }

  async refresh(request: Request): Promise<RefreshResult> {
    const refreshToken = readCookie(request, REFRESH_COOKIE);
    if (!refreshToken) return { claims: null, headers: new Headers() };

    const nowMs = Date.now();
    const grace = this.refreshGrace.get(refreshToken);
    if (grace && nowMs < grace.expiresAtMs) return toResult(grace.stored);

    this.pruneGrace(nowMs);
    let pending = this.refreshInflight.get(refreshToken);
    if (!pending) {
      pending = this.doRefresh(refreshToken, nowMs).finally(() => {
        this.refreshInflight.delete(refreshToken);
      });
      this.refreshInflight.set(refreshToken, pending);
    }
    return toResult(await pending);
  }

  private async doRefresh(refreshToken: string, nowMs: number): Promise<StoredRefresh> {
    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refreshToken);
    body.set('client_id', this.config.clientId);
    if (this.config.clientSecret) body.set('client_secret', this.config.clientSecret);

    const response = await this.postToken(this.tokenUrl, body);
    if (!response.ok) {
      // Same split as the callback: 5xx is an outage (throw, and let the
      // next request retry), 4xx is the IdP refusing the token — the session
      // is over, so clear the cookies.
      if (response.status >= 500) throw new Error(`token endpoint answered ${response.status}`);
      return cleared();
    }

    const tokens = await this.readTokens(response);
    const claims = await this.verify(tokens.accessToken);
    // A token we cannot verify is a refusal, not a session.
    if (!claims) return cleared();

    const stored: StoredRefresh = {
      claims,
      accessToken: tokens.accessToken,
      cookies: [
        serializeCookie(ACCESS_COOKIE, tokens.accessToken, tokens.expiresIn),
        serializeCookie(REFRESH_COOKIE, tokens.refreshToken, REFRESH_MAX_AGE_SECS),
      ],
    };
    this.refreshGrace.set(refreshToken, { stored, expiresAtMs: nowMs + REFRESH_GRACE_MS });
    return stored;
  }

  async signOut(): Promise<Response> {
    const url = new URL(this.logoutUrl);
    url.searchParams.set('client_id', this.config.clientId);
    if (this.config.postLogoutRedirectUri) {
      url.searchParams.set('post_logout_redirect_uri', this.config.postLogoutRedirectUri);
    }
    // The IdP's POST /logout and /logout-all only accept its own session
    // cookie, which a cross-origin app cannot send, so there is no
    // "everywhere" here: this ends the signed-in browser's one session. The
    // browser flow is a top-level GET to end_session_endpoint.
    const headers = new Headers();
    appendSetCookie(headers, deleteCookie(ACCESS_COOKIE));
    appendSetCookie(headers, deleteCookie(REFRESH_COOKIE));
    appendSetCookie(headers, deleteCookie(STATE_COOKIE));
    headers.set('Location', url.toString());
    headers.set('Cache-Control', 'no-store');
    return new Response(null, { status: 302, headers });
  }

  private postToken(tokenEndpoint: string, body: URLSearchParams): Promise<Response> {
    return this.fetchImpl(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString(),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  }

  private async readTokens(response: Response): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    let json: unknown;
    try {
      json = await response.json();
    } catch {
      throw new Error('token endpoint returned a non-JSON body');
    }
    if (typeof json !== 'object' || json === null) {
      throw new Error('token endpoint returned a non-object body');
    }
    const tokens = json as Record<string, unknown>;
    const accessToken = tokens['access_token'];
    const refreshToken = tokens['refresh_token'];
    // Both tokens go straight into `Set-Cookie`; a value with a CR/LF or a
    // `;` would let the IdP (or anyone who can spoof it) inject headers.
    if (
      typeof accessToken !== 'string' ||
      typeof refreshToken !== 'string' ||
      !TOKEN_CHARSET.test(accessToken) ||
      !TOKEN_CHARSET.test(refreshToken)
    ) {
      throw new Error('token endpoint response is missing a usable token');
    }
    const rawExpires = tokens['expires_in'];
    const expiresIn =
      typeof rawExpires === 'number' && rawExpires > 0
        ? Math.min(rawExpires, MAX_ACCESS_COOKIE_SECS)
        : DEFAULT_EXPIRES_IN;
    return { accessToken, refreshToken, expiresIn };
  }

  /** Drop expired grace entries so the map cannot grow without bound. */
  private pruneGrace(nowMs: number): void {
    for (const [token, entry] of this.refreshGrace) {
      if (nowMs >= entry.expiresAtMs) this.refreshGrace.delete(token);
    }
  }
}

/** A refresh that could not be renewed: session cookies are cleared. */
function cleared(): StoredRefresh {
  return { claims: null, cookies: [deleteCookie(ACCESS_COOKIE), deleteCookie(REFRESH_COOKIE)] };
}

function toResult(stored: StoredRefresh): RefreshResult {
  const headers = new Headers();
  for (const cookie of stored.cookies) appendSetCookie(headers, cookie);
  const result: RefreshResult = { claims: stored.claims, headers };
  if (stored.accessToken !== undefined) result.accessToken = stored.accessToken;
  return result;
}

/** The generic refusal every failed callback returns: one shape, no detail. */
function refusal(): Response {
  const headers = new Headers();
  appendSetCookie(headers, deleteCookie(STATE_COOKIE));
  headers.set('Cache-Control', 'no-store');
  return new Response('Sign-in could not be completed. Please try again.', { status: 400, headers });
}

/**
 * The 502 a callback returns when the IdP could not be reached or answered
 * nonsense. The state cookie is deleted either way, so the user restarts a
 * clean sign-in and the spent code can never be replayed.
 */
function unavailable(): Response {
  const headers = new Headers();
  appendSetCookie(headers, deleteCookie(STATE_COOKIE));
  headers.set('Cache-Control', 'no-store');
  return new Response('Sign-in is temporarily unavailable. Please try again.', { status: 502, headers });
}

/** Pull the access token from a request, or take a raw token string as-is. */
function extractToken(input: Request | string): string | null {
  if (typeof input === 'string') return input.trim() === '' ? null : input.trim();
  const cookie = readCookie(input, ACCESS_COOKIE);
  if (cookie) return cookie;
  const authorization = input.headers.get('Authorization');
  if (authorization && /^bearer /i.test(authorization)) {
    const bearer = authorization.slice('bearer '.length).trim();
    return bearer === '' ? null : bearer;
  }
  return null;
}
