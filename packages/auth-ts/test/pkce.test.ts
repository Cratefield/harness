import { describe, expect, it } from 'vitest';
import { codeChallengeS256, createCodeVerifier, sanitizeReturnTo } from '../src/index.js';

describe('PKCE', () => {
  it('matches RFC 7636 Appendix B', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    await expect(codeChallengeS256(verifier)).resolves.toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('generates a 43-character verifier from the unreserved charset', () => {
    for (let i = 0; i < 50; i += 1) {
      const verifier = createCodeVerifier();
      expect(verifier).toHaveLength(43);
      expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
    }
  });

  it('generates a different verifier each time', () => {
    const seen = new Set(Array.from({ length: 20 }, () => createCodeVerifier()));
    expect(seen.size).toBe(20);
  });
});

describe('sanitizeReturnTo', () => {
  const cases: Array<[string, string, string]> = [
    ['protocol-relative //', '//evil.com', '/'],
    ['slash-backslash', '/\\evil.com', '/'],
    ['backslash-backslash', '\\\\evil.com', '/'],
    ['absolute https', 'https://evil.com', '/'],
    ['javascript scheme', 'javascript:alert(1)', '/'],
    ['tab trick', '/\t/evil.com', '/'],
    ['leading space', ' /x', '/'],
    ['dot-segment to protocol-relative', '/foo/..//evil.com', '/'],
    ['encoded dot-segment to protocol-relative', '/%2e%2e//evil.com', '/'],
    ['dot-segment to protocol-relative (a/..)', '/a/..//evil.com', '/'],
    ['empty', '', '/'],
    ['control character', '/a\u0000b', '/'],
    ['newline', '/a\nb', '/'],
  ];

  it.each(cases)('collapses %s to /', (_label, input, expected) => {
    expect(sanitizeReturnTo(input)).toBe(expected);
  });

  it('treats undefined and null as /', () => {
    expect(sanitizeReturnTo(undefined)).toBe('/');
    expect(sanitizeReturnTo(null)).toBe('/');
  });

  it('keeps a percent-encoded newline as a path', () => {
    expect(sanitizeReturnTo('/%0a/x')).toBe('/%0a/x');
  });

  it('preserves a legitimate path, query and fragment', () => {
    expect(sanitizeReturnTo('/a/b?c=1#d')).toBe('/a/b?c=1#d');
  });

  it('preserves a bare root', () => {
    expect(sanitizeReturnTo('/')).toBe('/');
  });
});
