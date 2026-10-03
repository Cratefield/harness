import { describe, expect, it } from 'vitest';
import { createHarness } from './fake-idp.js';
import { cookieAttributes } from './http-helpers.js';

describe('signOut', () => {
  it('redirects to end_session and clears both session cookies', async () => {
    const { auth, idp, config } = await createHarness({ config: { postLogoutRedirectUri: 'https://app.example/goodbye' } });
    const response = await auth.signOut();

    expect(response.status).toBe(302);
    expect(response.headers.get('Cache-Control')).toBe('no-store');

    const location = new URL(response.headers.get('Location')!);
    expect(`${location.origin}${location.pathname}`).toBe(idp.logoutUrl);
    expect(location.searchParams.get('client_id')).toBe(config.clientId);
    expect(location.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example/goodbye');

    for (const name of ['__Host-cf_at', '__Host-cf_rt', '__Host-cf_state']) {
      const attributes = cookieAttributes(response.headers, name);
      expect(attributes['Max-Age']).toBe('0');
      expect(attributes['Path']).toBe('/');
      expect(attributes).toHaveProperty('Secure');
      expect(attributes).toHaveProperty('HttpOnly');
      expect(attributes['SameSite']).toBe('Lax');
    }
  });

  it('omits post_logout_redirect_uri when unset', async () => {
    const { auth } = await createHarness();
    const response = await auth.signOut();
    const location = new URL(response.headers.get('Location')!);
    expect(location.searchParams.has('post_logout_redirect_uri')).toBe(false);
  });
});
