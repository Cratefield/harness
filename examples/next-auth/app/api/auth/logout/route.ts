import { getNextAuth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/** Clear the session cookies and redirect to the IdP's sign-out. Same-origin only. */
export function POST(request: Request): Promise<Response> {
  return getNextAuth().handlers.logout(request);
}
