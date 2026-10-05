import { getNextAuth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/** Redeem the authorization code and start the session. */
export function GET(request: Request): Promise<Response> {
  return getNextAuth().handlers.callback(request);
}
