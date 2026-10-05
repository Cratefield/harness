import { getNextAuth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/** Begin sign-in: set the state cookie and redirect to the IdP. */
export function GET(request: Request): Promise<Response> {
  return getNextAuth().handlers.start(request);
}
