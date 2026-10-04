import { getNextAuth } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/** Rotate the session cookies. Same-origin only; 204 or 401. */
export function POST(request: Request): Promise<Response> {
  return getNextAuth().handlers.refresh(request);
}
