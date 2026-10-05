import type { NextRequest } from 'next/server';
import { getNextAuth } from './lib/auth';

type Guard = (request: Request) => Promise<Response | undefined>;

let guard: Guard | undefined;

// Built on the first request, not at module scope: `next build` imports this
// file to read `config`, before `.env.local` necessarily exists.
export default function middleware(request: NextRequest): Promise<Response | undefined> {
  guard ??= getNextAuth().authMiddleware({
    protect: ['/dashboard'],
    signInPath: '/api/auth/start',
  });
  return guard(request);
}

export const config = {
  // Everything except the auth routes and Next's static assets. `/api/auth`
  // must be reachable unauthenticated — that is the whole sign-in flow — and
  // guarding it would loop.
  matcher: ['/((?!api/auth|_next/static|_next/image|favicon.ico).*)'],
};
