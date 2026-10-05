import Link from 'next/link';
import { getSession } from '@/lib/auth';

// Reads the session cookie, so never prerendered.
export const dynamic = 'force-dynamic';

export default async function Home() {
  const claims = await getSession();

  return (
    <main>
      <h1>Next.js + Cratefield auth-core</h1>
      {claims ? (
        <p>
          Signed in as <code data-testid="subject">{claims.sub}</code>.{' '}
          <Link href="/dashboard">Go to the dashboard</Link>.
        </p>
      ) : (
        <p>
          {/* A plain anchor, not <Link>: this is an API route, not a page. */}
          <a href="/api/auth/start?return_to=/dashboard">Sign in</a>
        </p>
      )}
    </main>
  );
}
