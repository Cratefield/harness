import { getSession } from '@/lib/auth';

// Protected by middleware.ts; the session read is why it is dynamic per request.
export const dynamic = 'force-dynamic';

export default async function Dashboard() {
  const claims = await getSession();

  return (
    <main>
      <h1>Dashboard</h1>
      {claims ? (
        <>
          <p>
            Signed in as <code data-testid="subject">{claims.sub}</code>
          </p>
          <pre data-testid="claims">{JSON.stringify(claims, null, 2)}</pre>
          <form method="post" action="/api/auth/logout">
            <button type="submit">Sign out</button>
          </form>
        </>
      ) : (
        <p>No session.</p>
      )}
    </main>
  );
}
