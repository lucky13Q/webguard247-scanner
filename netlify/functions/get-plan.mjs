// WebGuard247 — get-plan endpoint (Netlify Function).
// The dashboard calls this to find out the logged-in user's plan WITHOUT the
// browser ever touching the profiles table directly (that table's Data API is
// locked down on purpose). We verify the caller's login token, then read the
// authoritative plan with the service-role key — the same method scan.mjs uses
// and which we've proven works.
//
// Dependency-free: uses global fetch only. Secrets come from Netlify env vars:
//   SUPABASE_SERVICE_ROLE_KEY - lets the server read the profiles table.

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://uhyuvlqxlfvolmykrmce.supabase.co';
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json',
};

// Verify the caller's login token and return their real plan.
// Anything unverified / failing safely returns 'free' (never throws).
async function resolvePlan(event) {
  try {
    const h = event.headers || {};
    const authHeader = h.authorization || h.Authorization || '';
    const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!m) return 'free';
    const token = m[1].trim();
    if (!token || !SERVICE_KEY) return 'free';

    // 1) Verify the token and find out who it belongs to.
    const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${token}` },
    });
    if (!userRes.ok) return 'free';
    const user = await userRes.json();
    if (!user || !user.id) return 'free';

    // 2) Read the authoritative plan with the service-role key (bypasses RLS).
    const profRes = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(user.id)}&select=plan`,
      { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
    );
    if (!profRes.ok) return 'free';
    const rows = await profRes.json();
    const plan = Array.isArray(rows) && rows[0] && rows[0].plan ? String(rows[0].plan) : 'free';
    return plan;
  } catch {
    return 'free';
  }
}

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  const plan = await resolvePlan(event);
  return { statusCode: 200, headers: CORS, body: JSON.stringify({ plan }) };
};
