// WebGuard247 — Stripe webhook (Netlify Function).
// Stripe calls this automatically when a checkout completes. We (1) verify the
// message really came from Stripe, then (2) stamp the customer's plan into the
// Supabase 'profiles' table.
//
// Dependency-free: uses Node's built-in crypto + fetch (no npm installs).
// Secrets live in Netlify → Environment variables (NEVER in this code):
//   STRIPE_WEBHOOK_SECRET     - the endpoint "Signing secret" from Stripe (whsec_...)
//   SUPABASE_SERVICE_ROLE_KEY - Supabase service-role key (allows writing to profiles)

import crypto from 'node:crypto';

const SUPABASE_URL = 'https://uhyuvlqxlfvolmykrmce.supabase.co';

// Which stored plan each purchased price maps to.
const PLAN_FROM_KEY = {
  guide:          'guide',
  pro_monthly:    'pro',
  pro_yearly:     'pro',
  agency_monthly: 'agency',
  agency_yearly:  'agency',
};

function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  for (const piece of sigHeader.split(',')) {
    const idx = piece.indexOf('=');
    if (idx > -1) parts[piece.slice(0, idx)] = piece.slice(idx + 1);
  }
  const t = parts.t;
  const v1 = parts.v1;
  if (!t || !v1) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${t}.${rawBody}`, 'utf8')
    .digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(v1);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!secret || !serviceKey) {
    return { statusCode: 500, body: 'Webhook not configured' };
  }

  // Stripe needs the EXACT raw body to verify the signature.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : event.body;

  const sig = event.headers['stripe-signature'] || event.headers['Stripe-Signature'];
  if (!verifyStripeSignature(rawBody, sig, secret)) {
    return { statusCode: 400, body: 'Invalid signature' };
  }

  let evt;
  try { evt = JSON.parse(rawBody); }
  catch { return { statusCode: 400, body: 'Bad payload' }; }

  if (evt.type === 'checkout.session.completed') {
    const session = evt.data.object || {};
    const planKey = session.metadata && session.metadata.plan;
    const userId = session.client_reference_id || (session.metadata && session.metadata.supabase_user_id);
    const plan = PLAN_FROM_KEY[planKey] || 'free';
    const email = (session.customer_details && session.customer_details.email) || session.customer_email || null;

    if (userId) {
      const row = {
        id: userId,
        plan,
        stripe_customer_id: session.customer || null,
        updated_at: new Date().toISOString(),
      };
      if (email) row.email = email;

      try {
        const resp = await fetch(`${SUPABASE_URL}/rest/v1/profiles?on_conflict=id`, {
          method: 'POST',
          headers: {
            apikey: serviceKey,
            Authorization: `Bearer ${serviceKey}`,
            'Content-Type': 'application/json',
            Prefer: 'resolution=merge-duplicates,return=minimal',
          },
          body: JSON.stringify(row),
        });
        if (!resp.ok) {
          const txt = await resp.text();
          console.error('Supabase upsert failed', resp.status, txt);
        }
      } catch (e) {
        console.error('Supabase upsert error', e);
      }
    }
  }

  // Always acknowledge so Stripe doesn't keep retrying.
  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
