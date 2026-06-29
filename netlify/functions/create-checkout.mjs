// WebGuard247 — create a Stripe Checkout session (Netlify Function).
// Given a plan name, it asks Stripe to build a secure hosted checkout page and
// returns its URL, which the browser then redirects to.
//
// Uses only the built-in fetch (Node 18+), so there are NO dependencies to install.
// The Stripe SECRET key is read from the STRIPE_SECRET_KEY environment variable
// (set in Netlify → Site configuration → Environment variables). It is NEVER in this code.

// Plan name -> Stripe price + checkout mode.
// The price is decided HERE on the server, so the browser can only choose a plan
// name, never an amount. (These are the LIVE price IDs.)
const PLANS = {
  guide:          { price: 'price_1TnkYbCWpCO9ZCTCa0hKIX90', mode: 'payment' },
  pro_monthly:    { price: 'price_1Tnkd0CWpCO9ZCTCNuejm8Jx', mode: 'subscription' },
  pro_yearly:     { price: 'price_1TnkgmCWpCO9ZCTCMUynxEYV', mode: 'subscription' },
  agency_monthly: { price: 'price_1TnkiICWpCO9ZCTC8IWh7K68', mode: 'subscription' },
  agency_yearly:  { price: 'price_1TnkkECWpCO9ZCTC9NE2J285', mode: 'subscription' },
};

const SITE = 'https://webguard247.com';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Payment is not configured yet.' }) };
  }

  let body;
  try { body = event.body ? JSON.parse(event.body) : {}; }
  catch { return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Bad request.' }) }; }

  const plan = PLANS[body.plan];
  if (!plan) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Unknown plan.' }) };
  }

  // Build the Checkout Session request (form-encoded, as the Stripe API expects).
  const form = new URLSearchParams();
  form.set('mode', plan.mode);
  form.set('line_items[0][price]', plan.price);
  form.set('line_items[0][quantity]', '1');
  form.set('success_url', `${SITE}/login.html?checkout=success&session_id={CHECKOUT_SESSION_ID}`);
  form.set('cancel_url', `${SITE}/pricing.html?checkout=cancelled`);
  form.set('allow_promotion_codes', 'true');
  form.set('billing_address_collection', 'auto');
  if (body.email) form.set('customer_email', body.email);
  if (body.userId) {
    // Ties the purchase back to the logged-in WebGuard247 account.
    form.set('client_reference_id', body.userId);
    form.set('metadata[supabase_user_id]', body.userId);
  }
  form.set('metadata[plan]', body.plan);

  try {
    const resp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${secret}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
    const data = await resp.json();
    if (!resp.ok) {
      const msg = data && data.error && data.error.message ? data.error.message : 'Could not start checkout.';
      return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: msg }) };
    }
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ url: data.url }) };
  } catch (e) {
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: 'Could not reach the payment service.' }) };
  }
};
