# CLAUDE.md — WebGuard247

## What this project is
WebGuard247 is a website security scanner. A visitor enters their site's URL,
we scan it, and we report back the security issues we find — then sell help
fixing them. Operated by **ONLINE PORCUPINE LTD** (UK company).

Live site: https://webguard247.com

## Who you're working with
The founder is **non-technical**. When you make changes:
- Explain what you're doing and why, in plain English. Skip unexplained jargon.
- Work **one task at a time**. Finish and confirm before moving to the next.
- When a file needs editing, give the **complete file**, not just a diff or
  "change line 42".
- If you create a file, give it a clear, unique name and say exactly where it
  goes in the repo.

## Tech stack
- **Frontend:** plain HTML / CSS / JavaScript — `public/index.html` is the page
  visitors see.
- **Scanner:** Netlify serverless functions — `netlify/functions/scan.mjs` does
  the scanning, `netlify/functions/lib/checks.mjs` holds the security rules.
  The scanner is passive: it only inspects what any browser can see.
- **Hosting / deploy:** Netlify, configured by `netlify.toml`.
- **Auth:** Supabase (project `uhyuvlqxlfvolmykrmce.supabase.co`), JS v2 client.
- **Payments:** Stripe (account `acct_1TPPw7CWpCO9ZCTC`).
  **Use test keys first**; switch to live keys only once the flow is verified
  end-to-end. Note: a second Stripe account exists (created by another AI tool,
  Manus) — do NOT use it. Only `acct_1TPPw7CWpCO9ZCTC` is correct.

## Scanning rules — legal boundary (do not cross)
This scanner is PASSIVE ONLY: it inspects only what any ordinary web browser
can see when visiting a site (public headers, HTTPS/certificate details,
publicly served pages). This is deliberate — it means users may scan any site
without proving they own it.

- NEVER add "active" scanning features: no probing for vulnerabilities, no
  brute-forcing, no fuzzing, no testing logins, no requests designed to
  trigger errors or bypass protections. In the UK, active scanning of sites
  you don't own or have permission for can be a criminal offence (Computer
  Misuse Act).
- If active checks are ever proposed in future, domain ownership verification
  (DNS record, file upload, or email to the domain itself) becomes mandatory
  FIRST — and the founder must explicitly approve the feature. A collected
  email address alone is NOT proof of ownership.
- User-facing copy should reassure: scans are passive and read-only.

## Pricing (source of truth for any checkout/product code)
- **Fix-It Guide** — £4.99, one-off payment
- **Pro** — £9 / month, or £89 / year
- **Agency** — £29 / month, or £290 / year

## Secrets — never commit these
Stripe secret keys, Supabase service-role keys, and any other private keys must
**never** be written into this repo or any committed file. They live in Netlify
environment variables. The Supabase URL and the **anon/public** key are safe in
client-side code; the service-role key is not. This repo is PUBLIC — anyone on
the internet can read it, so treat every committed file as visible to the world.

## Copy & tone (for any user-facing text)
- Reassuring and clear, not alarmist or fear-mongering.
- Professional; avoid overly casual language in product copy.
- British English spelling throughout (e.g. "organise", "licence").

## Current focus
Stripe payments via Payment Links, in test/sandbox mode first. Supabase logins
exist; linking payments to user accounts comes later.
