# WebGuard247 — your own scanner (no Manus)

This folder is a complete, self-contained website security scanner. It does **not**
depend on Manus, and it has **no paid services and nothing to install** — it runs on
Netlify's free tier using only built-in code.

You do **not** need to understand the code. Here's what it is and what to do.

---

## What's in here

| File | What it does (in plain English) |
|------|--------------------------------|
| `public/index.html` | The page people see — type a website, hit "Scan now", get a graded report. |
| `netlify/functions/scan.mjs` | The robot that actually visits the site and inspects it. |
| `netlify/functions/lib/checks.mjs` | The brain — the security rules that decide pass / warn / fail. |
| `netlify.toml` | Tells Netlify how to run everything. |
| `test/run-tests.mjs` | A self-test that proves the brain works (already passed). |

It checks: HTTPS & TLS certificates, security headers (HSTS, CSP, clickjacking, etc.),
cookie safety, DNS and email protection (SPF / DMARC / CAA), and information leaks.
It is **passive** — it only looks at what any browser can see. It does not hack,
port-scan, or touch private/internal systems.

---

## The only steps that need YOU (about 5 minutes)

You can't email me your Netlify login, and I can't click "deploy" as you — so this
short bit is yours. Everything else is already built.

**Option A — drag & drop (easiest, no coding):**
1. Go to https://app.netlify.com and log in (the same account hosting webguard247.com).
2. Zip this whole folder.
3. On Netlify, open your site → **Deploys** → drag the zip onto the page.
4. Wait ~1 minute. Visit `https://<your-site>/api/scan?url=example.com` — you should see
   JSON results. The homepage scan button now works.

**Option B — connect to GitHub (better long-term):**
1. Put this folder in a GitHub repo.
2. In Netlify: **Add new site → Import from GitHub** → pick the repo.
3. Netlify auto-detects `netlify.toml` and deploys. Every future change redeploys itself.

Then point your real domain's scan button at `/api/scan` (I can do that wiring for you
once it's live — just tell me).

---

## What's still on the to-do list (and who does what)

| Piece | Status | Who |
|-------|--------|-----|
| Scanning engine | ✅ Built, tested, Manus-free | Me |
| Front-end / report UI | ✅ Built | Me |
| **User logins** | Not started — easy, ~1 day with Supabase/Clerk | I build it; you create the free account |
| **Payments** | Not started — Stripe Checkout | I build it; you open the Stripe account (your company's money) |

Say the word and I'll do the logins and payments next the same way: I write everything,
you just create the accounts and paste two keys.
