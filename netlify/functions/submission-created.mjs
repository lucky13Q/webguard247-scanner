// WebGuard247 — emails a visitor their free scan results.
//
// Netlify runs a function with this exact name automatically whenever a form
// submission is created. There is nothing to wire up and no endpoint to call:
// the name is the trigger. See the "scan-report" form in public/index.html.
//
// Uses only global fetch, so there are NO dependencies to install — the same
// rule the rest of this project follows.
//
// WHAT IT SENDS: the free traffic-light summary only — grade, score and the
// pass/warn/fail status of each check. The written fix for each issue is the
// £4.99 Fix-It Guide and is never included here. The scan function already
// strips those server-side for non-paying callers, so they are not in the
// submission to begin with; this is the second lock on the same door.
//
// SETUP (one time):
//   1. Create an account with an email sending service and verify the domain
//      you want to send from.
//   2. In Netlify: Project configuration → Environment variables, add
//      RESEND_API_KEY. Optionally REPORT_FROM to change the sender.
//   3. Netlify: Project configuration → Forms → form detection must be on,
//      or no submission ever reaches this function.
//
// Without RESEND_API_KEY this function does nothing and says so in the logs.
// The submission is still recorded by Netlify either way, so no lead is lost
// while the sending side is being set up.

const API = 'https://api.resend.com/emails';
const FROM = process.env.REPORT_FROM || 'WebGuard247 <results@webguard247.com>';
const REPLY_TO = 'hello@onlineporqupine.com';
const FORM = 'scan-report';

const esc = (s) =>
  String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function plainBody({ site, grade, issues, summary }) {
  const lines = [];
  lines.push(`Here are the results of your free security check on ${site}.`);
  lines.push('');
  lines.push(summary || `Grade ${grade}.`);
  lines.push('');
  if (Number(issues) > 0) {
    lines.push(`We found ${issues} thing${issues === '1' ? '' : 's'} worth looking at.`);
    lines.push('');
    lines.push('This summary shows you WHERE the problems are. To see what each');
    lines.push('one actually means, and the plain-English steps to put it right,');
    lines.push('the Fix-It Guide is £4.99 — one payment, no subscription:');
    lines.push('https://webguard247.com/pricing');
    lines.push('');
    lines.push('Would rather someone just did it? We fix everything on the report,');
    lines.push('re-scan the site and send you the before and after, from £79:');
    lines.push('https://webguard247.com/fix');
  } else {
    lines.push('Nothing needs your attention today, which is a good place to be.');
    lines.push('Worth running again in a few months — certificates expire and');
    lines.push('settings drift.');
  }
  lines.push('');
  lines.push('Any questions, just reply to this email or ring 07375 889707.');
  lines.push('');
  lines.push('Colin Booker');
  lines.push('ONLINE PORQUPINE LTD · Company no. 17108652 · West Mersea, Essex');
  lines.push('');
  lines.push('You are getting this because you asked for your results at');
  lines.push('webguard247.com. We will not add you to anything you did not tick.');
  return lines.join('\n');
}

function htmlBody({ site, grade, issues, summary }) {
  const problems = Number(issues) > 0;
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#070a09;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#e9f1ec">
<div style="max-width:560px;margin:0 auto">
  <p style="font-size:12px;letter-spacing:.14em;color:#b8ff3a;margin:0 0 6px;font-weight:700">WEBGUARD247</p>
  <h1 style="font-size:22px;line-height:1.25;margin:0 0 14px">Your results for ${esc(site)}</h1>
  <p style="font-size:15px;line-height:1.6;color:#9fb0a6;margin:0 0 18px">Grade <strong style="color:#e9f1ec">${esc(grade)}</strong>. Here is everything the free check looked at.</p>
  <pre style="background:#0f1613;border:1px solid #27362f;border-radius:10px;padding:16px;font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.5;color:#e9f1ec;white-space:pre-wrap;word-break:break-word;margin:0 0 20px">${esc(summary)}</pre>
  ${problems ? `
  <div style="border:1px solid rgba(184,255,58,.35);background:rgba(184,255,58,.06);border-radius:10px;padding:16px;margin:0 0 16px">
    <p style="margin:0 0 10px;font-size:15px;line-height:1.6"><strong>This shows you where the problems are.</strong> To see what each one means and how to put it right, the Fix-It Guide is £4.99 — one payment, no subscription.</p>
    <a href="https://webguard247.com/pricing" style="display:inline-block;background:#b8ff3a;color:#08120a;text-decoration:none;font-weight:700;padding:11px 20px;border-radius:8px;font-size:14px">Unlock the fixes — £4.99</a>
  </div>
  <p style="font-size:14px;line-height:1.6;color:#9fb0a6;margin:0 0 20px">Would rather someone just did it? We fix everything on this report, re-scan the site and send you the before and after, <a href="https://webguard247.com/fix" style="color:#b8ff3a">from £79</a>.</p>
  ` : `
  <p style="font-size:15px;line-height:1.6;margin:0 0 20px">Nothing needs your attention today, which is a good place to be. Worth running again in a few months — certificates expire and settings drift.</p>
  `}
  <p style="font-size:14px;line-height:1.6;color:#9fb0a6;margin:0 0 20px">Any questions, reply to this email or ring <a href="tel:+447375889707" style="color:#b8ff3a">07375 889707</a>. A person answers.</p>
  <p style="font-size:14px;line-height:1.6;margin:0 0 4px">Colin Booker</p>
  <p style="font-size:11px;line-height:1.6;color:#7d8d84;margin:0 0 16px">ONLINE PORQUPINE LTD · Company no. 17108652 · West Mersea, Essex</p>
  <p style="font-size:11px;line-height:1.6;color:#7d8d84;margin:0;border-top:1px solid #1d2a24;padding-top:14px">You are getting this because you asked for your results at webguard247.com. We will not add you to anything you did not tick.</p>
</div>
</body></html>`;
}

export const handler = async (event) => {
  let payload;
  try {
    payload = JSON.parse(event.body || '{}').payload || {};
  } catch {
    console.error('submission-created: body was not JSON, ignoring');
    return { statusCode: 200, body: 'ignored' };
  }

  const formName = payload.form_name || payload.formName;
  if (formName !== FORM) {
    // Another form on the site (the fix request, say). Not ours.
    return { statusCode: 200, body: 'not the scan-report form' };
  }

  const d = payload.data || {};
  const to = (d.Email || '').trim();
  const site = (d['Website scanned'] || 'your site').trim();
  const grade = (d.Grade || '?').trim();
  const issues = (d['Issues found'] || '0').trim();
  const summary = d['Report summary'] || '';

  if (!to) {
    console.error('submission-created: submission had no email address');
    return { statusCode: 200, body: 'no address' };
  }

  const key = process.env.RESEND_API_KEY;
  if (!key) {
    // Deliberately not an error: the lead is safely recorded by Netlify and
    // Colin still gets his notification. Only the automatic reply is missing.
    console.warn(
      `submission-created: RESEND_API_KEY is not set, so ${to} has NOT been ` +
      `emailed their results. Set it in Netlify environment variables.`
    );
    return { statusCode: 200, body: 'no api key, nothing sent' };
  }

  const subject = `Your website security results for ${site} — grade ${grade}`;

  try {
    const res = await fetch(API, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: FROM,
        to: [to],
        reply_to: REPLY_TO,
        subject,
        text: plainBody({ site, grade, issues, summary }),
        html: htmlBody({ site, grade, issues, summary }),
      }),
    });

    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      console.error(`submission-created: send failed for ${to} — ${res.status} ${detail}`);
      // 200 so Netlify does not retry in a loop. The submission is still saved,
      // and the log above says who was missed so they can be emailed by hand.
      return { statusCode: 200, body: 'send failed, logged' };
    }

    console.log(`submission-created: results for ${site} sent to ${to}`);
    return { statusCode: 200, body: 'sent' };
  } catch (e) {
    console.error(`submission-created: send threw for ${to} — ${String(e && e.message || e)}`);
    return { statusCode: 200, body: 'send threw, logged' };
  }
};
