// WebGuard247 — passive security analysis engine.
// PURE FUNCTIONS ONLY: these take already-collected "evidence" and return findings.
// No network access happens here, which is exactly why it can be unit-tested offline.
//
// A "finding" looks like:
//   { id, category, title, status, detail, recommendation, weight }
//   status: 'pass' | 'warn' | 'fail' | 'info'
//   weight: how much it counts toward the score (info findings are excluded)

const H = (headers, name) => {
  if (!headers) return undefined;
  return headers[name.toLowerCase()];
};

function f(id, category, title, status, detail, recommendation = '', weight = 1) {
  return { id, category, title, status, detail, recommendation, weight };
}

// ---------------------------------------------------------------------------
// Transport: reachability, HTTPS, redirects, TLS certificate
// ---------------------------------------------------------------------------
function analyzeTransport(ev) {
  const out = [];

  out.push(
    ev.reachable
      ? f('reachable', 'Transport', 'Site is reachable', 'pass', `Responded with HTTP ${ev.statusCode}.`)
      : f('reachable', 'Transport', 'Site is reachable', 'fail', ev.error || 'No response from the server.', 'Make sure the domain resolves and the server is online.', 3)
  );

  const isHttps = (ev.finalUrl || ev.url || '').startsWith('https://');
  out.push(
    isHttps
      ? f('https', 'Transport', 'Served over HTTPS', 'pass', 'The final page is delivered over an encrypted connection.')
      : f('https', 'Transport', 'Served over HTTPS', 'fail', 'The page is served over plain HTTP.', 'Install a TLS certificate and serve everything over HTTPS.', 3)
  );

  // HTTP -> HTTPS redirect
  const upgraded = (ev.redirectChain || []).some(
    (h) => (h.from || '').startsWith('http://') && (h.to || '').startsWith('https://')
  );
  if ((ev.url || '').startsWith('http://')) {
    out.push(
      upgraded || isHttps
        ? f('http-redirect', 'Transport', 'HTTP redirects to HTTPS', 'pass', 'Plain-HTTP visitors are upgraded to a secure connection.')
        : f('http-redirect', 'Transport', 'HTTP redirects to HTTPS', 'fail', 'An HTTP request was not upgraded to HTTPS.', 'Add a 301 redirect from http:// to https://.', 2)
    );
  }

  const tls = ev.tls;
  if (isHttps) {
    if (!tls || tls.error) {
      out.push(f('tls-valid', 'Transport', 'Valid TLS certificate', 'fail', tls?.error || 'Certificate could not be validated.', 'Reissue a valid certificate (Let’s Encrypt is free).', 3));
    } else {
      out.push(f('tls-valid', 'Transport', 'Valid TLS certificate', 'pass', `Issued by ${tls.issuer || 'a trusted CA'}.`));

      if (typeof tls.daysToExpiry === 'number') {
        if (tls.daysToExpiry < 0) out.push(f('tls-expiry', 'Transport', 'Certificate not expired', 'fail', `Expired ${Math.abs(tls.daysToExpiry)} days ago.`, 'Renew immediately.', 3));
        else if (tls.daysToExpiry < 14) out.push(f('tls-expiry', 'Transport', 'Certificate not expiring soon', 'warn', `Expires in ${tls.daysToExpiry} days.`, 'Renew now and enable auto-renewal.', 2));
        else out.push(f('tls-expiry', 'Transport', 'Certificate not expiring soon', 'pass', `Valid for another ${tls.daysToExpiry} days.`));
      }

      if (tls.protocol) {
        const weak = /TLSv1(\.0|\.1)?$|SSL/i.test(tls.protocol) && !/TLSv1\.2|TLSv1\.3/i.test(tls.protocol);
        out.push(
          weak
            ? f('tls-version', 'Transport', 'Modern TLS protocol', 'fail', `Negotiated ${tls.protocol}.`, 'Disable TLS 1.0/1.1 and require TLS 1.2+.', 2)
            : f('tls-version', 'Transport', 'Modern TLS protocol', 'pass', `Negotiated ${tls.protocol}.`)
        );
      }

      if (tls.hostMatch === false) {
        out.push(f('tls-hostmatch', 'Transport', 'Certificate matches hostname', 'fail', 'The certificate does not cover this hostname.', 'Issue a certificate that includes this domain in its SAN list.', 2));
      } else if (tls.hostMatch === true) {
        out.push(f('tls-hostmatch', 'Transport', 'Certificate matches hostname', 'pass', 'The certificate covers this hostname.'));
      }
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Security response headers
// ---------------------------------------------------------------------------
function analyzeHeaders(ev) {
  const out = [];
  const h = ev.headers || {};

  // HSTS
  const hsts = H(h, 'strict-transport-security');
  if (hsts) {
    out.push(f('hsts', 'Headers', 'HSTS enabled', 'pass', 'Strict-Transport-Security is set.'));
    const m = /max-age=(\d+)/i.exec(hsts);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    out.push(
      maxAge >= 31536000
        ? f('hsts-maxage', 'Headers', 'HSTS max-age is at least 1 year', 'pass', `max-age=${maxAge}.`)
        : f('hsts-maxage', 'Headers', 'HSTS max-age is at least 1 year', 'warn', `max-age=${maxAge} is short.`, 'Set max-age to 31536000 or more.', 1)
    );
    out.push(/includeSubDomains/i.test(hsts)
      ? f('hsts-subdomains', 'Headers', 'HSTS covers subdomains', 'pass', 'includeSubDomains is present.')
      : f('hsts-subdomains', 'Headers', 'HSTS covers subdomains', 'info', 'includeSubDomains is not set.', 'Add includeSubDomains if all subdomains use HTTPS.'));
    out.push(/preload/i.test(hsts)
      ? f('hsts-preload', 'Headers', 'HSTS preload requested', 'info', 'preload directive present.')
      : f('hsts-preload', 'Headers', 'HSTS preload requested', 'info', 'Not submitted for preload.', 'Optional: submit to hstspreload.org.'));
  } else if ((ev.finalUrl || '').startsWith('https://')) {
    out.push(f('hsts', 'Headers', 'HSTS enabled', 'fail', 'Strict-Transport-Security header is missing.', 'Add Strict-Transport-Security with a long max-age.', 2));
  }

  // CSP
  const csp = H(h, 'content-security-policy');
  if (csp) {
    out.push(f('csp', 'Headers', 'Content-Security-Policy set', 'pass', 'A CSP is defined.'));
    const unsafe = /unsafe-inline|unsafe-eval/i.test(csp);
    out.push(unsafe
      ? f('csp-unsafe', 'Headers', 'CSP avoids unsafe directives', 'warn', "Policy contains 'unsafe-inline' or 'unsafe-eval'.", 'Remove unsafe directives; use nonces or hashes.', 1)
      : f('csp-unsafe', 'Headers', 'CSP avoids unsafe directives', 'pass', 'No unsafe-inline/unsafe-eval found.'));
    const fa = /frame-ancestors/i.test(csp);
    out.push(fa
      ? f('csp-frameancestors', 'Headers', 'CSP restricts framing', 'pass', 'frame-ancestors directive present.')
      : f('csp-frameancestors', 'Headers', 'CSP restricts framing', 'info', 'No frame-ancestors directive.', 'Add frame-ancestors to control embedding.'));
  } else {
    out.push(f('csp', 'Headers', 'Content-Security-Policy set', 'warn', 'No Content-Security-Policy header.', 'Add a CSP to mitigate XSS and injection.', 2));
  }

  // Clickjacking (XFO or CSP frame-ancestors)
  const xfo = H(h, 'x-frame-options');
  const cspFA = csp && /frame-ancestors/i.test(csp);
  out.push((xfo || cspFA)
    ? f('clickjacking', 'Headers', 'Clickjacking protection', 'pass', xfo ? `X-Frame-Options: ${xfo}.` : 'Protected via CSP frame-ancestors.')
    : f('clickjacking', 'Headers', 'Clickjacking protection', 'fail', 'No X-Frame-Options and no frame-ancestors.', 'Add X-Frame-Options: SAMEORIGIN or a CSP frame-ancestors directive.', 2));

  // X-Content-Type-Options
  const xcto = H(h, 'x-content-type-options');
  out.push(/nosniff/i.test(xcto || '')
    ? f('nosniff', 'Headers', 'MIME-sniffing disabled', 'pass', 'X-Content-Type-Options: nosniff.')
    : f('nosniff', 'Headers', 'MIME-sniffing disabled', 'fail', 'X-Content-Type-Options is missing or not nosniff.', 'Add X-Content-Type-Options: nosniff.', 1));

  // Referrer-Policy
  out.push(H(h, 'referrer-policy')
    ? f('referrer', 'Headers', 'Referrer-Policy set', 'pass', `Referrer-Policy: ${H(h, 'referrer-policy')}.`)
    : f('referrer', 'Headers', 'Referrer-Policy set', 'warn', 'No Referrer-Policy header.', 'Add e.g. Referrer-Policy: strict-origin-when-cross-origin.', 1));

  // Permissions-Policy
  out.push(H(h, 'permissions-policy')
    ? f('permissions', 'Headers', 'Permissions-Policy set', 'pass', 'Permissions-Policy is defined.')
    : f('permissions', 'Headers', 'Permissions-Policy set', 'info', 'No Permissions-Policy header.', 'Optionally restrict camera/microphone/geolocation features.'));

  // Cross-origin isolation headers (modern, mostly info)
  out.push(H(h, 'cross-origin-opener-policy')
    ? f('coop', 'Headers', 'Cross-Origin-Opener-Policy set', 'pass', 'COOP defined.')
    : f('coop', 'Headers', 'Cross-Origin-Opener-Policy set', 'info', 'No COOP header.', 'Consider same-origin for isolation.'));
  out.push(H(h, 'cross-origin-resource-policy')
    ? f('corp', 'Headers', 'Cross-Origin-Resource-Policy set', 'pass', 'CORP defined.')
    : f('corp', 'Headers', 'Cross-Origin-Resource-Policy set', 'info', 'No CORP header.', 'Consider same-origin/ same-site.'));

  // CORS misconfiguration
  const acao = H(h, 'access-control-allow-origin');
  const acac = H(h, 'access-control-allow-credentials');
  if (acao === '*' && /true/i.test(acac || '')) {
    out.push(f('cors', 'Headers', 'CORS not dangerously permissive', 'fail', 'Allow-Origin: * combined with Allow-Credentials: true.', 'Never combine a wildcard origin with credentials.', 2));
  } else if (acao === '*') {
    out.push(f('cors', 'Headers', 'CORS not dangerously permissive', 'info', 'Access-Control-Allow-Origin: * (acceptable for public, non-credentialed data).'));
  } else if (acao) {
    out.push(f('cors', 'Headers', 'CORS not dangerously permissive', 'pass', 'Access-Control-Allow-Origin is scoped.'));
  }

  return out;
}

// ---------------------------------------------------------------------------
// Cookies (expands per cookie => contributes to a higher total check count)
// ---------------------------------------------------------------------------
function analyzeCookies(ev) {
  const out = [];
  const cookies = ev.setCookies || [];
  if (cookies.length === 0) {
    out.push(f('cookies-none', 'Cookies', 'Cookie security', 'info', 'No Set-Cookie headers were observed on this response.'));
    return out;
  }
  cookies.forEach((raw, i) => {
    const name = (raw.split('=')[0] || `cookie ${i + 1}`).trim();
    const secure = /;\s*secure/i.test(raw);
    const httpOnly = /;\s*httponly/i.test(raw);
    const sameSite = /;\s*samesite=/i.test(raw);
    out.push(secure
      ? f(`cookie-secure-${i}`, 'Cookies', `"${name}" has Secure flag`, 'pass', 'Sent only over HTTPS.')
      : f(`cookie-secure-${i}`, 'Cookies', `"${name}" has Secure flag`, 'fail', 'Missing Secure flag.', 'Add the Secure attribute.', 1));
    out.push(httpOnly
      ? f(`cookie-httponly-${i}`, 'Cookies', `"${name}" has HttpOnly flag`, 'pass', 'Not readable by JavaScript.')
      : f(`cookie-httponly-${i}`, 'Cookies', `"${name}" has HttpOnly flag`, 'warn', 'Missing HttpOnly flag.', 'Add HttpOnly for session cookies.', 1));
    out.push(sameSite
      ? f(`cookie-samesite-${i}`, 'Cookies', `"${name}" has SameSite`, 'pass', 'SameSite attribute set.')
      : f(`cookie-samesite-${i}`, 'Cookies', `"${name}" has SameSite`, 'warn', 'No SameSite attribute.', 'Add SameSite=Lax or Strict.', 1));
  });
  return out;
}

// ---------------------------------------------------------------------------
// Information disclosure
// ---------------------------------------------------------------------------
function analyzeDisclosure(ev) {
  const out = [];
  const h = ev.headers || {};
  const server = H(h, 'server');
  if (server && /[0-9]/.test(server)) {
    out.push(f('server-version', 'Disclosure', 'Server version hidden', 'warn', `Server header reveals "${server}".`, 'Suppress version numbers in the Server header.', 1));
  } else {
    out.push(f('server-version', 'Disclosure', 'Server version hidden', 'pass', server ? 'Server header reveals no version.' : 'No Server header.'));
  }
  const xpb = H(h, 'x-powered-by');
  out.push(xpb
    ? f('x-powered-by', 'Disclosure', 'No X-Powered-By disclosure', 'warn', `Reveals "${xpb}".`, 'Remove the X-Powered-By header.', 1)
    : f('x-powered-by', 'Disclosure', 'No X-Powered-By disclosure', 'pass', 'Header not present.'));
  const aspnet = H(h, 'x-aspnet-version') || H(h, 'x-aspnetmvc-version');
  if (aspnet) out.push(f('aspnet-version', 'Disclosure', 'No framework version disclosure', 'warn', `Reveals "${aspnet}".`, 'Remove X-AspNet(-Mvc)-Version headers.', 1));

  return out;
}

// ---------------------------------------------------------------------------
// DNS & email authentication
// ---------------------------------------------------------------------------
function analyzeDns(ev) {
  const out = [];
  const d = ev.dns || {};

  out.push((d.a && d.a.length)
    ? f('dns-a', 'DNS & Email', 'DNS A record present', 'pass', `Resolves to ${d.a.length} address(es).`)
    : f('dns-a', 'DNS & Email', 'DNS A record present', 'info', 'No A records resolved (may use AAAA/ALIAS).'));

  out.push((d.caa && d.caa.length)
    ? f('caa', 'DNS & Email', 'CAA record present', 'pass', 'Certificate issuance is restricted via CAA.')
    : f('caa', 'DNS & Email', 'CAA record present', 'info', 'No CAA record.', 'Add a CAA record to control which CAs can issue certs.'));

  const hasMx = d.mx && d.mx.length;
  if (hasMx) {
    out.push(f('mx', 'DNS & Email', 'Mail (MX) records present', 'info', `Domain receives email (${d.mx.length} MX record(s)).`));

    const spf = (d.txt || []).find((t) => /v=spf1/i.test(t));
    out.push(spf
      ? f('spf', 'DNS & Email', 'SPF record present', 'pass', 'An SPF policy is published.')
      : f('spf', 'DNS & Email', 'SPF record present', 'warn', 'No SPF record found.', 'Publish a TXT record starting with v=spf1.', 1));
    if (spf && /\+all/i.test(spf)) {
      out.push(f('spf-all', 'DNS & Email', 'SPF not overly permissive', 'fail', 'SPF ends with +all (allows anyone to send).', 'Use -all or ~all instead of +all.', 2));
    } else if (spf) {
      out.push(f('spf-all', 'DNS & Email', 'SPF not overly permissive', 'pass', 'SPF does not use +all.'));
    }

    const dmarc = (d.dmarc || []).find((t) => /v=dmarc1/i.test(t));
    out.push(dmarc
      ? f('dmarc', 'DNS & Email', 'DMARC record present', 'pass', 'A DMARC policy is published.')
      : f('dmarc', 'DNS & Email', 'DMARC record present', 'warn', 'No DMARC record found.', 'Publish a _dmarc TXT record.', 1));
    if (dmarc && /p=none/i.test(dmarc)) {
      out.push(f('dmarc-policy', 'DNS & Email', 'DMARC policy enforced', 'warn', 'DMARC policy is p=none (monitoring only).', 'Move to p=quarantine or p=reject once confident.', 1));
    } else if (dmarc) {
      out.push(f('dmarc-policy', 'DNS & Email', 'DMARC policy enforced', 'pass', 'DMARC enforces a policy.'));
    }
  } else {
    out.push(f('mx', 'DNS & Email', 'Mail (MX) records', 'info', 'No MX records — domain does not appear to receive email.'));
  }

  return out;
}

// ---------------------------------------------------------------------------
// Content & configuration
// ---------------------------------------------------------------------------
function analyzeContent(ev) {
  const out = [];

  if (ev.robots) {
    out.push(ev.robots.found
      ? f('robots', 'Content', 'robots.txt present', 'info', 'A robots.txt file is published.')
      : f('robots', 'Content', 'robots.txt present', 'info', 'No robots.txt found.', 'Optional: add robots.txt to guide crawlers.'));
  }
  if (ev.securityTxt) {
    out.push(ev.securityTxt.found
      ? f('security-txt', 'Content', 'security.txt present', 'pass', 'A /.well-known/security.txt contact is published.')
      : f('security-txt', 'Content', 'security.txt present', 'info', 'No security.txt found.', 'Add /.well-known/security.txt with a disclosure contact.'));
  }

  // Mixed content (http:// references inside an https page)
  if ((ev.finalUrl || '').startsWith('https://') && typeof ev.bodySnippet === 'string') {
    const mixed = /(?:src|href)\s*=\s*["']http:\/\//i.test(ev.bodySnippet);
    out.push(mixed
      ? f('mixed-content', 'Content', 'No mixed content', 'warn', 'Page references resources over plain http://.', 'Load all resources over https://.', 1)
      : f('mixed-content', 'Content', 'No mixed content', 'pass', 'No insecure http:// resources detected in the sampled HTML.'));
  }

  // Caching headers (informational)
  const cc = H(ev.headers, 'cache-control');
  out.push(cc
    ? f('cache-control', 'Content', 'Cache-Control header set', 'info', `Cache-Control: ${cc}.`)
    : f('cache-control', 'Content', 'Cache-Control header set', 'info', 'No Cache-Control header.', 'Set explicit caching directives.'));

  return out;
}

// ---------------------------------------------------------------------------
// Compose the full report + score
// ---------------------------------------------------------------------------
export function analyze(evidence) {
  const findings = [
    ...analyzeTransport(evidence),
    ...analyzeHeaders(evidence),
    ...analyzeCookies(evidence),
    ...analyzeDisclosure(evidence),
    ...analyzeDns(evidence),
    ...analyzeContent(evidence),
  ];

  // Score: weighted, ignoring purely informational checks.
  let earned = 0;
  let possible = 0;
  const value = { pass: 1, warn: 0.5, fail: 0 };
  for (const fd of findings) {
    if (fd.status === 'info') continue;
    possible += fd.weight;
    earned += fd.weight * value[fd.status];
  }
  const score = possible ? Math.round((earned / possible) * 100) : 0;
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

  const summary = {
    pass: findings.filter((x) => x.status === 'pass').length,
    warn: findings.filter((x) => x.status === 'warn').length,
    fail: findings.filter((x) => x.status === 'fail').length,
    info: findings.filter((x) => x.status === 'info').length,
  };

  // Group by category for display.
  const categories = {};
  for (const fd of findings) (categories[fd.category] ||= []).push(fd);

  return {
    target: evidence.finalUrl || evidence.url,
    scannedAt: new Date().toISOString(),
    score,
    grade,
    total: findings.length,
    summary,
    categories,
    findings,
  };
}

export const _internal = {
  analyzeTransport,
  analyzeHeaders,
  analyzeCookies,
  analyzeDisclosure,
  analyzeDns,
  analyzeContent,
};
