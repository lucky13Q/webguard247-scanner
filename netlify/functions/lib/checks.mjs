// WebGuard247 — passive security analysis engine (v2, 100+ checks).
// PURE FUNCTIONS ONLY: these take already-collected "evidence" and return findings.
// No network access happens here, which is exactly why it can be unit-tested offline.
//
// A "finding" looks like:
//   { id, category, title, status, detail, recommendation, weight }
//   status: 'pass' | 'warn' | 'fail' | 'info'
//   weight: how much it counts toward the score (info findings are excluded)
//
// Every check is written defensively: if a piece of evidence is missing it
// degrades to an informational finding rather than throwing.

const H = (headers, name) => {
  if (!headers) return undefined;
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(', ') : v;
};

function f(id, category, title, status, detail, recommendation = '', weight = 1) {
  return { id, category, title, status, detail, recommendation, weight };
}

// CSP directive lookup helper
function cspDir(csp, name) {
  if (!csp) return null;
  const re = new RegExp('(?:^|;)\\s*' + name + '\\s+([^;]+)', 'i');
  const m = re.exec(csp);
  return m ? m[1].trim() : null;
}
function cspHas(csp, name) {
  if (!csp) return false;
  return new RegExp('(?:^|;)\\s*' + name + '(?:\\s|;|$)', 'i').test(csp);
}

// ---------------------------------------------------------------------------
// Transport: reachability, HTTPS, redirects, TLS certificate & negotiation
// ---------------------------------------------------------------------------
function analyzeTransport(ev) {
  const out = [];
  const T = 'Transport';

  out.push(
    ev.reachable
      ? f('reachable', T, 'Site is reachable', 'pass', `Responded with HTTP ${ev.statusCode}.`)
      : f('reachable', T, 'Site is reachable', 'fail', ev.error || 'No response from the server.', 'Make sure the domain resolves and the server is online.', 3)
  );

  const isHttps = (ev.finalUrl || ev.url || '').startsWith('https://');
  out.push(
    isHttps
      ? f('https', T, 'Served over HTTPS', 'pass', 'The final page is delivered over an encrypted connection.')
      : f('https', T, 'Served over HTTPS', 'fail', 'The page is served over plain HTTP.', 'Install a TLS certificate and serve everything over HTTPS.', 3)
  );

  // HTTP -> HTTPS upgrade
  const chain = ev.redirectChain || [];
  const upgraded = chain.some((h) => (h.from || '').startsWith('http://') && (h.to || '').startsWith('https://'));
  out.push(
    (upgraded || isHttps)
      ? f('http-redirect', T, 'HTTP upgrades to HTTPS', 'pass', 'Plain-HTTP visitors are sent to a secure connection.')
      : f('http-redirect', T, 'HTTP upgrades to HTTPS', 'warn', 'An HTTP request was not upgraded to HTTPS.', 'Add a 301 redirect from http:// to https://.', 2)
  );

  // No HTTPS -> HTTP downgrade anywhere in the chain
  const downgraded = chain.some((h) => (h.from || '').startsWith('https://') && (h.to || '').startsWith('http://'));
  out.push(
    downgraded
      ? f('redirect-no-downgrade', T, 'No HTTPS→HTTP downgrade', 'fail', 'A redirect sends users from HTTPS back to HTTP.', 'Never redirect from https:// to http://.', 2)
      : f('redirect-no-downgrade', T, 'No HTTPS→HTTP downgrade', 'pass', 'No secure-to-insecure redirects were seen.')
  );

  // Redirect count sane
  out.push(
    chain.length <= 3
      ? f('redirect-count', T, 'Reasonable redirect count', 'pass', `${chain.length} redirect(s) before the final page.`)
      : f('redirect-count', T, 'Reasonable redirect count', 'warn', `${chain.length} redirects before the final page.`, 'Reduce redirect hops to speed up and avoid loops.', 1)
  );

  const tls = ev.tls || null;
  if (isHttps) {
    if (!tls || tls.error) {
      out.push(f('tls-valid', T, 'Valid TLS certificate', 'fail', (tls && tls.error) || 'Certificate could not be validated.', 'Reissue a valid certificate (Let’s Encrypt is free).', 3));
    } else {
      out.push(f('tls-valid', T, 'Valid TLS certificate', 'pass', `Issued by ${tls.issuer || 'a trusted CA'}.`));

      // Already valid (not future-dated)
      if (typeof tls.validFromOk === 'boolean') {
        out.push(tls.validFromOk
          ? f('tls-validfrom', T, 'Certificate already valid', 'pass', 'The certificate validity period has begun.')
          : f('tls-validfrom', T, 'Certificate already valid', 'fail', 'The certificate is not yet valid (future start date).', 'Check the server clock and certificate dates.', 2));
      }

      // Expiry
      if (typeof tls.daysToExpiry === 'number') {
        if (tls.daysToExpiry < 0) out.push(f('tls-expiry', T, 'Certificate not expired', 'fail', `Expired ${Math.abs(tls.daysToExpiry)} days ago.`, 'Renew immediately.', 3));
        else if (tls.daysToExpiry < 14) out.push(f('tls-expiry', T, 'Certificate not expiring soon', 'warn', `Expires in ${tls.daysToExpiry} days.`, 'Renew now and enable auto-renewal.', 2));
        else out.push(f('tls-expiry', T, 'Certificate not expiring soon', 'pass', `Valid for another ${tls.daysToExpiry} days.`));
      }

      // Negotiated protocol modern
      if (tls.protocol) {
        const weak = /SSL|TLSv1(\.0|\.1)?$/i.test(tls.protocol) && !/TLSv1\.2|TLSv1\.3/i.test(tls.protocol);
        out.push(weak
          ? f('tls-version', T, 'Modern TLS protocol', 'fail', `Negotiated ${tls.protocol}.`, 'Disable TLS 1.0/1.1 and require TLS 1.2+.', 2)
          : f('tls-version', T, 'Modern TLS protocol', 'pass', `Negotiated ${tls.protocol}.`));
      }

      // TLS 1.3 supported
      if (typeof tls.tls13 === 'boolean') {
        out.push(tls.tls13
          ? f('tls13', T, 'TLS 1.3 supported', 'pass', 'The server supports the latest TLS 1.3 protocol.')
          : f('tls13', T, 'TLS 1.3 supported', 'info', 'TLS 1.3 was not negotiated.', 'Enable TLS 1.3 for better speed and security.'));
      }

      // Legacy TLS disabled
      if (typeof tls.legacyAccepted === 'boolean') {
        out.push(tls.legacyAccepted
          ? f('tls-legacy-disabled', T, 'Legacy TLS disabled', 'fail', 'The server still accepts TLS 1.0/1.1.', 'Disable TLS 1.0 and 1.1 at the server/CDN.', 2)
          : f('tls-legacy-disabled', T, 'Legacy TLS disabled', 'pass', 'Obsolete TLS 1.0/1.1 are refused.'));
      }

      // Cipher strength
      if (tls.cipher) {
        const c = typeof tls.cipher === 'string' ? tls.cipher : (tls.cipher.name || '');
        const weakCipher = /RC4|DES|3DES|MD5|NULL|EXPORT/i.test(c);
        out.push(weakCipher
          ? f('tls-cipher-strong', T, 'Strong cipher suite', 'fail', `Weak cipher negotiated: ${c}.`, 'Disable weak ciphers (RC4/3DES/DES).', 2)
          : f('tls-cipher-strong', T, 'Strong cipher suite', 'pass', `Negotiated ${c}.`));
        // Forward secrecy
        const fs = /ECDHE|DHE/i.test(c) || tls.forwardSecrecy === true;
        out.push(fs
          ? f('tls-forward-secrecy', T, 'Forward secrecy', 'pass', 'The cipher provides forward secrecy (ECDHE/DHE).')
          : f('tls-forward-secrecy', T, 'Forward secrecy', 'warn', 'No forward-secrecy key exchange detected.', 'Prefer ECDHE cipher suites.', 1));
      }

      // Certificate key size (EC keys are strong at 256-bit; RSA needs 2048+)
      if (typeof tls.keyBits === 'number' && tls.keyBits > 0) {
        const isEc = /ec|ecdsa|ecc/i.test(tls.keyType || '') || (tls.keyBits >= 224 && tls.keyBits <= 600);
        const strong = isEc ? tls.keyBits >= 224 : tls.keyBits >= 2048;
        const kind = isEc ? 'EC' : 'RSA';
        out.push(strong
          ? f('tls-keysize', T, 'Strong certificate key', 'pass', `${tls.keyBits}-bit ${kind} key.`)
          : f('tls-keysize', T, 'Strong certificate key', 'fail', `Weak ${tls.keyBits}-bit ${kind} key.`, 'Use a 2048-bit RSA or 256-bit EC key or stronger.', 2));
      }

      // Chain provided
      if (typeof tls.chainProvided === 'boolean') {
        out.push(tls.chainProvided
          ? f('tls-chain', T, 'Certificate chain served', 'pass', 'Intermediate certificate(s) are provided.')
          : f('tls-chain', T, 'Certificate chain served', 'warn', 'No intermediate chain was served.', 'Serve the full certificate chain to avoid trust errors.', 1));
      }

      // Certificate lifetime within CA/Browser limits
      if (typeof tls.lifetimeDays === 'number' && tls.lifetimeDays > 0) {
        out.push(tls.lifetimeDays <= 398
          ? f('tls-cert-lifetime', T, 'Certificate lifetime within limits', 'pass', `Issued for ${tls.lifetimeDays} days.`)
          : f('tls-cert-lifetime', T, 'Certificate lifetime within limits', 'warn', `Issued for ${tls.lifetimeDays} days (over the 398-day max).`, 'Use certificates valid for 398 days or fewer.', 1));
      }

      // Hostname match
      if (tls.hostMatch === false) out.push(f('tls-hostmatch', T, 'Certificate matches hostname', 'fail', 'The certificate does not cover this hostname.', 'Issue a certificate that includes this domain in its SAN list.', 2));
      else if (tls.hostMatch === true) out.push(f('tls-hostmatch', T, 'Certificate matches hostname', 'pass', 'The certificate covers this hostname.'));

      // OCSP stapling
      if (typeof tls.ocspStapled === 'boolean') {
        out.push(tls.ocspStapled
          ? f('ocsp-stapling', T, 'OCSP stapling', 'pass', 'The server staples a fresh revocation response.')
          : f('ocsp-stapling', T, 'OCSP stapling', 'info', 'OCSP stapling not detected.', 'Enable OCSP stapling to speed up revocation checks.'));
      }

      // ALPN / HTTP/2
      if (tls.alpn) {
        out.push(/h2|h3/i.test(tls.alpn)
          ? f('alpn-http2', T, 'Modern HTTP version (HTTP/2+)', 'pass', `Negotiated ${tls.alpn}.`)
          : f('alpn-http2', T, 'Modern HTTP version (HTTP/2+)', 'info', `Negotiated ${tls.alpn}.`, 'Enable HTTP/2 for better performance.'));
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
  const C = 'Headers';
  const h = ev.headers || {};
  const isHttps = (ev.finalUrl || '').startsWith('https://');

  // HSTS
  const hsts = H(h, 'strict-transport-security');
  if (hsts) {
    out.push(f('hsts', C, 'HSTS enabled', 'pass', 'Strict-Transport-Security is set.'));
    const m = /max-age=(\d+)/i.exec(hsts);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    out.push(maxAge >= 31536000
      ? f('hsts-maxage', C, 'HSTS max-age ≥ 1 year', 'pass', `max-age=${maxAge}.`)
      : f('hsts-maxage', C, 'HSTS max-age ≥ 1 year', 'warn', `max-age=${maxAge} is short.`, 'Set max-age to 31536000 or more.', 1));
    out.push(/includeSubDomains/i.test(hsts)
      ? f('hsts-subdomains', C, 'HSTS covers subdomains', 'pass', 'includeSubDomains is present.')
      : f('hsts-subdomains', C, 'HSTS covers subdomains', 'info', 'includeSubDomains is not set.', 'Add includeSubDomains if all subdomains use HTTPS.'));
    out.push(/preload/i.test(hsts)
      ? f('hsts-preload', C, 'HSTS preload requested', 'info', 'preload directive present.')
      : f('hsts-preload', C, 'HSTS preload requested', 'info', 'Not submitted for preload.', 'Optional: submit to hstspreload.org.'));
  } else if (isHttps) {
    out.push(f('hsts', C, 'HSTS enabled', 'fail', 'Strict-Transport-Security header is missing.', 'Add Strict-Transport-Security with a long max-age.', 2));
  }

  // CSP + sub-directives
  const csp = H(h, 'content-security-policy');
  if (csp) {
    out.push(f('csp', C, 'Content-Security-Policy set', 'pass', 'A CSP is defined.'));
    out.push(/unsafe-inline|unsafe-eval/i.test(csp)
      ? f('csp-unsafe', C, 'CSP avoids unsafe directives', 'warn', "Policy contains 'unsafe-inline' or 'unsafe-eval'.", 'Remove unsafe directives; use nonces or hashes.', 1)
      : f('csp-unsafe', C, 'CSP avoids unsafe directives', 'pass', 'No unsafe-inline/unsafe-eval found.'));
    out.push(cspHas(csp, 'frame-ancestors')
      ? f('csp-frameancestors', C, 'CSP restricts framing', 'pass', 'frame-ancestors directive present.')
      : f('csp-frameancestors', C, 'CSP restricts framing', 'info', 'No frame-ancestors directive.', 'Add frame-ancestors to control embedding.'));
    out.push((cspHas(csp, 'default-src'))
      ? f('csp-default-src', C, 'CSP has default-src', 'pass', 'A default-src fallback is defined.')
      : f('csp-default-src', C, 'CSP has default-src', 'warn', 'No default-src directive.', 'Add default-src to set a safe baseline.', 1));
    out.push((cspDir(csp, 'object-src') && /none/i.test(cspDir(csp, 'object-src')))
      ? f('csp-object-src', C, "CSP object-src 'none'", 'pass', 'Legacy plugin content is blocked.')
      : f('csp-object-src', C, "CSP object-src 'none'", 'info', "object-src is not 'none'.", "Set object-src 'none' to block plugins."));
    out.push(cspHas(csp, 'base-uri')
      ? f('csp-base-uri', C, 'CSP restricts base-uri', 'pass', 'base-uri directive present.')
      : f('csp-base-uri', C, 'CSP restricts base-uri', 'info', 'No base-uri directive.', "Add base-uri 'self' to block base-tag injection."));
    out.push(cspHas(csp, 'upgrade-insecure-requests')
      ? f('csp-upgrade-insecure', C, 'CSP upgrades insecure requests', 'pass', 'upgrade-insecure-requests is set.')
      : f('csp-upgrade-insecure', C, 'CSP upgrades insecure requests', 'info', 'No upgrade-insecure-requests.', 'Optional: auto-upgrade http subresources.'));
  } else {
    out.push(f('csp', C, 'Content-Security-Policy set', 'warn', 'No Content-Security-Policy header.', 'Add a CSP to mitigate XSS and injection.', 2));
  }

  // Clickjacking
  const xfo = H(h, 'x-frame-options');
  out.push((xfo || (csp && cspHas(csp, 'frame-ancestors')))
    ? f('clickjacking', C, 'Clickjacking protection', 'pass', xfo ? `X-Frame-Options: ${xfo}.` : 'Protected via CSP frame-ancestors.')
    : f('clickjacking', C, 'Clickjacking protection', 'fail', 'No X-Frame-Options and no frame-ancestors.', 'Add X-Frame-Options: SAMEORIGIN or a CSP frame-ancestors directive.', 2));

  // MIME sniffing
  out.push(/nosniff/i.test(H(h, 'x-content-type-options') || '')
    ? f('nosniff', C, 'MIME-sniffing disabled', 'pass', 'X-Content-Type-Options: nosniff.')
    : f('nosniff', C, 'MIME-sniffing disabled', 'fail', 'X-Content-Type-Options is missing or not nosniff.', 'Add X-Content-Type-Options: nosniff.', 1));

  // Referrer-Policy
  const rp = H(h, 'referrer-policy');
  out.push(rp
    ? f('referrer', C, 'Referrer-Policy set', 'pass', `Referrer-Policy: ${rp}.`)
    : f('referrer', C, 'Referrer-Policy set', 'warn', 'No Referrer-Policy header.', 'Add e.g. Referrer-Policy: strict-origin-when-cross-origin.', 1));
  out.push((rp && /no-referrer|strict-origin|same-origin/i.test(rp))
    ? f('referrer-strict', C, 'Referrer-Policy is privacy-preserving', 'pass', 'A strict referrer policy is used.')
    : f('referrer-strict', C, 'Referrer-Policy is privacy-preserving', rp ? 'info' : 'info', rp ? `Policy "${rp}" may leak referrers.` : 'No policy set.', 'Prefer strict-origin-when-cross-origin or stricter.'));

  // Permissions-Policy
  const pp = H(h, 'permissions-policy');
  out.push(pp
    ? f('permissions', C, 'Permissions-Policy set', 'pass', 'Permissions-Policy is defined.')
    : f('permissions', C, 'Permissions-Policy set', 'info', 'No Permissions-Policy header.', 'Optionally restrict camera/microphone/geolocation features.'));
  out.push((pp && /geolocation|camera|microphone/i.test(pp))
    ? f('permissions-restrictive', C, 'Permissions-Policy restricts sensitive features', 'pass', 'Sensitive browser features are constrained.')
    : f('permissions-restrictive', C, 'Permissions-Policy restricts sensitive features', 'info', 'Sensitive features not explicitly restricted.', 'Restrict camera, microphone and geolocation by default.'));

  // Cross-origin isolation trio
  out.push(H(h, 'cross-origin-opener-policy')
    ? f('coop', C, 'Cross-Origin-Opener-Policy set', 'pass', 'COOP defined.')
    : f('coop', C, 'Cross-Origin-Opener-Policy set', 'info', 'No COOP header.', 'Consider same-origin for isolation.'));
  out.push(H(h, 'cross-origin-resource-policy')
    ? f('corp', C, 'Cross-Origin-Resource-Policy set', 'pass', 'CORP defined.')
    : f('corp', C, 'Cross-Origin-Resource-Policy set', 'info', 'No CORP header.', 'Consider same-origin/same-site.'));
  out.push(H(h, 'cross-origin-embedder-policy')
    ? f('coep', C, 'Cross-Origin-Embedder-Policy set', 'pass', 'COEP defined.')
    : f('coep', C, 'Cross-Origin-Embedder-Policy set', 'info', 'No COEP header.', 'Set COEP for cross-origin isolation when needed.'));

  // CORS misconfiguration
  const acao = H(h, 'access-control-allow-origin');
  const acac = H(h, 'access-control-allow-credentials');
  if (acao === '*' && /true/i.test(acac || '')) {
    out.push(f('cors', C, 'CORS not dangerously permissive', 'fail', 'Allow-Origin: * combined with Allow-Credentials: true.', 'Never combine a wildcard origin with credentials.', 2));
  } else if (acao === '*') {
    out.push(f('cors', C, 'CORS not dangerously permissive', 'info', 'Access-Control-Allow-Origin: * (fine for public, non-credentialed data).'));
  } else {
    out.push(f('cors', C, 'CORS not dangerously permissive', 'pass', acao ? 'Access-Control-Allow-Origin is scoped.' : 'No permissive CORS header.'));
  }

  // X-XSS-Protection should be 0 (the old filter is harmful)
  const xxp = H(h, 'x-xss-protection');
  if (xxp !== undefined) {
    out.push(/^0/.test(xxp.trim())
      ? f('xss-protection', C, 'Legacy XSS filter disabled', 'pass', 'X-XSS-Protection: 0 (correct modern practice).')
      : f('xss-protection', C, 'Legacy XSS filter disabled', 'warn', `X-XSS-Protection: ${xxp}.`, 'Set X-XSS-Protection: 0 and rely on CSP.', 1));
  } else {
    out.push(f('xss-protection', C, 'Legacy XSS filter disabled', 'pass', 'No legacy X-XSS-Protection header (correct).'));
  }

  // X-Permitted-Cross-Domain-Policies
  out.push(H(h, 'x-permitted-cross-domain-policies')
    ? f('x-permitted-cdp', C, 'Cross-domain policy controlled', 'pass', 'X-Permitted-Cross-Domain-Policies set.')
    : f('x-permitted-cdp', C, 'Cross-domain policy controlled', 'info', 'Header not set.', "Optionally set to 'none' to block Adobe cross-domain access."));

  // X-DNS-Prefetch-Control
  out.push(H(h, 'x-dns-prefetch-control')
    ? f('x-dns-prefetch', C, 'DNS prefetch controlled', 'info', `X-DNS-Prefetch-Control: ${H(h, 'x-dns-prefetch-control')}.`)
    : f('x-dns-prefetch', C, 'DNS prefetch controlled', 'info', 'Header not set.', 'Optional privacy hardening.'));

  // Reporting endpoints
  out.push((H(h, 'report-to') || H(h, 'reporting-endpoints'))
    ? f('report-to', C, 'Reporting endpoint configured', 'info', 'A reporting endpoint is configured.')
    : f('report-to', C, 'Reporting endpoint configured', 'info', 'No Report-To/Reporting-Endpoints header.', 'Optional: collect CSP/violation reports.'));

  // NEL
  out.push(H(h, 'nel')
    ? f('nel', C, 'Network Error Logging', 'info', 'NEL is configured.')
    : f('nel', C, 'Network Error Logging', 'info', 'No NEL header.', 'Optional: enable NEL for reliability telemetry.'));

  // Expect-CT (legacy; informational)
  out.push(H(h, 'expect-ct')
    ? f('expect-ct', C, 'Certificate Transparency policy', 'info', 'Expect-CT header present (now largely deprecated).')
    : f('expect-ct', C, 'Certificate Transparency policy', 'info', 'No Expect-CT header (CT is now enforced by browsers anyway).'));

  // Feature-Policy (predecessor of Permissions-Policy)
  out.push(H(h, 'feature-policy')
    ? f('feature-policy', C, 'Feature-Policy present', 'info', 'Legacy Feature-Policy header present.', 'Migrate to Permissions-Policy.')
    : f('feature-policy', C, 'Feature-Policy present', 'info', 'No legacy Feature-Policy (Permissions-Policy is preferred).'));

  // Cookies should not be cached by shared caches
  const ccHdr = H(h, 'cache-control') || '';
  if ((ev.setCookies || []).length) {
    out.push(/(no-store|no-cache|private)/i.test(ccHdr)
      ? f('cookie-cache', C, 'Cookies not publicly cacheable', 'pass', 'Responses that set cookies are marked private/no-store.')
      : f('cookie-cache', C, 'Cookies not publicly cacheable', 'warn', 'A response set a cookie without a private/no-store cache directive.', 'Mark cookie responses Cache-Control: private or no-store.', 1));
  } else {
    out.push(f('cookie-cache', C, 'Cookies not publicly cacheable', 'pass', 'No cookies set on this response.'));
  }

  // Content-Type with charset
  const ct = H(h, 'content-type');
  out.push((ct && /charset=/i.test(ct))
    ? f('content-type-charset', C, 'Content-Type declares charset', 'pass', `${ct}.`)
    : f('content-type-charset', C, 'Content-Type declares charset', 'info', ct ? `Content-Type: ${ct} (no charset).` : 'No Content-Type header.', 'Declare ; charset=utf-8 to avoid sniffing.'));

  return out;
}

// ---------------------------------------------------------------------------
// Cookies (per-cookie flag checks)
// ---------------------------------------------------------------------------
function analyzeCookies(ev) {
  const out = [];
  const C = 'Cookies';
  const cookies = ev.setCookies || [];
  if (cookies.length === 0) {
    out.push(f('cookies-none', C, 'Cookie security', 'info', 'No Set-Cookie headers were observed on this response.'));
    return out;
  }
  cookies.forEach((raw, i) => {
    const name = (raw.split('=')[0] || `cookie ${i + 1}`).trim();
    const secure = /;\s*secure/i.test(raw);
    const httpOnly = /;\s*httponly/i.test(raw);
    const ssMatch = /;\s*samesite=(\w+)/i.exec(raw);
    const sameSite = !!ssMatch;
    out.push(secure
      ? f(`cookie-secure-${i}`, C, `"${name}" has Secure flag`, 'pass', 'Sent only over HTTPS.')
      : f(`cookie-secure-${i}`, C, `"${name}" has Secure flag`, 'fail', 'Missing Secure flag.', 'Add the Secure attribute.', 1));
    out.push(httpOnly
      ? f(`cookie-httponly-${i}`, C, `"${name}" has HttpOnly flag`, 'pass', 'Not readable by JavaScript.')
      : f(`cookie-httponly-${i}`, C, `"${name}" has HttpOnly flag`, 'warn', 'Missing HttpOnly flag.', 'Add HttpOnly for session cookies.', 1));
    out.push(sameSite
      ? f(`cookie-samesite-${i}`, C, `"${name}" sets SameSite`, 'pass', `SameSite=${ssMatch[1]}.`)
      : f(`cookie-samesite-${i}`, C, `"${name}" sets SameSite`, 'warn', 'No SameSite attribute.', 'Add SameSite=Lax or Strict.', 1));
    // SameSite=None must be Secure
    if (ssMatch && /none/i.test(ssMatch[1])) {
      out.push(secure
        ? f(`cookie-ss-none-secure-${i}`, C, `"${name}" SameSite=None is Secure`, 'pass', 'SameSite=None correctly paired with Secure.')
        : f(`cookie-ss-none-secure-${i}`, C, `"${name}" SameSite=None is Secure`, 'fail', 'SameSite=None without Secure is rejected by browsers.', 'Add Secure whenever SameSite=None.', 1));
    }
    // Host/Secure prefix hardening (info)
    out.push(/^__(Secure|Host)-/i.test(name)
      ? f(`cookie-prefix-${i}`, C, `"${name}" uses a hardening prefix`, 'pass', 'Cookie name uses a __Secure-/__Host- prefix.')
      : f(`cookie-prefix-${i}`, C, `"${name}" uses a hardening prefix`, 'info', 'No __Secure-/__Host- prefix.', 'Consider prefixes for sensitive cookies.'));
  });
  return out;
}

// ---------------------------------------------------------------------------
// Information disclosure
// ---------------------------------------------------------------------------
function analyzeDisclosure(ev) {
  const out = [];
  const C = 'Disclosure';
  const h = ev.headers || {};

  const server = H(h, 'server');
  if (server && /[0-9]/.test(server)) out.push(f('server-version', C, 'Server version hidden', 'warn', `Server header reveals "${server}".`, 'Suppress version numbers in the Server header.', 1));
  else out.push(f('server-version', C, 'Server version hidden', 'pass', server ? 'Server header reveals no version.' : 'No Server header.'));

  out.push(server
    ? f('server-present', C, 'Server software exposure', 'info', `Server: ${server}.`)
    : f('server-present', C, 'Server software exposure', 'pass', 'No Server header is sent.'));

  const xpb = H(h, 'x-powered-by');
  out.push(xpb
    ? f('x-powered-by', C, 'No X-Powered-By disclosure', 'warn', `Reveals "${xpb}".`, 'Remove the X-Powered-By header.', 1)
    : f('x-powered-by', C, 'No X-Powered-By disclosure', 'pass', 'Header not present.'));

  const aspnet = H(h, 'x-aspnet-version') || H(h, 'x-aspnetmvc-version');
  out.push(aspnet
    ? f('aspnet-version', C, 'No framework version disclosure', 'warn', `Reveals "${aspnet}".`, 'Remove X-AspNet(-Mvc)-Version headers.', 1)
    : f('aspnet-version', C, 'No framework version disclosure', 'pass', 'No ASP.NET version headers.'));

  out.push(H(h, 'x-generator')
    ? f('x-generator', C, 'No generator disclosure (header)', 'warn', `X-Generator reveals "${H(h, 'x-generator')}".`, 'Remove the X-Generator header.', 1)
    : f('x-generator', C, 'No generator disclosure (header)', 'pass', 'No X-Generator header.'));

  out.push(H(h, 'via')
    ? f('via-header', C, 'No proxy disclosure (Via)', 'info', `Via: ${H(h, 'via')}.`, 'Optionally strip the Via header.')
    : f('via-header', C, 'No proxy disclosure (Via)', 'pass', 'No Via header.'));

  out.push(H(h, 'x-runtime')
    ? f('x-runtime', C, 'No timing disclosure (X-Runtime)', 'warn', 'X-Runtime exposes server processing time.', 'Remove the X-Runtime header.', 1)
    : f('x-runtime', C, 'No timing disclosure (X-Runtime)', 'pass', 'No X-Runtime header.'));

  // Powered-by tech fingerprint from body (info)
  const body = typeof ev.bodySnippet === 'string' ? ev.bodySnippet : '';
  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i.exec(body);
  out.push(gen
    ? f('generator-meta', C, 'No generator <meta> disclosure', 'info', `Page advertises "${gen[1]}".`, 'Optionally remove the generator meta tag.')
    : f('generator-meta', C, 'No generator <meta> disclosure', 'pass', 'No generator meta tag found.'));

  // ETag (can leak inode info on some servers; informational)
  out.push(H(h, 'etag')
    ? f('etag', C, 'ETag header review', 'info', 'An ETag is present (normal; ensure it is not inode-based).')
    : f('etag', C, 'ETag header review', 'pass', 'No ETag header.'));

  // Cache/proxy disclosure
  out.push((H(h, 'x-cache') || H(h, 'x-served-by'))
    ? f('x-cache', C, 'Cache layer disclosure', 'info', 'Cache/CDN headers (X-Cache/X-Served-By) are present.', 'Optional: strip internal cache headers.')
    : f('x-cache', C, 'Cache layer disclosure', 'pass', 'No cache-layer disclosure headers.'));

  // CMS / tech fingerprint from body
  const techMatch = /wp-content|wp-includes/i.test(body) ? 'WordPress'
    : /Drupal\.settings|sites\/default\/files/i.test(body) ? 'Drupal'
    : /\/media\/jui\/|Joomla/i.test(body) ? 'Joomla'
    : /cdn\.shopify\.com/i.test(body) ? 'Shopify' : null;
  out.push(techMatch
    ? f('tech-fingerprint', C, 'Platform fingerprint', 'info', `Page markup suggests ${techMatch}.`, 'Keep the platform patched and reduce obvious fingerprints.')
    : f('tech-fingerprint', C, 'Platform fingerprint', 'info', 'No obvious CMS fingerprint in the sampled HTML.'));

  return out;
}

// ---------------------------------------------------------------------------
// DNS & email authentication
// ---------------------------------------------------------------------------
function analyzeDns(ev) {
  const out = [];
  const C = 'DNS & Email';
  const d = ev.dns || {};

  out.push((d.a && d.a.length)
    ? f('dns-a', C, 'DNS A record present', 'pass', `Resolves to ${d.a.length} IPv4 address(es).`)
    : f('dns-a', C, 'DNS A record present', 'info', 'No A records resolved (may use AAAA/ALIAS).'));

  out.push((d.aaaa && d.aaaa.length)
    ? f('ipv6', C, 'IPv6 (AAAA) available', 'pass', `Reachable over IPv6 (${d.aaaa.length} address(es)).`)
    : f('ipv6', C, 'IPv6 (AAAA) available', 'info', 'No AAAA record.', 'Optional: add IPv6 (AAAA) connectivity.'));

  out.push((d.ns && d.ns.length >= 2)
    ? f('ns-redundancy', C, 'Redundant nameservers', 'pass', `${d.ns.length} nameservers configured.`)
    : f('ns-redundancy', C, 'Redundant nameservers', (d.ns && d.ns.length === 1) ? 'warn' : 'info', (d.ns && d.ns.length) ? `${d.ns.length} nameserver(s).` : 'Nameservers not determined.', 'Use at least two nameservers for resilience.', 1));

  out.push(d.soa
    ? f('soa', C, 'SOA record present', 'pass', 'The zone publishes a Start-of-Authority record.')
    : f('soa', C, 'SOA record present', 'info', 'SOA not determined.'));

  out.push((d.caa && d.caa.length)
    ? f('caa', C, 'CAA record present', 'pass', 'Certificate issuance is restricted via CAA.')
    : f('caa', C, 'CAA record present', 'info', 'No CAA record.', 'Add a CAA record to control which CAs can issue certs.'));

  // DNSSEC (AD flag from a validating resolver)
  if (typeof d.dnssec === 'boolean') {
    out.push(d.dnssec
      ? f('dnssec', C, 'DNSSEC validated', 'pass', 'Responses are DNSSEC-authenticated.')
      : f('dnssec', C, 'DNSSEC validated', 'info', 'DNSSEC not detected.', 'Enable DNSSEC at your DNS provider.'));
  }

  out.push((d.txt && d.txt.length)
    ? f('txt-present', C, 'TXT records published', 'info', `${d.txt.length} TXT record(s) found.`)
    : f('txt-present', C, 'TXT records published', 'info', 'No TXT records resolved.'));

  const hasMx = d.mx && d.mx.length;
  if (hasMx) out.push(f('mx-count', C, 'Mail server redundancy', d.mx.length >= 2 ? 'pass' : 'info', `${d.mx.length} MX record(s).`, d.mx.length >= 2 ? '' : 'Consider a backup MX for resilience.'));
  out.push(hasMx
    ? f('mx', C, 'Mail (MX) records present', 'info', `Domain receives email (${d.mx.length} MX record(s)).`)
    : f('mx', C, 'Mail (MX) records', 'info', 'No MX records — domain does not appear to receive email.'));

  if (hasMx) {
    const txt = d.txt || [];
    const spfs = txt.filter((t) => /v=spf1/i.test(t));
    const spf = spfs[0];
    out.push(spf
      ? f('spf', C, 'SPF record present', 'pass', 'An SPF policy is published.')
      : f('spf', C, 'SPF record present', 'warn', 'No SPF record found.', 'Publish a TXT record starting with v=spf1.', 1));
    out.push(spfs.length <= 1
      ? f('spf-single', C, 'Single SPF record', 'pass', spf ? 'Exactly one SPF record.' : 'No duplicate SPF records.')
      : f('spf-single', C, 'Single SPF record', 'fail', `${spfs.length} SPF records (must be exactly one).`, 'Merge into a single v=spf1 record.', 1));
    if (spf) {
      out.push(/\+all/i.test(spf)
        ? f('spf-all', C, 'SPF not overly permissive', 'fail', 'SPF ends with +all (allows anyone to send).', 'Use -all or ~all instead of +all.', 2)
        : f('spf-all', C, 'SPF not overly permissive', 'pass', 'SPF does not use +all.'));
    }

    const dmarc = (d.dmarc || []).find((t) => /v=dmarc1/i.test(t));
    out.push(dmarc
      ? f('dmarc', C, 'DMARC record present', 'pass', 'A DMARC policy is published.')
      : f('dmarc', C, 'DMARC record present', 'warn', 'No DMARC record found.', 'Publish a _dmarc TXT record.', 1));
    if (dmarc) {
      out.push(/p=none/i.test(dmarc)
        ? f('dmarc-policy', C, 'DMARC policy enforced', 'warn', 'DMARC policy is p=none (monitoring only).', 'Move to p=quarantine or p=reject once confident.', 1)
        : f('dmarc-policy', C, 'DMARC policy enforced', 'pass', 'DMARC enforces a policy.'));
      out.push(/rua=/i.test(dmarc)
        ? f('dmarc-rua', C, 'DMARC aggregate reporting', 'pass', 'Aggregate (rua) reporting is configured.')
        : f('dmarc-rua', C, 'DMARC aggregate reporting', 'info', 'No rua reporting address.', 'Add rua= to receive DMARC reports.'));
      const pct = /pct=(\d+)/i.exec(dmarc);
      out.push((!pct || parseInt(pct[1], 10) === 100)
        ? f('dmarc-pct', C, 'DMARC applies to all mail', 'pass', 'Policy applies to 100% of messages.')
        : f('dmarc-pct', C, 'DMARC applies to all mail', 'warn', `Policy only applies to ${pct[1]}% of mail.`, 'Raise pct to 100 once confident.', 1));
      out.push(/sp=/i.test(dmarc)
        ? f('dmarc-sp', C, 'DMARC subdomain policy', 'pass', 'A subdomain policy (sp=) is set.')
        : f('dmarc-sp', C, 'DMARC subdomain policy', 'info', 'No explicit subdomain policy.', 'Add sp= to cover subdomains explicitly.'));
    }

    // DKIM (common selectors)
    if (d.dkim) {
      const found = Array.isArray(d.dkim) ? d.dkim : (d.dkim.found ? [d.dkim.selector] : []);
      out.push(found.length
        ? f('dkim', C, 'DKIM signing key published', 'pass', `DKIM key found (selector: ${found.join(', ')}).`)
        : f('dkim', C, 'DKIM signing key published', 'info', 'No DKIM key found at common selectors.', 'Publish a DKIM key and sign outbound mail.'));
    }

    // MTA-STS
    if (d.mtaSts !== undefined) {
      out.push((d.mtaSts && d.mtaSts.length)
        ? f('mta-sts', C, 'MTA-STS policy', 'pass', 'An MTA-STS record is published.')
        : f('mta-sts', C, 'MTA-STS policy', 'info', 'No MTA-STS record.', 'Publish MTA-STS to enforce TLS for inbound mail.'));
    }
    // TLS-RPT
    if (d.tlsRpt !== undefined) {
      out.push((d.tlsRpt && d.tlsRpt.length)
        ? f('tls-rpt', C, 'SMTP TLS reporting', 'pass', 'A TLS-RPT record is published.')
        : f('tls-rpt', C, 'SMTP TLS reporting', 'info', 'No TLS-RPT record.', 'Add _smtp._tls TXT to receive TLS failure reports.'));
    }
    // BIMI
    if (d.bimi !== undefined) {
      out.push((d.bimi && d.bimi.length)
        ? f('bimi', C, 'BIMI brand indicator', 'info', 'A BIMI record is published.')
        : f('bimi', C, 'BIMI brand indicator', 'info', 'No BIMI record.', 'Optional: publish BIMI once DMARC is enforced.'));
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Content & configuration
// ---------------------------------------------------------------------------
function analyzeContent(ev) {
  const out = [];
  const C = 'Content';
  const p = ev.probes || {};
  const isHttps = (ev.finalUrl || '').startsWith('https://');
  const body = typeof ev.bodySnippet === 'string' ? ev.bodySnippet : '';

  // robots.txt
  const robots = p.robots || ev.robots;
  if (robots) out.push(robots.found
    ? f('robots', C, 'robots.txt present', 'info', 'A robots.txt file is published.')
    : f('robots', C, 'robots.txt present', 'info', 'No robots.txt found.', 'Optional: add robots.txt to guide crawlers.'));

  // sitemap.xml
  if (p.sitemap !== undefined) out.push(p.sitemap.found
    ? f('sitemap', C, 'sitemap.xml present', 'info', 'A sitemap is published.')
    : f('sitemap', C, 'sitemap.xml present', 'info', 'No sitemap.xml found.', 'Optional: add a sitemap for SEO.'));

  // humans.txt
  if (p.humans !== undefined) out.push(p.humans.found
    ? f('humans-txt', C, 'humans.txt present', 'info', 'A humans.txt file is published.')
    : f('humans-txt', C, 'humans.txt present', 'info', 'No humans.txt (optional).'));

  // security.txt
  const stxt = p.securityTxt || ev.securityTxt;
  if (stxt) out.push(stxt.found
    ? f('security-txt', C, 'security.txt present', 'pass', 'A /.well-known/security.txt contact is published.')
    : f('security-txt', C, 'security.txt present', 'info', 'No security.txt found.', 'Add /.well-known/security.txt with a disclosure contact.'));

  // Mixed content
  if (isHttps) {
    const mixed = /(?:src|href)\s*=\s*["']http:\/\//i.test(body);
    out.push(mixed
      ? f('mixed-content', C, 'No mixed content', 'warn', 'Page references resources over plain http://.', 'Load all resources over https://.', 1)
      : f('mixed-content', C, 'No mixed content', 'pass', 'No insecure http:// resources detected in the sampled HTML.'));
  }

  // Subresource Integrity on external scripts
  if (body) {
    const extScripts = (body.match(/<script[^>]+src=["']https?:\/\/[^"']+["'][^>]*>/gi) || []);
    if (extScripts.length) {
      const withSri = extScripts.filter((s) => /integrity=/i.test(s)).length;
      out.push(withSri === extScripts.length
        ? f('sri', C, 'Subresource Integrity on scripts', 'pass', 'All external scripts use integrity hashes.')
        : f('sri', C, 'Subresource Integrity on scripts', 'info', `${withSri}/${extScripts.length} external scripts use SRI.`, 'Add integrity + crossorigin to third-party scripts.'));
      out.push(f('external-scripts', C, 'Third-party script footprint', 'info', `${extScripts.length} external script(s) referenced.`, 'Minimise third-party JavaScript.'));
    }

    // Forms post to HTTPS
    const forms = (body.match(/<form[^>]*>/gi) || []);
    if (forms.length) {
      const insecure = forms.filter((fm) => /action=["']http:\/\//i.test(fm)).length;
      out.push(insecure === 0
        ? f('forms-https', C, 'Forms submit securely', 'pass', `${forms.length} form(s); none post to http://.`)
        : f('forms-https', C, 'Forms submit securely', 'fail', `${insecure} form(s) post to insecure http://.`, 'Point all form actions at https:// endpoints.', 2));
    }

    // Password field autocomplete (info)
    const pwFields = (body.match(/<input[^>]+type=["']password["'][^>]*>/gi) || []);
    if (pwFields.length) {
      const risky = pwFields.filter((i) => /autocomplete=["']?(on|true)/i.test(i)).length;
      out.push(risky === 0
        ? f('password-autocomplete', C, 'Password fields handled sensibly', 'pass', 'No password fields force autocomplete on.')
        : f('password-autocomplete', C, 'Password fields handled sensibly', 'info', `${risky} password field(s) enable autocomplete.`, 'Review autocomplete on sensitive fields.'));
    }

    // External links use rel=noopener
    const blankLinks = (body.match(/<a[^>]+target=["']_blank["'][^>]*>/gi) || []);
    if (blankLinks.length) {
      const safe = blankLinks.filter((a) => /rel=["'][^"']*noopener/i.test(a)).length;
      out.push(safe === blankLinks.length
        ? f('noopener', C, 'External links use rel=noopener', 'pass', 'target=_blank links include noopener.')
        : f('noopener', C, 'External links use rel=noopener', 'info', `${safe}/${blankLinks.length} _blank links use noopener.`, 'Add rel="noopener" to target=_blank links.'));
    }

    // HTML5 doctype
    out.push(/<!doctype\s+html>/i.test(body)
      ? f('doctype-html5', C, 'HTML5 doctype declared', 'pass', 'The page declares a standards-mode HTML5 doctype.')
      : f('doctype-html5', C, 'HTML5 doctype declared', 'info', 'No <!doctype html> found in the sample.', 'Declare <!doctype html> for standards mode.'));

    // Referrer meta in HTML
    out.push(/<meta[^>]+name=["']referrer["']/i.test(body)
      ? f('meta-referrer', C, 'Referrer controlled in HTML', 'info', 'A <meta name="referrer"> tag is present.')
      : f('meta-referrer', C, 'Referrer controlled in HTML', 'info', 'No referrer meta tag (header-based policy preferred).'));

    // Charset meta
    out.push(/<meta[^>]+charset/i.test(body)
      ? f('charset-meta', C, 'Charset declared in HTML', 'pass', 'A <meta charset> is present.')
      : f('charset-meta', C, 'Charset declared in HTML', 'info', 'No <meta charset> found.', 'Declare <meta charset="utf-8">.'));
  }

  // Cache-Control
  const cc = H(ev.headers, 'cache-control');
  out.push(cc
    ? f('cache-control', C, 'Cache-Control header set', 'info', `Cache-Control: ${cc}.`)
    : f('cache-control', C, 'Cache-Control header set', 'info', 'No Cache-Control header.', 'Set explicit caching directives.'));

  // Exposed sensitive files
  if (p.gitConfig !== undefined) out.push(p.gitConfig.found
    ? f('exposed-git', C, '.git directory not exposed', 'fail', 'A /.git/config file is publicly readable.', 'Block access to the .git directory.', 3)
    : f('exposed-git', C, '.git directory not exposed', 'pass', 'No public /.git/config.'));
  if (p.dotenv !== undefined) out.push(p.dotenv.found
    ? f('exposed-env', C, '.env file not exposed', 'fail', 'A /.env file is publicly readable.', 'Remove or block public access to .env.', 3)
    : f('exposed-env', C, '.env file not exposed', 'pass', 'No public /.env file.'));
  if (p.dsStore !== undefined) out.push(p.dsStore.found
    ? f('exposed-dsstore', C, '.DS_Store not exposed', 'warn', 'A /.DS_Store file is publicly readable (leaks file names).', 'Block access to .DS_Store files.', 1)
    : f('exposed-dsstore', C, '.DS_Store not exposed', 'pass', 'No public /.DS_Store file.'));
  if (p.svn !== undefined) out.push(p.svn.found
    ? f('exposed-svn', C, '.svn metadata not exposed', 'fail', 'A /.svn/entries file is publicly readable.', 'Block access to the .svn directory.', 2)
    : f('exposed-svn', C, '.svn metadata not exposed', 'pass', 'No public /.svn metadata.'));
  if (p.changePassword !== undefined) out.push(p.changePassword.found
    ? f('change-password', C, 'Well-known change-password URL', 'pass', 'A /.well-known/change-password route is published.')
    : f('change-password', C, 'Well-known change-password URL', 'info', 'No change-password well-known route.', 'Optional: add /.well-known/change-password.'));

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

  let earned = 0, possible = 0;
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
  analyzeTransport, analyzeHeaders, analyzeCookies, analyzeDisclosure, analyzeDns, analyzeContent,
};
