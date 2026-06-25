// WebGuard247 — scan endpoint (Netlify Function), v2.
// Collects passive, non-intrusive evidence about a URL and runs the analysis engine.
// Uses only Node built-ins + global fetch, so there are NO dependencies to install.
//
// Passive only: it reads the same things any browser or mail server can see
// (HTTP headers, the TLS certificate, public DNS records, a handful of well-known
// files). It does NOT port scan, brute force, or probe internal systems, and it
// refuses private/internal addresses (SSRF guard).

import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import net from 'node:net';
import { analyze } from './lib/checks.mjs';

const TIMEOUT = 8000;
const TLS_PROBE_TIMEOUT = 4000;
const MAX_REDIRECTS = 5;
const MAX_BODY = 200 * 1024;

// --- SSRF guard ---
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return (p[0] === 10 || p[0] === 127 || (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || p[0] === 0);
  }
  const low = ip.toLowerCase();
  return low === '::1' || low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80') || low === '::';
}
async function guardHost(hostname) {
  if (/^(localhost|.*\.local)$/i.test(hostname)) throw new Error('Refusing to scan a local hostname.');
  const records = await dns.lookup(hostname, { all: true });
  for (const r of records) if (isPrivateIp(r.address)) throw new Error('Refusing to scan a private/internal address.');
}

function request(urlStr, maxBytes = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error('Invalid URL')); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(urlStr,
      { method: 'GET', timeout: TIMEOUT, headers: { 'User-Agent': 'WebGuard247/1.0 (+security-scan)' } },
      (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < maxBytes) body += c.toString('utf8'); });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      });
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function fetchWithRedirects(startUrl) {
  const chain = [];
  let current = startUrl, last;
  const setCookies = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    last = await request(current);
    const sc = last.headers['set-cookie'];
    if (sc) (Array.isArray(sc) ? sc : [sc]).forEach((c) => setCookies.push(c));
    if (last.statusCode >= 300 && last.statusCode < 400 && last.headers.location) {
      const next = new URL(last.headers.location, current).toString();
      chain.push({ from: current, to: next, status: last.statusCode });
      current = next; continue;
    }
    break;
  }
  return { finalUrl: current, response: last, redirectChain: chain, setCookies };
}

// --- TLS: main handshake captures protocol, cipher, ALPN, OCSP, cert details ---
function getCertificate(hostname) {
  return new Promise((resolve) => {
    let ocspStapled = false;
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: TIMEOUT, rejectUnauthorized: false,
        requestOCSP: true, ALPNProtocols: ['h2', 'http/1.1'] },
      () => {
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const protocol = socket.getProtocol();
        const cipherObj = socket.getCipher() || {};
        const alpn = socket.alpnProtocol || null;
        let daysToExpiry, validFromOk, lifetimeDays, hostMatch, keyBits, keyType, chainProvided;

        if (cert && cert.valid_to) daysToExpiry = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
        if (cert && cert.valid_from) {
          validFromOk = new Date(cert.valid_from).getTime() <= Date.now();
          if (cert.valid_to) lifetimeDays = Math.round((new Date(cert.valid_to).getTime() - new Date(cert.valid_from).getTime()) / 86400000);
        }
        if (cert && (cert.subjectaltname || cert.subject)) {
          const names = [];
          if (cert.subjectaltname) cert.subjectaltname.split(',').forEach((s) => names.push(s.replace(/^\s*DNS:/i, '').trim()));
          if (cert.subject && cert.subject.CN) names.push(cert.subject.CN);
          hostMatch = names.some((n) => n === hostname || (n.startsWith('*.') && hostname.endsWith(n.slice(1))));
        }
        if (cert) {
          if (cert.nistCurve || cert.asn1Curve) {
            keyType = 'EC';
            keyBits = cert.nistCurve === 'P-384' ? 384 : cert.nistCurve === 'P-521' ? 521 : 256;
          } else if (cert.bits) { keyType = 'RSA'; keyBits = cert.bits; }
          const issuerCert = cert.issuerCertificate;
          chainProvided = !!(issuerCert && issuerCert.fingerprint && issuerCert.fingerprint !== cert.fingerprint);
        }

        resolve({
          error: authorized ? null : (socket.authorizationError ? String(socket.authorizationError) : null),
          issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN) : null,
          daysToExpiry, validFromOk, lifetimeDays, protocol,
          cipher: cipherObj.name || null, forwardSecrecy: /ECDHE|DHE/i.test(cipherObj.name || ''),
          alpn, ocspStapled, hostMatch, keyBits, keyType, chainProvided,
        });
        socket.end();
      });
    socket.on('OCSPResponse', (resp) => { if (resp && resp.length) ocspStapled = true; });
    socket.on('error', (e) => resolve({ error: String(e.message || e) }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'TLS connection timed out' }); });
  });
}

// --- TLS: does the server accept a specific protocol band? ---
function tlsAccepts(hostname, opts) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: TLS_PROBE_TIMEOUT, rejectUnauthorized: false, ...opts },
      () => { resolve(true); socket.end(); });
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

// --- registrable domain (naive, with a few common multi-part TLDs) ---
const MULTI_TLD = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.nz', 'com.au', 'co.za', 'com.br', 'co.jp', 'co.in'];
function baseDomain(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  if (MULTI_TLD.includes(last2)) return last3;
  return last2;
}

async function getDns(hostname) {
  const dom = baseDomain(hostname);
  const safe = (p) => p.then((v) => v).catch(() => []);
  const safeBool = (p) => p.then(() => true).catch(() => false);

  const dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'dkim', 'mail', 's1', 'smtp'];
  const dkimLookups = dkimSelectors.map((sel) =>
    dns.resolveTxt(`${sel}._domainkey.${dom}`).then((r) => {
      const joined = r.map((x) => x.join('')).join(' ');
      return /v=DKIM1|k=rsa|p=/i.test(joined) ? sel : null;
    }).catch(() => null));

  const [a, aaaa, mx, txt, dmarc, caa, ns, soa, mtaSts, tlsRpt, bimi, dkimFound, dnssec] = await Promise.all([
    safe(dns.resolve4(hostname)),
    safe(dns.resolve6(hostname)),
    safe(dns.resolveMx(dom).then((r) => r.map((x) => x.exchange))),
    safe(dns.resolveTxt(dom).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveTxt('_dmarc.' + dom).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveCaa ? dns.resolveCaa(dom).then((r) => r.map((x) => JSON.stringify(x))) : Promise.resolve([])),
    safe(dns.resolveNs(dom)),
    safeBool(dns.resolveSoa(dom)),
    safe(dns.resolveTxt('_mta-sts.' + dom).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveTxt('_smtp._tls.' + dom).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveTxt('default._bimi.' + dom).then((r) => r.map((x) => x.join('')))),
    Promise.all(dkimLookups).then((r) => r.filter(Boolean)),
    checkDnssec(dom),
  ]);
  return { a, aaaa, mx, txt, dmarc, caa, ns, soa, mtaSts, tlsRpt, bimi, dkim: dkimFound, dnssec };
}

// DNSSEC via a validating resolver (Cloudflare DoH) — reads the AD (authenticated data) flag.
async function checkDnssec(domain) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { accept: 'application/dns-json' }, signal: ctrl.signal });
    clearTimeout(t);
    const j = await res.json();
    return j && typeof j.AD === 'boolean' ? j.AD : null;
  } catch { return null; }
}

// --- well-known / sensitive file probes (with signatures to avoid false alarms) ---
async function probe(origin, path, opts = {}) {
  try {
    const r = await request(new URL(path, origin).toString(), 16 * 1024);
    const ok2xx = r.statusCode >= 200 && r.statusCode < 300;
    if (opts.redirectOk && r.statusCode >= 300 && r.statusCode < 400) return { found: true, status: r.statusCode };
    if (!ok2xx) return { found: false, status: r.statusCode };
    const looksHtml = /<(?:!doctype|html)\b/i.test(r.body.slice(0, 400));
    if (opts.signature) {
      const matches = opts.signature.test(r.body);
      return { found: matches && !looksHtml, status: r.statusCode };
    }
    return { found: true, status: r.statusCode };
  } catch { return { found: false }; }
}

function normalise(input) {
  let s = (input || '').trim();
  if (!s) throw new Error('No URL provided.');
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  return s;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };

  let target;
  try {
    const fromQuery = event.queryStringParameters && event.queryStringParameters.url;
    const fromBody = event.body ? (JSON.parse(event.body).url) : null;
    target = normalise(fromQuery || fromBody);
  } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: e.message }) };
  }

  const startUrl = new URL(target);
  try { await guardHost(startUrl.hostname); }
  catch (e) { return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: e.message }) }; }

  try {
    const { finalUrl, response, redirectChain, setCookies } = await fetchWithRedirects(target);
    const finalHost = new URL(finalUrl).hostname;
    const isHttps = finalUrl.startsWith('https://');

    const [tlsInfo, tls13, legacy, dnsInfo, robots, securityTxt, sitemap, humans, gitConfig, dotenv, dsStore, svn, changePassword] = await Promise.all([
      isHttps ? getCertificate(finalHost) : Promise.resolve(null),
      isHttps ? tlsAccepts(finalHost, { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }) : Promise.resolve(null),
      isHttps ? tlsAccepts(finalHost, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1' }) : Promise.resolve(null),
      getDns(finalHost),
      probe(finalUrl, '/robots.txt'),
      probe(finalUrl, '/.well-known/security.txt'),
      probe(finalUrl, '/sitemap.xml'),
      probe(finalUrl, '/humans.txt'),
      probe(finalUrl, '/.git/config', { signature: /\[core\]|\[remote|\[branch/i }),
      probe(finalUrl, '/.env', { signature: /(^|\n)\s*[A-Z][A-Z0-9_]+\s*=/ }),
      probe(finalUrl, '/.DS_Store', { signature: /Bud1/ }),
      probe(finalUrl, '/.svn/entries', { signature: /dir|svn|^\d+$/im }),
      probe(finalUrl, '/.well-known/change-password', { redirectOk: true }),
    ]);

    if (tlsInfo && typeof tls13 === 'boolean') tlsInfo.tls13 = tls13;
    if (tlsInfo && typeof legacy === 'boolean') tlsInfo.legacyAccepted = legacy;

    const evidence = {
      url: target, finalUrl, reachable: true, statusCode: response.statusCode,
      headers: response.headers, setCookies, redirectChain,
      tls: tlsInfo, dns: dnsInfo,
      probes: { robots, securityTxt, sitemap, humans, gitConfig, dotenv, dsStore, svn, changePassword },
      robots, securityTxt, // back-compat aliases
      bodySnippet: response.body,
    };

    const report = analyze(evidence);
    return { statusCode: 200, headers: CORS, body: JSON.stringify(report) };
  } catch (e) {
    const report = analyze({ url: target, finalUrl: target, reachable: false, error: String(e.message || e), headers: {}, dns: {}, probes: {} });
    return { statusCode: 200, headers: CORS, body: JSON.stringify(report) };
  }
};

// Allow `node scan.mjs https://example.com` for local testing too.
if (import.meta.url === `file://${process.argv[1]}`) {
  const url = process.argv[2] || 'https://example.com';
  handler({ httpMethod: 'GET', queryStringParameters: { url } })
    .then((r) => console.log(r.body))
    .catch((e) => console.error(e));
}
