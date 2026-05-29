// WebGuard247 — scan endpoint (Netlify Function).
// Collects passive, non-intrusive evidence about a URL and runs the analysis engine.
// Uses only Node built-ins, so there are NO dependencies to install.
//
// Passive only: it reads the same things any browser sees (headers, the TLS
// certificate, public DNS records, robots.txt / security.txt). It does NOT port
// scan, brute force, or probe internal systems, and it refuses private/internal
// addresses (SSRF guard).

import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import net from 'node:net';
import { analyze } from './lib/checks.mjs';

const TIMEOUT = 8000;
const MAX_REDIRECTS = 5;
const MAX_BODY = 200 * 1024; // sample first 200KB of HTML

// --- SSRF guard: refuse anything that resolves to a private/internal address ---
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return (
      p[0] === 10 ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      p[0] === 0
    );
  }
  const low = ip.toLowerCase();
  return low === '::1' || low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80') || low === '::';
}

async function guardHost(hostname) {
  if (/^(localhost|.*\.local)$/i.test(hostname)) throw new Error('Refusing to scan a local hostname.');
  const records = await dns.lookup(hostname, { all: true });
  for (const r of records) {
    if (isPrivateIp(r.address)) throw new Error('Refusing to scan a private/internal address.');
  }
}

function request(urlStr) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch { return reject(new Error('Invalid URL')); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      urlStr,
      { method: 'GET', timeout: TIMEOUT, headers: { 'User-Agent': 'WebGuard247/1.0 (+security-scan)' } },
      (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < MAX_BODY) body += c.toString('utf8'); });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, body }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function fetchWithRedirects(startUrl) {
  const chain = [];
  let current = startUrl;
  let last;
  const setCookies = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    last = await request(current);
    // collect Set-Cookie at every hop
    const sc = last.headers['set-cookie'];
    if (sc) (Array.isArray(sc) ? sc : [sc]).forEach((c) => setCookies.push(c));
    if (last.statusCode >= 300 && last.statusCode < 400 && last.headers.location) {
      const next = new URL(last.headers.location, current).toString();
      chain.push({ from: current, to: next, status: last.statusCode });
      current = next;
      continue;
    }
    break;
  }
  return { finalUrl: current, response: last, redirectChain: chain, setCookies };
}

function getCertificate(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: TIMEOUT, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const protocol = socket.getProtocol();
        let daysToExpiry, hostMatch;
        if (cert && cert.valid_to) {
          daysToExpiry = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
        }
        if (cert && (cert.subjectaltname || cert.subject)) {
          const names = [];
          if (cert.subjectaltname) cert.subjectaltname.split(',').forEach((s) => names.push(s.replace(/^\s*DNS:/i, '').trim()));
          if (cert.subject && cert.subject.CN) names.push(cert.subject.CN);
          hostMatch = names.some((n) => n === hostname || (n.startsWith('*.') && hostname.endsWith(n.slice(1))));
        }
        resolve({
          error: authorized ? null : (socket.authorizationError ? String(socket.authorizationError) : null),
          issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN) : null,
          daysToExpiry,
          protocol,
          hostMatch,
        });
        socket.end();
      }
    );
    socket.on('error', (e) => resolve({ error: String(e.message || e) }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'TLS connection timed out' }); });
  });
}

async function getDns(hostname) {
  const safe = (p) => p.then((v) => v).catch(() => []);
  const [a, mx, txt, dmarc, caa] = await Promise.all([
    safe(dns.resolve4(hostname)),
    safe(dns.resolveMx(hostname).then((r) => r.map((x) => x.exchange))),
    safe(dns.resolveTxt(hostname).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveTxt('_dmarc.' + hostname).then((r) => r.map((x) => x.join('')))),
    safe(dns.resolveCaa ? dns.resolveCaa(hostname).then((r) => r.map((x) => JSON.stringify(x))) : Promise.resolve([])),
  ]);
  return { a, mx, txt, dmarc, caa };
}

async function probe(origin, path) {
  try {
    const r = await request(new URL(path, origin).toString());
    return { found: r.statusCode >= 200 && r.statusCode < 300, status: r.statusCode };
  } catch {
    return { found: false };
  }
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

  try {
    await guardHost(startUrl.hostname);
  } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: e.message }) };
  }

  try {
    const { finalUrl, response, redirectChain, setCookies } = await fetchWithRedirects(target);
    const finalHost = new URL(finalUrl).hostname;

    const [tlsInfo, dnsInfo, robots, securityTxt] = await Promise.all([
      finalUrl.startsWith('https://') ? getCertificate(finalHost) : Promise.resolve(null),
      getDns(finalHost),
      probe(finalUrl, '/robots.txt'),
      probe(finalUrl, '/.well-known/security.txt'),
    ]);

    const evidence = {
      url: target,
      finalUrl,
      reachable: true,
      statusCode: response.statusCode,
      headers: response.headers,
      setCookies,
      redirectChain,
      tls: tlsInfo,
      dns: dnsInfo,
      robots,
      securityTxt,
      bodySnippet: response.body,
    };

    const report = analyze(evidence);
    return { statusCode: 200, headers: CORS, body: JSON.stringify(report) };
  } catch (e) {
    const report = analyze({ url: target, finalUrl: target, reachable: false, error: String(e.message || e), headers: {}, dns: {} });
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
