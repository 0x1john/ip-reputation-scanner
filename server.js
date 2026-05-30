'use strict';
const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const dns   = require('dns');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

// ── CORS allowlist ────────────────────────────────────────────────────────
// Add exact origins here, or set ALLOWED_ORIGINS="https://a.com,https://b.com" in env.
// *.vercel.app (incl. preview deploys), localhost, 127.0.0.1 and github.io are always allowed.
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean)
  .concat([
    'https://ip-reputation-scanner-chi.vercel.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
  ]);

function originAllowed(origin) {
  if (!origin) return true;                 // curl / same-origin / server-to-server
  if (ALLOWED.includes(origin)) return true;
  let host = '';
  try { host = new URL(origin).hostname; } catch { return false; }
  return /\.vercel\.app$/.test(host)        // any Vercel deploy (prod + previews)
      || host === 'localhost'
      || host === '127.0.0.1'
      || /\.github\.io$/.test(host) || host === 'github.io';
}

// ── HTTPS helper ──────────────────────────────────────────────────────────
function req(opts, body = null) {
  return new Promise((resolve, reject) => {
    const r = https.request(opts, res => {
      const buf = [];
      res.on('data', c => buf.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(buf).toString() }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

// ── Talos mnemonic → display label ───────────────────────────────────────
const TALOS_LABELS = {
  favorable:   'Favorable',
  neutral:     'Neutral',
  unfavorable: 'Unfavorable',
  untrusted:   'Untrusted',
  poor:        'Poor',
  good:        'Good',
  bad:         'Bad',
};
function talosLabel(mnemonic) {
  if (!mnemonic) return null;
  return TALOS_LABELS[mnemonic.toLowerCase()] || (mnemonic.charAt(0).toUpperCase() + mnemonic.slice(1));
}

// ── Server ────────────────────────────────────────────────────────────────
http.createServer(async (request, response) => {
  const u = new URL(request.url, `http://localhost:${PORT}`);

  // ── CORS (the fix) ──
  // Reflect the origin only when it is allowed; otherwise DO NOT send the header
  // at all. Never send an empty string — that is what the browser was rejecting.
  const origin = request.headers['origin'] || '';
  if (originAllowed(origin)) {
    response.setHeader('Access-Control-Allow-Origin', origin || '*');
    response.setHeader('Vary', 'Origin');
  }
  response.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-abuse-key,x-vt-key');
  response.setHeader('Access-Control-Expose-Headers', 'X-RateLimit-Backoff');
  if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return; }

  const send = (code, body, ct = 'application/json') => {
    response.setHeader('Content-Type', ct);
    response.writeHead(code);
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  // ── Serve index.html ──
  if (u.pathname === '/' || u.pathname === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) return send(404, { error: 'index.html not found' });
      response.setHeader('Content-Type', 'text/html');
      response.writeHead(200);
      response.end(data);
    });
    return;
  }

  // ── DNS forward resolve (domain → IP) ──
  if (u.pathname === '/api/resolve') {
    const domain = u.searchParams.get('domain');
    if (!domain) return send(400, { error: 'Missing domain' });
    dns.lookup(domain, { family: 4 }, (err, address) => {
      if (err) dns.lookup(domain, (err2, address2) => {
        if (err2) return send(404, { error: err2.message });
        send(200, JSON.stringify({ domain, ip: address2 }));
      });
      else send(200, JSON.stringify({ domain, ip: address }));
    });
    return;
  }

  // ── DNS reverse lookup (IP → hostname) ──
  if (u.pathname === '/api/rdns') {
    const ip = u.searchParams.get('ip');
    if (!ip) return send(400, { error: 'Missing ip' });
    const ptrDomain = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    // Use public resolvers since local DNS often refuses PTR queries
    const resolver = new dns.Resolver();
    resolver.setServers(['8.8.8.8', '1.1.1.1']);
    resolver.resolve(ptrDomain, 'PTR', (err, hostnames) => {
      if (err || !hostnames || !hostnames.length) return send(200, JSON.stringify({ ip, hostname: null }));
      send(200, JSON.stringify({ ip, hostname: hostnames[0].replace(/\.$/, '') }));
    });
    return;
  }

  // ── VirusTotal proxy ──
  if (u.pathname === '/api/vt') {
    const target = u.searchParams.get('target');
    const key    = request.headers['x-vt-key'];
    if (!target || !key) return send(400, { error: 'Missing target or key' });
    const type = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || target.includes(':') ? 'ip_addresses' : 'domains';
    try {
      const r = await req({
        hostname: 'www.virustotal.com',
        path: `/api/v3/${type}/${encodeURIComponent(target)}`,
        method: 'GET',
        headers: { 'x-apikey': key, 'Accept': 'application/json' },
      });
      if (r.status === 429) response.setHeader('X-RateLimit-Backoff', '60');
      send(r.status, r.text);
    } catch (e) { send(502, { error: e.message }); }
    return;
  }

  // ── AbuseIPDB proxy ──
  if (u.pathname === '/api/abuseipdb') {
    const ip  = u.searchParams.get('ip');
    const key = request.headers['x-abuse-key'];
    if (!ip || !key) return send(400, { error: 'Missing ip or key' });
    try {
      const r = await req({
        hostname: 'api.abuseipdb.com',
        path: `/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        method: 'GET',
        headers: { 'Key': key, 'Accept': 'application/json' },
      });
      send(r.status, r.text);
    } catch (e) { send(502, { error: e.message }); }
    return;
  }

  // ── GreyNoise community proxy (IPs only, no key required) ──
  if (u.pathname === '/api/greynoise') {
    const ip = u.searchParams.get('ip');
    if (!ip) return send(400, { error: 'Missing ip' });
    try {
      const r = await req({
        hostname: 'api.greynoise.io',
        path: `/v3/community/${encodeURIComponent(ip)}`,
        method: 'GET',
        headers: { 'Accept': 'application/json', 'User-Agent': 'IPReputationScanner/1.0' },
      });
      send(r.status, r.text);
    } catch (e) { send(502, { error: e.message }); }
    return;
  }

  // ── Talos proxy — GET /cloud_intel/ip_reputation?ip=X ──
  if (u.pathname === '/api/talos') {
    const target = u.searchParams.get('ip') || u.searchParams.get('domain');
    if (!target) return send(400, { error: 'Missing ip or domain' });

    const isAddr = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || (target.includes(':') && /^[0-9a-fA-F:]+$/.test(target));

    if (isAddr) {
      try {
        const r = await req({
          hostname: 'talosintelligence.com',
          path: `/cloud_intel/ip_reputation?ip=${encodeURIComponent(target)}`,
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'application/json, */*',
            'Referer': 'https://talosintelligence.com/reputation_center/',
          },
        });
        if (r.status === 200 && r.text.trim().startsWith('{')) {
          const d = JSON.parse(r.text);
          const mnemonic = d?.reputation?.threat_level_mnemonic;
          const label = talosLabel(mnemonic);
          if (label) { send(200, JSON.stringify({ threat_level: label, _src: 'talos' })); return; }
        }
      } catch {}
    }

    send(200, JSON.stringify({ threat_level: null }));
    return;
  }

  send(404, { error: 'Not found' });

}).listen(PORT, '0.0.0.0', () => {
  const line = '─'.repeat(51);
  console.log(`\n┌${line}┐`);
  console.log(`│   🔍  IP Reputation Scanner — Proxy Server         │`);
  console.log(`├${line}┤`);
  console.log(`│   Open  →  http://localhost:${PORT}                    │`);
  console.log(`│   Stop  →  Ctrl+C                                   │`);
  console.log(`│                                                     │`);
  console.log(`│   ✅  VirusTotal   (direct, CORS OK)                │`);
  console.log(`│   ✅  AbuseIPDB    (proxied via this server)        │`);
  console.log(`│   ✅  Cisco Talos  (proxied via this server)        │`);
  console.log(`└${line}┘\n`);
});
