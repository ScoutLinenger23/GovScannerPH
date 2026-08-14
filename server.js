const express = require('express');
const https = require('node:https');
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const path = require('node:path');
const fs = require('node:fs');
const { execFile } = require('node:child_process');

// Optional last-resort fallback: routes a check through a SOCKS5 proxy tunneled back to
// your home ISP connection (via `ssh -R 1080 -N user@vps-ip` run from home). Gov sites
// almost never block residential ISP IPs — only datacenter/VPS ranges — so this sidesteps
// that block entirely for the handful of sites that need it. Lazy-loaded: the app runs
// completely normally even if socks-proxy-agent was never installed.
let SocksProxyAgent = null;
try {
  const socksModule = require('socks-proxy-agent');
  // Different published versions export this differently (named export vs default vs
  // bare module.exports) — handle all three so a version mismatch can't silently no-op.
  SocksProxyAgent = socksModule.SocksProxyAgent || socksModule.default || socksModule;
  if (typeof SocksProxyAgent !== 'function') {
    SocksProxyAgent = null;
    throw new Error('unrecognized export shape from socks-proxy-agent');
  }
  console.log('[*] socks-proxy-agent loaded — home-ISP SOCKS fallback is active.');
} catch (e) {
  console.warn(`[!] socks-proxy-agent not usable (${e.message}) — home-ISP fallback disabled. Run \`npm install socks-proxy-agent\` to enable it.`);
}
const SOCKS_PROXY_URL = process.env.SOCKS_PROXY_URL || 'socks5h://127.0.0.1:1080';

// Real last resort: a headless Chromium browser via Puppeteer. Unlike everything else in
// this fallback chain, this can actually execute JS-challenge bot-checks that curl/raw
// sockets simply cannot — but it's the heaviest option by far (full Chromium process per
// check). Optional and lazily loaded: if not installed, this fallback just no-ops and
// affected sites keep showing their current status exactly as before.
//
// Prefer puppeteer-extra + the stealth plugin if installed — plain Puppeteer still exposes
// JS-level tells (navigator.webdriver=true, missing browser plugins, inconsistent
// permissions API, etc.) that bot-detection checks for independently of TLS fingerprint or
// IP reputation. The stealth plugin patches these to look like a genuine user's browser.
// Falls back to plain puppeteer automatically if the extra packages aren't installed.
let puppeteer = null;
let stealthActive = false;
try {
  puppeteer = require('puppeteer-extra');
  const StealthPlugin = require('puppeteer-extra-plugin-stealth');
  puppeteer.use(StealthPlugin());
  stealthActive = true;
  console.log('[*] puppeteer-extra + stealth plugin loaded — real-browser fallback is active (stealth mode).');
} catch (e) {
  try {
    puppeteer = require('puppeteer');
    console.log('[*] puppeteer loaded — real-browser fallback is active (no stealth plugin found, run `npm install puppeteer-extra puppeteer-extra-plugin-stealth` to add it).');
  } catch (e2) {
    console.warn('[!] puppeteer not installed — real-browser fallback disabled. Run `npm install puppeteer` to enable it.');
  }
}
const HEADLESS_TIMEOUT_MS = parseInt(process.env.HEADLESS_TIMEOUT_MS, 10) || 20000;
const HEADLESS_CONCURRENCY = parseInt(process.env.HEADLESS_CONCURRENCY, 10) || 2;

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SCAN_INTERVAL_MS = parseInt(process.env.SCAN_INTERVAL_MS, 10) || 120000;
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS, 10) || 10000;
const SCAN_CONCURRENCY = parseInt(process.env.SCAN_CONCURRENCY, 10) || 18;
const HISTORY_FILE = process.env.HISTORY_FILE || path.join(__dirname, 'history-store.json');
const MAX_INCIDENTS_PER_SITE = 20;

// curl-impersonate: a modified curl binary that replicates a real Chrome TLS handshake
// byte-for-byte (cipher order, extensions, GREASE values) — the only thing that actually
// gets past WAFs that silently drop Node's TLS handshake before any HTTP data is sent.
// Optional and lazily detected: if the binary isn't installed, this fallback just no-ops
// and affected sites keep showing TIMEOUT exactly like before, nothing else breaks.
const CURL_IMPERSONATE_BIN = process.env.CURL_IMPERSONATE_BIN || 'curl_chrome116';
const IMPERSONATE_CONCURRENCY = parseInt(process.env.IMPERSONATE_CONCURRENCY, 10) || 5;
let impersonateAvailable = true; // optimistic until proven otherwise (ENOENT on first real use)

// Some gov.ph sites (confirmed via manual inspection) send an incomplete cert chain —
// a real, legitimate cert whose intermediate CA just isn't included in what the server
// sends. Browsers silently fetch the missing intermediate automatically; Node doesn't.
// Dropping the correct intermediate .pem file(s) in certs/ fixes this properly — this
// AUGMENTS Node's default trusted root store, it doesn't replace or weaken it.
const EXTRA_CA_DIR = path.join(__dirname, 'certs');
let extraCAs = [];
try {
  if (fs.existsSync(EXTRA_CA_DIR)) {
    const files = fs.readdirSync(EXTRA_CA_DIR).filter(f => f.endsWith('.pem'));
    extraCAs = files.map(f => fs.readFileSync(path.join(EXTRA_CA_DIR, f), 'utf8'));
    if (extraCAs.length) console.log(`[*] Loaded ${extraCAs.length} extra trusted intermediate CA cert(s) from ${EXTRA_CA_DIR}`);
  }
} catch (e) {
  console.warn(`[!] Could not load extra CA certs: ${e.message}`);
}

const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 30,
  ca: extraCAs.length ? [...tls.rootCertificates, ...extraCAs] : undefined // undefined = untouched Node defaults
});
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 30 });
// Used ONLY as a secondary, clearly-labeled reachability check when the primary request
// fails on a broken cert chain — never for the primary request. Results from this agent
// are always tagged 'INSECURE_CERT' so the dashboard shows an honest warning rather than
// silently treating an untrusted cert as a clean "up".
const httpsAgentInsecure = new https.Agent({ keepAlive: true, maxSockets: 10, rejectUnauthorized: false });
const CERT_CHAIN_ERROR_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_UNTRUSTED'
]);


const URLS = [
  "https://caloocancity.gov.ph", "https://laspinascity.gov.ph", "https://www.makati.gov.ph",
  "https://www.malabon.gov.ph", "https://www.mandaluyong.gov.ph", "https://manila.gov.ph",
  "https://marikina.gov.ph", "https://muntinlupacity.gov.ph", "https://www.navotas.gov.ph",
  "https://paranaquecity.gov.ph", "https://www.pasay.gov.ph", "https://www.pasigcity.gov.ph",
  "https://pateros.gov.ph", "https://quezoncity.gov.ph", "https://sanjuancity.gov.ph",
  "https://www.taguig.gov.ph", "https://www.valenzuela.gov.ph", "https://www.mmda.gov.ph",
  "https://www.bsp.gov.ph", "https://op-proper.gov.ph", "https://www.ovp.gov.ph",
  "https://www.senate.gov.ph", "https://www.congress.gov.ph", "https://sc.judiciary.gov.ph",
  "https://ca.judiciary.gov.ph", "https://sb.judiciary.gov.ph", "https://cta.judiciary.gov.ph",
  "https://www.dar.gov.ph", "https://www.da.gov.ph", "https://www.dbm.gov.ph",
  "https://www.deped.gov.ph", "https://www.doe.gov.ph", "https://www.denr.gov.ph",
  "https://www.dof.gov.ph", "https://dfa.gov.ph", "https://doh.gov.ph",
  "https://dhsud.gov.ph", "https://dict.gov.ph", "https://www.dilg.gov.ph",
  "https://www.doj.gov.ph", "https://www.dole.gov.ph", "https://www.dnd.gov.ph",
  "https://www.dpwh.gov.ph", "https://www.dost.gov.ph", "https://www.dswd.gov.ph",
  "https://www.tourism.gov.ph", "https://www.dti.gov.ph", "https://www.dotr.gov.ph",
  "https://www.dmw.gov.ph", "https://neda.gov.ph", "https://philsa.gov.ph",
  "https://www.bir.gov.ph", "https://customs.gov.ph", "https://lto.gov.ph",
  "https://ltfrb.gov.ph", "https://nbi.gov.ph", "https://pnp.gov.ph",
  "https://bjmp.gov.ph", "https://bfp.gov.ph", "https://coastguard.gov.ph",
  "https://ched.gov.ph", "https://www.tesda.gov.ph", "https://psa.gov.ph",
  "https://bagong.pagasa.dost.gov.ph", "https://www.phivolcs.dost.gov.ph",
  "https://www.namria.gov.ph", "https://www.sec.gov.ph", "https://www.insurance.gov.ph",
  "https://cda.gov.ph", "https://fda.gov.ph", "https://www.philhealth.gov.ph",
  "https://www.sss.gov.ph", "https://www.gsis.gov.ph", "https://www.pagibigfund.gov.ph",
  "https://csc.gov.ph", "https://comelec.gov.ph", "https://www.coa.gov.ph",
  "https://www.foi.gov.ph", "https://e.gov.ph", "https://www.gov.ph",
  "https://www.officialgazette.gov.ph"
];

const historyStore = {};
const incidentStore = {}; // { url: { openSince: isoStringOrNull, incidents: [{start, end}] } }
const MAX_HISTORY = 100;
URLS.forEach(u => {
  historyStore[u] = [];
  incidentStore[u] = { openSince: null, incidents: [] };
});

// Restore uptime history + incident log from disk if present, so a restart/redeploy
// doesn't reset every site's uptime% and downtime log back to a blank slate.
function loadHistoryFrom(filePath) {
  const saved = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const savedHistory = saved.history || saved; // tolerate old format (history-only) from before this update
  const savedIncidents = saved.incidents || {};
  URLS.forEach(u => {
    if (Array.isArray(savedHistory[u])) historyStore[u] = savedHistory[u].slice(-MAX_HISTORY);
    if (savedIncidents[u]) incidentStore[u] = savedIncidents[u];
  });
  return Object.keys(savedHistory).length;
}

try {
  if (fs.existsSync(HISTORY_FILE)) {
    const count = loadHistoryFrom(HISTORY_FILE);
    console.log(`[*] Loaded history for ${count} sites from ${HISTORY_FILE}`);
  }
} catch (e) {
  // Main file corrupted (e.g. a previous process was killed mid-write) — check whether a
  // temp file from an interrupted atomic write happens to still be valid and recoverable.
  const tmpFile = `${HISTORY_FILE}.tmp`;
  try {
    if (fs.existsSync(tmpFile)) {
      const count = loadHistoryFrom(tmpFile);
      console.log(`[*] Main history file was corrupted, but recovered ${count} sites from a leftover temp file.`);
    } else {
      console.warn(`[!] Could not load history file (${e.message}) — starting fresh.`);
    }
  } catch (e2) {
    console.warn(`[!] Could not load history file (${e.message}) — starting fresh.`);
  }
}

let saveTimer = null;

// Writes to a temp file first, then renames it over the real file. A crash/kill mid-write
// only ever corrupts the temp file, never the real history-store.json — rename is atomic
// at the filesystem level, so the actual file is always either the old complete version or
// the new complete version, never a truncated half-write like what just happened.
function atomicWriteHistory(callback) {
  const tmpFile = `${HISTORY_FILE}.tmp`;
  const data = JSON.stringify({ history: historyStore, incidents: incidentStore });
  fs.writeFile(tmpFile, data, (err) => {
    if (err) { if (callback) callback(err); return; }
    fs.rename(tmpFile, HISTORY_FILE, (renameErr) => {
      if (callback) callback(renameErr);
    });
  });
}

function persistHistory() {
  // Debounce so a burst of scans doesn't hammer disk I/O.
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    atomicWriteHistory((err) => {
      if (err) console.warn(`[!] Failed to save history: ${err.message}`);
    });
  }, 1000);
}

let cachedData = {
  timestamp: "Initializing direct VPS scan...",
  results: URLS.map(u => ({ url: u, status: 0, latency: 0, error: 'SCANNING...', uptime: 100, history: [], historyFull: [], incidents: [], downSince: null }))
};

app.use(express.static(path.join(__dirname, 'public')));

// Last-resort check when a response is malformed enough that even Node's lenient
// HTTP parser (insecureHTTPParser) can't handle it. Bypasses HTTP parsing
// entirely — connects raw, sends a minimal request by hand, and just reads the
// status line directly off the wire. Slower and cruder, but browsers do the
// equivalent of this under the hood and happily render these same pages.
function rawSocketCheck(targetUrl, timeoutMs) {
  return new Promise((resolve) => {
    let resolved = false;
    const start = Date.now();
    let socket;
    const done = (val) => {
      if (resolved) return;
      resolved = true;
      try { socket && socket.destroy(); } catch (e) { /* ignore */ }
      resolve(val);
    };

    let parsedUrl;
    try { parsedUrl = new URL(targetUrl); } catch (e) { return done(null); }
    const isHttps = parsedUrl.protocol === 'https:';
    const host = parsedUrl.hostname;
    const port = parsedUrl.port || (isHttps ? 443 : 80);

    const timer = setTimeout(() => done(null), timeoutMs);

    try {
      socket = isHttps
        ? tls.connect({ host, port, servername: host, ca: extraCAs.length ? [...tls.rootCertificates, ...extraCAs] : undefined })
        : net.connect({ host, port });
    } catch (e) {
      clearTimeout(timer);
      return done(null);
    }

    socket.on(isHttps ? 'secureConnect' : 'connect', () => {
      const path = parsedUrl.pathname + parsedUrl.search || '/';
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\r\nConnection: close\r\n\r\n`
      );
    });

    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      const match = buffer.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
      if (match) {
        clearTimeout(timer);
        done({ url: targetUrl, status: parseInt(match[1], 10), latency: Date.now() - start, error: null });
      }
    });

    socket.on('error', () => { clearTimeout(timer); done(null); });
    socket.on('close', () => { clearTimeout(timer); done(null); });
  });
}

// Only a few of these run at once — real curl processes are much lighter than a browser
// tab, but still heavier than a plain socket, so it stays capped regardless of how many
// sites need it.
let activeImpersonateChecks = 0;
const impersonateQueue = [];
function processImpersonateQueue() {
  while (activeImpersonateChecks < IMPERSONATE_CONCURRENCY && impersonateQueue.length > 0) {
    impersonateQueue.shift()();
  }
}

function impersonateCheck(targetUrl, timeoutMs) {
  if (!impersonateAvailable) return Promise.resolve(null);
  return new Promise((resolveOuter) => {
    const run = () => {
      activeImpersonateChecks++;
      const start = Date.now();
      const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
      execFile(
        CURL_IMPERSONATE_BIN,
        ['-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', String(timeoutSec), targetUrl],
        (err, stdout) => {
          activeImpersonateChecks--;
          processImpersonateQueue();
          if (err) {
            if (err.code === 'ENOENT') {
              impersonateAvailable = false;
              console.warn(`[!] ${CURL_IMPERSONATE_BIN} not found — TLS-fingerprint fallback disabled. Install curl-impersonate to enable it.`);
            }
            resolveOuter(null);
            return;
          }
          const status = parseInt(String(stdout).trim(), 10);
          if (!status || Number.isNaN(status)) { resolveOuter(null); return; }
          resolveOuter({ url: targetUrl, status, latency: Date.now() - start, error: null });
        }
      );
    };
    impersonateQueue.push(run);
    processImpersonateQueue();
  });
}

function toggleWwwUrl(targetUrl) {
  try {
    const u = new URL(targetUrl);
    u.hostname = u.hostname.startsWith('www.') ? u.hostname.slice(4) : ('www.' + u.hostname);
    return u.toString();
  } catch (e) {
    return null;
  }
}

// Confirms a site is reachable despite a broken cert chain, WITHOUT pretending the cert
// is trustworthy. The result is always tagged error: 'INSECURE_CERT' so the frontend can
// show an honest "cert issue" warning instead of either hiding the problem or reporting
// a reachable site as fully down.
function certReachabilityCheck(targetUrl, timeoutMs) {
  return new Promise((resolve) => {
    let resolved = false;
    const start = Date.now();
    const done = (v) => { if (!resolved) { resolved = true; resolve(v); } };
    const timer = setTimeout(() => done(null), timeoutMs);
    try {
      const req = https.request(
        targetUrl,
        {
          method: 'GET',
          agent: httpsAgentInsecure,
          insecureHTTPParser: true,
          family: 4,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36' }
        },
        (res) => {
          clearTimeout(timer);
          res.destroy();
          done({ url: targetUrl, status: res.statusCode, latency: Date.now() - start, error: 'INSECURE_CERT' });
        }
      );
      req.on('error', () => { clearTimeout(timer); done(null); });
      req.end();
    } catch (e) {
      clearTimeout(timer);
      done(null);
    }
  });
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

function attemptCheckStatus(targetUrl, timeoutMs, _isAltHostRetry = false) {
  return new Promise((resolve) => {
    let resolved = false;
    const start = Date.now();
    const safeResolve = (val) => { if (!resolved) { resolved = true; resolve(val); } };

    const hardTimer = setTimeout(() => {
      safeResolve({ url: targetUrl, status: 0, latency: 0, error: 'TIMEOUT' });
    }, timeoutMs);

    try {
      const parsedUrl = new URL(targetUrl);
      const isHttps = parsedUrl.protocol === 'https:';
      const protocol = isHttps ? https : http;
      const agent = isHttps ? httpsAgent : httpAgent;

      const req = protocol.request(
        targetUrl,
        {
          method: 'GET',
          agent,
          insecureHTTPParser: true, // some gov servers send headers that are technically non-RFC-compliant
                                     // (browsers tolerate this silently) — Node's strict parser rejects them
                                     // with HPE_INVALID_HEADER_TOKEN otherwise, even though the site is fine.
          family: 4, // several gov.ph hosts advertise AAAA records that don't actually respond,
                     // which stalls dual-stack lookups until they fall back to IPv4 anyway —
                     // skip straight to IPv4 to avoid that wasted round trip.
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
          }
        },
        (res) => {
          clearTimeout(hardTimer);
          res.destroy();
          safeResolve({ url: targetUrl, status: res.statusCode, latency: Date.now() - start, error: null });
        }
      );

      req.on('error', async (err) => {
        clearTimeout(hardTimer);
        // A parse error (HPE_*) means the site responded but Node's HTTP parser choked
        // on the raw bytes — try reading the status line manually before calling it down.
        if (err.code && err.code.startsWith('HPE_')) {
          await sleep(750); // avoid looking like an automated retry-hammer to a rate limiter
          const raw = await rawSocketCheck(targetUrl, timeoutMs);
          if (raw) { safeResolve(raw); return; }
        }

        // Hostname doesn't match the cert's SAN, or doesn't resolve via DNS at all —
        // usually just a www/non-www mismatch (a site with a DNS record for one variant
        // but not the other, or a cert issued for one but not the other). Try the other
        // variant once before giving up (not a bypass, just the correct hostname).
        if ((err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' || err.code === 'ENOTFOUND') && !_isAltHostRetry) {
          await sleep(750);
          const altUrl = toggleWwwUrl(targetUrl);
          if (altUrl) {
            const altResult = await attemptCheckStatus(altUrl, timeoutMs, true);
            if (altResult && altResult.status) { safeResolve({ ...altResult, url: targetUrl }); return; }
          }
        }

        // Broken cert chain (missing intermediate, expired, self-signed) OR a hostname
        // mismatch the www-toggle didn't fix — likely means the real cause isn't just
        // www vs non-www (e.g. a shared hosting platform/CDN serving the wrong cert via
        // broken SNI routing). Either way: confirm reachability honestly instead of
        // either silently trusting an unverified cert or reporting a live site as down.
        if (err.code && (CERT_CHAIN_ERROR_CODES.has(err.code) || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID')) {
          await sleep(750); // a same-instant second connection is exactly what rate-limiting WAFs flag as a bot
          let certResult = await certReachabilityCheck(targetUrl, timeoutMs);
          if (!certResult) {
            // These sites are known to be intermittently flaky (WAF rate-limiting, not a
            // consistent failure) — one retry meaningfully cuts down false red flickers.
            await sleep(1200);
            certResult = await certReachabilityCheck(targetUrl, timeoutMs);
          }
          if (certResult) { safeResolve(certResult); return; }
        }

        safeResolve({ url: targetUrl, status: 0, latency: 0, error: err.code || 'CONN_ERR' });
      });

      req.end();
    } catch (e) {
      clearTimeout(hardTimer);
      safeResolve({ url: targetUrl, status: 0, latency: 0, error: 'INVALID' });
    }
  });
}

function socksProxyCheck(targetUrl, timeoutMs) {
  if (!SocksProxyAgent) return Promise.resolve(null);
  return new Promise((resolve) => {
    let resolved = false;
    const start = Date.now();
    const done = (v) => { if (!resolved) { resolved = true; resolve(v); } };
    const timer = setTimeout(() => done(null), timeoutMs);
    try {
      const agent = new SocksProxyAgent(SOCKS_PROXY_URL);
      const req = https.get(
        targetUrl,
        { agent, insecureHTTPParser: true, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36' } },
        (res) => {
          clearTimeout(timer);
          res.destroy();
          done({ url: targetUrl, status: res.statusCode, latency: Date.now() - start, error: null });
        }
      );
      req.on('error', () => { clearTimeout(timer); done(null); });
    } catch (e) {
      clearTimeout(timer);
      done(null);
    }
  });
}

// Slow-but-alive gov servers were getting flagged "down" on a single tight timeout.
// Give each site 10s, and if it times out, retry once before calling it down — this
// filters out one-off slow responses / transient network blips. If it STILL times out,
// it's very likely a WAF dropping the connection based on TLS fingerprint — try
// curl-impersonate next. If even that fails, it may be a block on this VPS's IP/datacenter
// specifically — as a final option, route through the home-ISP SOCKS tunnel if configured.
// --- Headless-browser fallback (Puppeteer) ---
// Two shared browsers, launched lazily on first use: one direct (uses this VPS's own IP),
// one routed through the home-ISP SOCKS tunnel (uses your phone/home connection's IP).
// Direct is tried first since it's cheaper and has no tunnel dependency — the proxied one
// is only used as a further fallback for sites where the block is IP-reputation-based
// rather than fingerprint-based, same root cause as the dilg/namria/neda cases.
let browserInstance = null;
let browserInstanceProxied = null;
let browserLaunching = null;
let browserLaunchingProxied = null;
let browserLaunchFailed = false;        // once true, stop retrying direct launches this run
let browserLaunchFailedProxied = false; // same, for proxied launches

async function getBrowser(useProxy = false) {
  if (!puppeteer) return null;

  if (useProxy) {
    if (!SocksProxyAgent) return null; // home-ISP tunnel not configured — nothing to route through
    if (browserLaunchFailedProxied) return null; // already confirmed broken this run — don't retry every site
    if (browserInstanceProxied) return browserInstanceProxied;
    if (browserLaunchingProxied) return browserLaunchingProxied;
    const proxyArg = `--proxy-server=${SOCKS_PROXY_URL.replace('socks5h://', 'socks5://')}`;
    browserLaunchingProxied = puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu', proxyArg]
    }).then(b => {
      browserInstanceProxied = b;
      browserLaunchingProxied = null;
      b.on('disconnected', () => { browserInstanceProxied = null; });
      return b;
    }).catch(err => {
      console.warn('[!] Failed to launch proxied headless browser (won\'t retry again this run):', err.message);
      browserLaunchingProxied = null;
      browserLaunchFailedProxied = true;
      return null;
    });
    return browserLaunchingProxied;
  }

  if (browserLaunchFailed) return null; // already confirmed broken this run — don't retry every site
  if (browserInstance) return browserInstance;
  if (browserLaunching) return browserLaunching;
  browserLaunching = puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
  }).then(b => {
    browserInstance = b;
    browserLaunching = null;
    b.on('disconnected', () => { browserInstance = null; }); // will relaunch fresh next time it's needed
    return b;
  }).catch(err => {
    console.warn('[!] Failed to launch headless browser (won\'t retry again this run):', err.message);
    browserLaunching = null;
    browserLaunchFailed = true;
    return null;
  });
  return browserLaunching;
}

// Headless checks are expensive (real browser tab per check), so only a couple run at
// once regardless of how many sites need it — everything else just waits its turn.
let activeHeadlessChecks = 0;
const headlessQueue = [];
function processHeadlessQueue() {
  while (activeHeadlessChecks < HEADLESS_CONCURRENCY && headlessQueue.length > 0) {
    headlessQueue.shift()();
  }
}

function headlessCheck(targetUrl, timeoutMs, useProxy = false) {
  if (!puppeteer) return Promise.resolve(null);
  return new Promise((resolveOuter) => {
    const run = async () => {
      activeHeadlessChecks++;
      const start = Date.now();
      let page;
      try {
        const browser = await getBrowser(useProxy);
        if (!browser) { resolveOuter(null); return; }
        page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
        // networkidle2 (not domcontentloaded) — gives a JS-challenge page time to actually
        // resolve and redirect before we read the status, instead of capturing the
        // challenge page's own status code.
        const response = await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: timeoutMs });
        const status = response ? response.status() : 0;
        resolveOuter({ url: targetUrl, status, latency: Date.now() - start, error: null });
      } catch (e) {
        resolveOuter(null);
      } finally {
        if (page) { try { await page.close(); } catch (e) { /* ignore */ } }
        activeHeadlessChecks--;
        processHeadlessQueue();
      }
    };
    headlessQueue.push(run);
    processHeadlessQueue();
  });
}

async function checkStatus(targetUrl, timeoutMs = REQUEST_TIMEOUT_MS) {
  const firstTry = await attemptCheckStatus(targetUrl, timeoutMs);

  if (firstTry.error === 'TIMEOUT') {
    const secondTry = await attemptCheckStatus(targetUrl, timeoutMs);
    if (secondTry.error === 'TIMEOUT') {
      const impersonated = await impersonateCheck(targetUrl, timeoutMs);
      if (impersonated) return maybeUnblock(impersonated, targetUrl, timeoutMs);

      const viaHomeISP = await socksProxyCheck(targetUrl, timeoutMs);
      if (viaHomeISP) return maybeUnblock(viaHomeISP, targetUrl, timeoutMs);

      const headless = await headlessCheck(targetUrl, HEADLESS_TIMEOUT_MS);
      return headless || secondTry;
    }
    return maybeUnblock(secondTry, targetUrl, timeoutMs);
  }

  return maybeUnblock(firstTry, targetUrl, timeoutMs);
}

// Backoff tracking for the unblock chain: a site that's been blocked for many consecutive
// cycles gets probed less often, not more — repeatedly hitting a blocked site with several
// different automated methods every single cycle is exactly the pattern that causes
// adaptive bot-management (Cloudflare, Akamai, etc.) to escalate its response over time,
// which can make things worse rather than better. Sites that unblock stay probed at full
// frequency; only ones stuck for a while start backing off.
let scanCycleCount = 0;
const blockStreak = {}; // url -> { consecutiveBlocks: number, lastAttemptCycle: number }

function shouldAttemptUnblock(targetUrl) {
  const state = blockStreak[targetUrl];
  if (!state || state.consecutiveBlocks < 3) return true; // always try for the first few blocks
  const interval = state.consecutiveBlocks < 10 ? 3 : 10; // back off further the longer it stays blocked
  return (scanCycleCount - state.lastAttemptCycle) >= interval;
}

function recordUnblockOutcome(targetUrl, stillBlocked) {
  const state = blockStreak[targetUrl] || (blockStreak[targetUrl] = { consecutiveBlocks: 0, lastAttemptCycle: 0 });
  state.lastAttemptCycle = scanCycleCount;
  state.consecutiveBlocks = stillBlocked ? state.consecutiveBlocks + 1 : 0;
}

// A 403/404 is a "successful" HTTP response as far as the code is concerned, so it never
// reached the TIMEOUT-only fallback chain above. Some WAF blocks are based on TLS
// fingerprint or missing browser-realistic headers — curl-impersonate and the home-ISP
// tunnel can get past those specific kinds. JS-challenge-based bot management needs an
// actual browser to execute the challenge — that's what the headless fallback is for.
// If even a direct real browser is still blocked, the block is likely IP-reputation-based
// (this VPS's datacenter IP), not fingerprint-based — the proxied headless browser tries
// combining both fixes at once as the final, most expensive tier.
async function maybeUnblock(result, targetUrl, timeoutMs) {
  if (result.status !== 403 && result.status !== 404) return result;

  if (!shouldAttemptUnblock(targetUrl)) {
    return result; // backing off on this site — it's stayed blocked for a while, avoid over-probing it
  }

  const impersonated = await impersonateCheck(targetUrl, timeoutMs);
  if (impersonated && impersonated.status !== 403 && impersonated.status !== 404) {
    recordUnblockOutcome(targetUrl, false);
    return impersonated;
  }

  const viaHomeISP = await socksProxyCheck(targetUrl, timeoutMs);
  if (viaHomeISP && viaHomeISP.status !== 403 && viaHomeISP.status !== 404) {
    recordUnblockOutcome(targetUrl, false);
    return viaHomeISP;
  }

  const headless = await headlessCheck(targetUrl, HEADLESS_TIMEOUT_MS);
  if (headless && headless.status !== 403 && headless.status !== 404) {
    recordUnblockOutcome(targetUrl, false);
    return headless;
  }

  const headlessViaHomeISP = await headlessCheck(targetUrl, HEADLESS_TIMEOUT_MS, true);
  if (headlessViaHomeISP && headlessViaHomeISP.status !== 403 && headlessViaHomeISP.status !== 404) {
    recordUnblockOutcome(targetUrl, false);
    return headlessViaHomeISP;
  }

  recordUnblockOutcome(targetUrl, true);
  return result; // still blocked even with a real browser AND a different IP — genuine, sophisticated bot-management block
}

async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length);
  let index = 0;
  const worker = async () => {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

// --- Live update subscribers (Server-Sent Events) ---
const sseClients = new Set();
function broadcastUpdate() {
  const payload = `data: ${JSON.stringify(cachedData)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch (e) {
      sseClients.delete(res);
    }
  }
}

let scanInProgress = false;

async function runBackgroundScan() {
  if (scanInProgress) {
    console.log('[*] Previous scan still running (likely several sites in the headless-browser queue) — skipping this cycle.');
    return;
  }
  scanInProgress = true;
  try {
    scanCycleCount++;
    console.log('[*] Scanning endpoints...');
    const rawResults = await mapConcurrent(URLS, SCAN_CONCURRENCY, (url) => checkStatus(url));
    const now = new Date().toISOString();

    const resultsWithUptime = rawResults.map(item => {
      const isUp = item.status >= 200 && item.status < 400;
      const hist = historyStore[item.url] || (historyStore[item.url] = []);
      const prevStatus = hist.length > 0 ? hist[hist.length - 1] : 1; // assume up if no prior data yet
      hist.push(isUp ? 1 : 0);
      if (hist.length > MAX_HISTORY) hist.shift();

      const total = hist.length;
      const upCount = hist.reduce((acc, curr) => acc + curr, 0);
      const calculatedUptime = total > 0 ? parseFloat(((upCount / total) * 100).toFixed(1)) : 100.0;

      // Track downtime incidents: log when a site transitions down -> up, or is currently down.
      const inc = incidentStore[item.url] || (incidentStore[item.url] = { openSince: null, incidents: [] });
      if (!isUp && prevStatus === 1) {
        inc.openSince = now;
      } else if (isUp && prevStatus === 0 && inc.openSince) {
        inc.incidents.unshift({ start: inc.openSince, end: now });
        inc.incidents = inc.incidents.slice(0, MAX_INCIDENTS_PER_SITE);
        inc.openSince = null;
      }

      return {
        ...item,
        uptime: calculatedUptime,
        history: hist.slice(-10),       // compact, for card mini-bars
        historyFull: hist.slice(-50),   // longer window, for the per-site detail chart
        incidents: inc.incidents,
        downSince: inc.openSince
      };
    });

    cachedData = { timestamp: new Date().toUTCString().replace('GMT', 'UTC'), results: resultsWithUptime };
    persistHistory();
    broadcastUpdate();
    console.log('[+] Scan complete.');
  } finally {
    scanInProgress = false;
  }
}

runBackgroundScan();
const scanInterval = setInterval(runBackgroundScan, SCAN_INTERVAL_MS);

app.get('/healthz', (req, res) => res.status(200).json({ ok: true, lastScan: cachedData.timestamp }));

app.get('/api/scan', (req, res) => res.json(cachedData));

// Server-Sent Events stream: pushes the latest scan the moment it completes,
// instead of the browser having to poll /api/scan on a timer.
app.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify(cachedData)}\n\n`); // send current state immediately on connect
  sseClients.add(res);

  const keepAlive = setInterval(() => res.write(':\n\n'), 25000); // comment ping, keeps proxies from closing idle connection

  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

const server = app.listen(PORT, HOST, () => console.log(`Gov Monitoring Dashboard running on http://${HOST}:${PORT}`));

// A single bad request/rejection anywhere shouldn't be able to kill monitoring
// for all 83 sites — log it and keep the scanner running.
process.on('uncaughtException', (err) => {
  console.error('[!] Uncaught exception (scanner still running):', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[!] Unhandled rejection (scanner still running):', err);
});

// Shut down cleanly on deploy/restart signals: stop scheduling new scans,
// flush current history to disk, then close the HTTP server.
function shutdown(signal) {
  console.log(`[*] Received ${signal}, shutting down gracefully...`);
  clearInterval(scanInterval);
  clearTimeout(saveTimer);
  if (browserInstance) { browserInstance.close().catch(() => {}); }
  if (browserInstanceProxied) { browserInstanceProxied.close().catch(() => {}); }
  atomicWriteHistory(() => {
    server.close(() => {
      console.log('[*] Shutdown complete.');
      process.exit(0);
    });
  });
  // Force-exit if close hangs for some reason.
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
