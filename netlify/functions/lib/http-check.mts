import https from 'node:https'
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'

const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 30 })
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 30 })
// Secondary, clearly-labeled reachability check used ONLY when the primary request fails on a
// broken cert chain — results are always tagged 'INSECURE_CERT' so callers show an honest
// warning rather than silently treating an untrusted cert as a clean "up".
const httpsAgentInsecure = new https.Agent({ keepAlive: true, maxSockets: 10, rejectUnauthorized: false })

const CERT_CHAIN_ERROR_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_UNTRUSTED',
])

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// Last-resort check when a response is malformed enough that Node's HTTP parser can't handle
// it. Bypasses HTTP parsing entirely — connects raw, sends a minimal request by hand, and reads
// the status line directly off the wire.
function rawSocketCheck(targetUrl, timeoutMs) {
  return new Promise((resolve) => {
    let resolved = false
    const start = Date.now()
    let socket
    const done = (val) => {
      if (resolved) return
      resolved = true
      try { socket && socket.destroy() } catch (e) { /* ignore */ }
      resolve(val)
    }

    let parsedUrl
    try { parsedUrl = new URL(targetUrl) } catch (e) { return done(null) }
    const isHttps = parsedUrl.protocol === 'https:'
    const host = parsedUrl.hostname
    const port = parsedUrl.port || (isHttps ? 443 : 80)

    const timer = setTimeout(() => done(null), timeoutMs)

    try {
      socket = isHttps
        ? tls.connect({ host, port, servername: host })
        : net.connect({ host, port })
    } catch (e) {
      clearTimeout(timer)
      return done(null)
    }

    socket.on(isHttps ? 'secureConnect' : 'connect', () => {
      const reqPath = parsedUrl.pathname + parsedUrl.search || '/'
      socket.write(
        `GET ${reqPath} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${USER_AGENT}\r\nConnection: close\r\n\r\n`
      )
    })

    let buffer = ''
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      const match = buffer.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/)
      if (match) {
        clearTimeout(timer)
        done({ url: targetUrl, status: parseInt(match[1], 10), latency: Date.now() - start, error: null })
      }
    })

    socket.on('error', () => { clearTimeout(timer); done(null) })
    socket.on('close', () => { clearTimeout(timer); done(null) })
  })
}

function toggleWwwUrl(targetUrl) {
  try {
    const u = new URL(targetUrl)
    u.hostname = u.hostname.startsWith('www.') ? u.hostname.slice(4) : ('www.' + u.hostname)
    return u.toString()
  } catch (e) {
    return null
  }
}

// Confirms a site is reachable despite a broken cert chain, WITHOUT pretending the cert is
// trustworthy. Result is always tagged error: 'INSECURE_CERT'.
function certReachabilityCheck(targetUrl, timeoutMs) {
  return new Promise((resolve) => {
    let resolved = false
    const start = Date.now()
    const done = (v) => { if (!resolved) { resolved = true; resolve(v) } }
    const timer = setTimeout(() => done(null), timeoutMs)
    try {
      const req = https.request(
        targetUrl,
        {
          method: 'GET',
          agent: httpsAgentInsecure,
          insecureHTTPParser: true,
          family: 4,
          headers: { 'User-Agent': USER_AGENT },
        },
        (res) => {
          clearTimeout(timer)
          res.destroy()
          done({ url: targetUrl, status: res.statusCode, latency: Date.now() - start, error: 'INSECURE_CERT' })
        }
      )
      req.on('error', () => { clearTimeout(timer); done(null) })
      req.end()
    } catch (e) {
      clearTimeout(timer)
      done(null)
    }
  })
}

function attemptCheckStatus(targetUrl, timeoutMs, _isAltHostRetry = false) {
  return new Promise((resolve) => {
    let resolved = false
    const start = Date.now()
    const safeResolve = (val) => { if (!resolved) { resolved = true; resolve(val) } }

    const hardTimer = setTimeout(() => {
      safeResolve({ url: targetUrl, status: 0, latency: 0, error: 'TIMEOUT' })
    }, timeoutMs)

    try {
      const parsedUrl = new URL(targetUrl)
      const isHttps = parsedUrl.protocol === 'https:'
      const protocol = isHttps ? https : http
      const agent = isHttps ? httpsAgent : httpAgent

      const req = protocol.request(
        targetUrl,
        {
          method: 'GET',
          agent,
          insecureHTTPParser: true,
          family: 4,
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
          },
        },
        (res) => {
          clearTimeout(hardTimer)
          res.destroy()
          safeResolve({ url: targetUrl, status: res.statusCode, latency: Date.now() - start, error: null })
        }
      )

      req.on('error', async (err) => {
        clearTimeout(hardTimer)

        if (err.code && err.code.startsWith('HPE_')) {
          await sleep(750)
          const raw = await rawSocketCheck(targetUrl, timeoutMs)
          if (raw) { safeResolve(raw); return }
        }

        if ((err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' || err.code === 'ENOTFOUND') && !_isAltHostRetry) {
          await sleep(750)
          const altUrl = toggleWwwUrl(targetUrl)
          if (altUrl) {
            const altResult = await attemptCheckStatus(altUrl, timeoutMs, true)
            if (altResult && altResult.status) { safeResolve({ ...altResult, url: targetUrl }); return }
          }
        }

        if (err.code && (CERT_CHAIN_ERROR_CODES.has(err.code) || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID')) {
          await sleep(750)
          let certResult = await certReachabilityCheck(targetUrl, timeoutMs)
          if (!certResult) {
            await sleep(1200)
            certResult = await certReachabilityCheck(targetUrl, timeoutMs)
          }
          if (certResult) { safeResolve(certResult); return }
        }

        safeResolve({ url: targetUrl, status: 0, latency: 0, error: err.code || 'CONN_ERR' })
      })

      req.end()
    } catch (e) {
      clearTimeout(hardTimer)
      safeResolve({ url: targetUrl, status: 0, latency: 0, error: 'INVALID' })
    }
  })
}

// One retry on timeout to filter out one-off slow responses / transient network blips.
export async function checkStatus(targetUrl, timeoutMs = 10000) {
  const firstTry = await attemptCheckStatus(targetUrl, timeoutMs)
  if (firstTry.error === 'TIMEOUT') {
    return attemptCheckStatus(targetUrl, timeoutMs)
  }
  return firstTry
}

export async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length)
  let index = 0
  const worker = async () => {
    while (index < items.length) {
      const i = index++
      results[i] = await fn(items[i])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()))
  return results
}
