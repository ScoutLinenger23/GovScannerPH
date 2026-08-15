import type { Config } from '@netlify/functions'
import { getStore } from '@netlify/blobs'
import { MONITORED_URLS } from './lib/scan-urls.mts'
import { checkStatus, mapConcurrent } from './lib/http-check.mts'

const SCAN_CONCURRENCY = 18
const REQUEST_TIMEOUT_MS = 10000
const MAX_HISTORY = 100
const MAX_INCIDENTS_PER_SITE = 20

export default async () => {
  const store = getStore('gov-scanner')

  const savedState = (await store.get('history', { type: 'json' })) as
    | { history: Record<string, number[]>; incidents: Record<string, { openSince: string | null; incidents: { start: string; end: string }[] }> }
    | null
  const historyStore = savedState?.history || {}
  const incidentStore = savedState?.incidents || {}
  MONITORED_URLS.forEach((u) => {
    if (!Array.isArray(historyStore[u])) historyStore[u] = []
    if (!incidentStore[u]) incidentStore[u] = { openSince: null, incidents: [] }
  })

  const rawResults = await mapConcurrent(MONITORED_URLS, SCAN_CONCURRENCY, (url) => checkStatus(url, REQUEST_TIMEOUT_MS))
  const now = new Date().toISOString()

  const resultsWithUptime = rawResults.map((item) => {
    const isUp = item.status >= 200 && item.status < 400
    const hist = historyStore[item.url] || (historyStore[item.url] = [])
    const prevStatus = hist.length > 0 ? hist[hist.length - 1] : 1 // assume up if no prior data yet
    hist.push(isUp ? 1 : 0)
    if (hist.length > MAX_HISTORY) hist.shift()

    const total = hist.length
    const upCount = hist.reduce((acc, curr) => acc + curr, 0)
    const calculatedUptime = total > 0 ? parseFloat(((upCount / total) * 100).toFixed(1)) : 100.0

    const inc = incidentStore[item.url] || (incidentStore[item.url] = { openSince: null, incidents: [] })
    if (!isUp && prevStatus === 1) {
      inc.openSince = now
    } else if (isUp && prevStatus === 0 && inc.openSince) {
      inc.incidents.unshift({ start: inc.openSince, end: now })
      inc.incidents = inc.incidents.slice(0, MAX_INCIDENTS_PER_SITE)
      inc.openSince = null
    }

    return {
      ...item,
      uptime: calculatedUptime,
      history: hist.slice(-10),
      historyFull: hist.slice(-50),
      incidents: inc.incidents,
      downSince: inc.openSince,
    }
  })

  const cachedData = { timestamp: new Date().toUTCString().replace('GMT', 'UTC'), results: resultsWithUptime }

  await store.setJSON('latest', cachedData)
  await store.setJSON('history', { history: historyStore, incidents: incidentStore })
}

export const config: Config = {
  background: true,
}
