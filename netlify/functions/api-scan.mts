import type { Config, Context } from '@netlify/functions'
import { getStore } from '@netlify/blobs'
import { placeholderScanData } from './lib/scan-urls.mts'

export default async (req: Request, context: Context) => {
  const store = getStore('gov-scanner')
  const cached = await store.get('latest', { type: 'json' })
  if (cached) return Response.json(cached)

  // No scan has completed yet (fresh deploy) — kick one off now instead of waiting for the
  // next scheduled tick, and return a placeholder immediately.
  context.waitUntil(fetch(`${context.site.url}/.netlify/functions/scan-background`, { method: 'POST' }).catch(() => {}))
  return Response.json(placeholderScanData())
}

export const config: Config = {
  path: '/api/scan',
}
