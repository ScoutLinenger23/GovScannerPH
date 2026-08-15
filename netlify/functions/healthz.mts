import type { Config } from '@netlify/functions'
import { getStore } from '@netlify/blobs'

export default async () => {
  const store = getStore('gov-scanner')
  const cached = (await store.get('latest', { type: 'json' })) as { timestamp: string } | null
  return Response.json({ ok: true, lastScan: cached ? cached.timestamp : null })
}

export const config: Config = {
  path: '/healthz',
}
