import type { Config, Context } from '@netlify/functions'

// Scheduled functions have a 30-second execution limit, far too short to scan 83 sites with
// retries — so this just fires the background function (up to 15 minutes) and returns.
export default async (req: Request, context: Context) => {
  await fetch(`${context.site.url}/.netlify/functions/scan-background`, { method: 'POST' })
}

export const config: Config = {
  schedule: '*/2 * * * *',
}
