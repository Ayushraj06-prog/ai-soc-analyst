const ANSI = /\u001b\[[0-?]*[ -/]*[@-~]/g
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g
const BIDI = /[\u202a-\u202e\u2066-\u2069]/g
const INVISIBLE = /[\u200b-\u200f\u2060\ufeff]/g
const MAX_SECURITY_TEXT = 8_000

export function sanitizeSecurityText(value: unknown, maximum = MAX_SECURITY_TEXT): string {
  if (value === null || value === undefined) return ''
  const cap = Math.max(0, Math.min(maximum, MAX_SECURITY_TEXT))
  return String(value).replace(ANSI, '').replace(CONTROL, '').replace(BIDI, '').replace(INVISIBLE, '').slice(0, cap)
}

export function displayEnum(value: unknown, knownValues: readonly string[]): string {
  if (typeof value !== 'string') return 'Unknown'
  return knownValues.find((candidate) => candidate.toLowerCase() === value.toLowerCase()) ?? 'Unknown'
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational', 'info'] as const
export const INCIDENT_STATUSES = ['open', 'acknowledged', 'investigating', 'confirmed', 'false_positive', 'resolved', 'closed'] as const
export const ALERT_STATUSES = ['new', 'open', 'acknowledged', 'triaged', 'investigating', 'resolved', 'suppressed'] as const

export function utcOrLocalTimestamp(value: unknown, mode: 'UTC' | 'LOCAL'): string {
  const text = sanitizeSecurityText(value, 100)
  if (!text) return 'Not available'
  const date = new Date(text)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    ...(mode === 'UTC' ? { timeZone: 'UTC', timeZoneName: 'short' as const } : { timeZoneName: 'short' as const }),
  }).format(date)
}

export function isNonLoopbackHttp(apiBase: string): boolean {
  try {
    const url = new URL(apiBase, window.location.origin)
    if (url.protocol !== 'http:') return false
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (host === 'localhost' || host === '::1') return false
    const parts = host.split('.').map(Number)
    if (parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return parts[0] !== 127
    return true
  } catch { return false }
}
