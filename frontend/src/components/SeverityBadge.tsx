import { displayEnum, SEVERITIES, sanitizeSecurityText } from '../utils/security'

const styles: Record<string, string> = { critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low', informational: 'severity-info', info: 'severity-info' }

export function SeverityBadge({ value }: { value: unknown }) {
  const label = displayEnum(value, SEVERITIES)
  const style = label === 'Unknown' ? 'severity-unknown' : styles[label.toLowerCase()] ?? 'severity-unknown'
  const text = label === 'Unknown' ? 'Unknown' : sanitizeSecurityText(value).toUpperCase()
  return <span className={`severity-badge ${style}`} aria-label={`Severity: ${text}`}><span aria-hidden="true">●</span> {text}</span>
}

export function EnumBadge({ value, values }: { value: unknown; values: readonly string[] }) {
  const label = displayEnum(value, values)
  return <span className={`severity-badge ${label === 'Unknown' ? 'severity-unknown' : 'severity-neutral'}`}>{label === 'Unknown' ? label : sanitizeSecurityText(label)}</span>
}
