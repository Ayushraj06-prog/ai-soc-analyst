import { useState } from 'react'
import { sanitizeSecurityText } from '../utils/security'

export function LongText({ value, limit = 280, label = 'value' }: { value: unknown; limit?: number; label?: string }) {
  const [expanded, setExpanded] = useState(false)
  const text = sanitizeSecurityText(value)
  const long = text.length > limit
  return <span className="long-text">
    <span>{long && !expanded ? `${text.slice(0, limit)}…` : text || 'Not available'}</span>
    {long && <button className="text-button" type="button" aria-expanded={expanded} onClick={() => setExpanded((open) => !open)}>{expanded ? 'Show less' : `Show more ${label}`}</button>}
  </span>
}
