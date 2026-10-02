import { useState } from 'react'
import { Link } from 'react-router-dom'
import { LongText } from './LongText'
import { CopyButton } from './CopyButton'
import { SeverityBadge } from './SeverityBadge'
import { useTimeMode } from '../layouts/SocLayout'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'

export type TimelineEvent = Record<string, unknown>
function rawText(value: unknown): string {
  try { return typeof value==='string'?value:JSON.stringify(value??'') } catch { return '[unavailable]' }
}
export function IncidentTimeline({ events }: { events: TimelineEvent[] }) {
  const mode=useTimeMode(), [open,setOpen]=useState<string[]>([])
  const bounded=events.slice(0,100)
  return <ol className="incident-timeline">{bounded.map((event,index)=>{
    const id=String(event.event_id||event.id||`event-${index}`), expanded=open.includes(id), raw=rawText(event.raw)
    return <li key={id}><span className="timeline-marker" aria-hidden="true"/><div className="timeline-card"><div className="timeline-head"><time dateTime={String(event.timestamp||'')}>{utcOrLocalTimestamp(event.timestamp,mode)}</time><SeverityBadge value={event.severity}/><strong>{sanitizeSecurityText(event.event_type||'Unknown event',100)}</strong><Link className="table-link" to={`/events/${encodeURIComponent(id)}`}>View evidence</Link><button className="text-button" type="button" aria-expanded={expanded} onClick={()=>setOpen(expanded?open.filter((key)=>key!==id):[...open,id])}>{expanded?'Hide details':'Show details'}</button></div>
      <dl className="timeline-fields"><div><dt>Source</dt><dd><LongText value={event.source_type}/></dd></div><div><dt>Host</dt><dd><LongText value={event.host}/></dd></div><div><dt>User</dt><dd><LongText value={event.user}/></dd></div><div><dt>Source IP</dt><dd><LongText value={event.src_ip}/></dd></div><div><dt>Destination IP</dt><dd><LongText value={event.dst_ip}/></dd></div></dl>
      {expanded&&<div className="timeline-raw"><div className="inline-heading"><strong>Observed evidence</strong><CopyButton value={raw}/></div><LongText value={raw} limit={1200} label="raw event evidence"/></div>}
    </div></li>
  })}{events.length>bounded.length&&<li className="subtle-copy">Showing first 100 of {events.length} events.</li>}</ol>
}
