import { useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { CopyButton } from '../components/CopyButton'
import { LongText } from '../components/LongText'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'

export function EventDetailPage(){
  const {eventId=''}=useParams(),load=useCallback((signal:AbortSignal)=>api.event(eventId,signal),[eventId]),{data,error,loading,retry}=useApiResource(load),mode=useTimeMode()
  const raw=typeof data?.raw==='string'?data.raw:JSON.stringify(data?.raw??{})
  return <div className="page-stack"><Link to="/incidents" className="back-link">← Incidents</Link>{loading?<LoadingState label="Loading event evidence…"/>:error?<ErrorState error={error} retry={retry}/>:!data?<EmptyState>Event not found.</EmptyState>:<><section className="incident-hero panel"><p className="eyebrow">OBSERVED EVIDENCE</p><h1>{sanitizeSecurityText(data.event_type||'Unknown event')}</h1><p className="mono">{sanitizeSecurityText(data.id||data.event_id||eventId)}</p><div className="incident-meta"><div><span>TIMESTAMP · {mode}</span><time>{utcOrLocalTimestamp(data.timestamp,mode)}</time></div><div><span>SOURCE</span><strong>{sanitizeSecurityText(data.source_type||'Not available')}</strong></div><div><span>HOST</span><strong>{sanitizeSecurityText(data.host||'Not available')}</strong></div><div><span>USER</span><strong>{sanitizeSecurityText(data.user||'Not available')}</strong></div></div></section><section className="panel detail-card"><div className="inline-heading"><h2>Raw evidence</h2><CopyButton value={raw}/></div><pre className="raw-preview"><LongText value={raw} limit={1600} label="event raw evidence"/></pre></section></>}</div>
}
