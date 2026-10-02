import { useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'
import { CopyButton } from '../components/CopyButton'
import { LongText } from '../components/LongText'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { AttackMappingCard } from '../components/AttackMappingCard'
import { IOCValue } from '../components/IOCValue'

function stringValue(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? sanitizeSecurityText(value) : ''
}

export function AlertDetailPage() {
  const { alertId = '' } = useParams()
  const timeMode = useTimeMode()
  const load = useCallback((signal: AbortSignal) => api.alert(alertId,signal),[alertId])
  const { data, error, loading, retry } = useApiResource(load)
  const fields = (data ?? {}) as Record<string, unknown>
  const evidence = Array.isArray(fields.evidence_refs) ? fields.evidence_refs : Array.isArray(fields.evidence) ? fields.evidence : []
  const iocs = Array.isArray(fields.iocs) ? fields.iocs : Array.isArray(fields.ioc_values) ? fields.ioc_values : []
  const mappings = Array.isArray(fields.attack_mappings) ? fields.attack_mappings : Array.isArray(fields.mitre) ? fields.mitre : []
  const events = Array.isArray(fields.events)?fields.events:[]

  return <div className="page-stack">
    <div className="back-row"><Link to="/alerts" className="back-link">← Alert queue</Link><span className="read-only-chip">DETERMINISTIC DETECTION</span></div>
    {loading ? <LoadingState label="Loading detection detail…" /> : error ? <ErrorState error={error} retry={retry} /> : !data ? <EmptyState>Alert not found.</EmptyState> : <>
      <section className="incident-hero panel"><div className="incident-hero-top"><div><p className="eyebrow">PHASE 3 · DETERMINISTIC DETECTION</p><h1>Alert detail</h1><p className="mono subdued-id">{sanitizeSecurityText(data.alert_id || alertId,180)}</p></div><SeverityBadge value={data.severity} /></div>
        <div className="incident-meta"><div><span>TIMESTAMP · {timeMode}</span><time dateTime={data.timestamp || undefined}>{utcOrLocalTimestamp(data.timestamp,timeMode)}</time></div><div><span>STATUS</span><strong>{stringValue(data.status)||'Unknown'}</strong></div><div><span>RULE</span><strong className="mono">{stringValue(data.rule_id)||'Not available'}</strong></div><div><span>CONFIDENCE</span><strong>{stringValue(data.confidence)||'Not available'}</strong></div></div>
      </section>
      <section className="detail-grid"><article className="panel detail-card"><p className="eyebrow">OBSERVED ENTITIES</p><h2>Detection context</h2><dl className="detail-list">
        <div><dt>Source IP</dt><dd className="copyable-value"><LongText value={fields.source_ip} />{stringValue(fields.source_ip)&&<CopyButton value={stringValue(fields.source_ip)} />}</dd></div>
        <div><dt>User</dt><dd><LongText value={fields.username} /></dd></div><div><dt>Host</dt><dd><LongText value={fields.hostname} /></dd></div><div><dt>Event type</dt><dd><LongText value={fields.event_type} /></dd></div>
      </dl></article><article className="panel detail-card"><p className="eyebrow">RULE EXPLANATION</p><h2>Why this detection fired</h2><p className="body-copy"><LongText value={fields.explanation ?? fields.reason ?? fields.description} limit={600} label="explanation" /></p></article></section>
      {typeof fields.incident_id==='string'&&<section className="panel detail-card"><p className="eyebrow">CORRELATED CASE</p><h2>Incident</h2><Link to={`/incidents/${encodeURIComponent(fields.incident_id)}`} className="table-link">View incident {sanitizeSecurityText(fields.incident_id,160)}</Link></section>}
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">ATT&CK CONTEXT</p><h2>Evidence-backed technique mappings</h2></div><Link to="/attack" className="table-link">All mappings</Link></div>{mappings.length ? <div className="attack-grid">{mappings.map((item,index)=><AttackMappingCard key={stringValue((item as Record<string,unknown>)?.technique_id)||index} mapping={(item&&typeof item==='object'?item:{}) as Record<string,unknown>}/>)}</div> : <p className="subtle-copy">No MITRE mapping is available on this alert response.</p>}</section>
      <section className="panel detail-card"><p className="eyebrow">OBSERVED EVIDENCE</p><h2>Evidence events</h2>{events.length?<div className="table-scroll"><table aria-label="Detection evidence"><thead><tr><th>Timestamp</th><th>Source</th><th>Host</th><th>User</th><th>Source IP</th><th>Destination IP</th><th>Event type</th><th>Raw preview</th></tr></thead><tbody>{events.slice(0,100).map((event,index)=>{const row=event as Record<string,unknown>,id=stringValue(row.id||row.event_id);return <tr key={id||index}><td>{utcOrLocalTimestamp(row.timestamp,timeMode)}{id&&<div><Link className="table-link" to={`/events/${encodeURIComponent(id)}`}>View evidence</Link></div>}</td><td>{stringValue(row.source_type)||'—'}</td><td><LongText value={row.host}/></td><td><LongText value={row.user}/></td><td>{stringValue(row.src_ip)||'—'}</td><td>{stringValue(row.dst_ip)||'—'}</td><td>{stringValue(row.event_type)||'Unknown'}</td><td><LongText value={row.raw&&typeof row.raw==='object'?JSON.stringify(row.raw):row.raw} limit={240} label="raw evidence"/></td></tr>})}</tbody></table></div>:<>{evidence.length?<ul className="reference-list">{evidence.map((value,index)=>{const id=stringValue(value);return <li key={`${id}-${index}`}><span className="mono">{id||'Unknown reference'}</span></li>})}</ul>:<EmptyState>No evidence references are available on this alert.</EmptyState>}</>}</section>
      <section className="panel detail-card"><p className="eyebrow">IOC VALUES</p><h2>Observed indicators</h2>{iocs.length ? <ul className="reference-list">{iocs.map((item,index)=>{const row=(item&&typeof item==='object'?item:{value:item}) as Record<string,unknown>;const value=stringValue(row.value);return <li key={stringValue(row.ioc_id)||`${value}-${index}`}><IOCValue iocId={stringValue(row.ioc_id)||undefined} value={value} type={stringValue(row.type)}/></li>})}</ul> : <p className="subtle-copy">No IOC values are available on this alert response.</p>}</section>
    </>}
  </div>
}
