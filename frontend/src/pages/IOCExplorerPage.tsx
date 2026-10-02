import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { Pager, PAGE_SIZE } from '../components/Pager'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { utcOrLocalTimestamp, sanitizeSecurityText } from '../utils/security'
import { classifyIP, IOCValue } from '../components/IOCValue'

export function IOCExplorerPage() {
  const [params,setParams]=useSearchParams(), key=params.toString(), mode=useTimeMode()
  const [type,setType]=useState(new URLSearchParams(key).get('type')||''),[value,setValue]=useState(new URLSearchParams(key).get('value')||'')
  useEffect(()=>{const p=new URLSearchParams(key);setType(p.get('type')||'');setValue(p.get('value')||'')},[key])
  const parsedParams=new URLSearchParams(key),page=Math.max(1,Number(parsedParams.get('page')||1)),query=useMemo(()=>{const parsed=new URLSearchParams(key);return {type:parsed.get('type')||undefined,value:parsed.get('value')||undefined,limit:PAGE_SIZE,offset:(page-1)*PAGE_SIZE}},[key,page])
  const load=useCallback((signal:AbortSignal)=>api.iocs(query,signal),[query]),{data,error,loading,retry}=useApiResource(load)
  const submit=(event:FormEvent)=>{event.preventDefault();const p=new URLSearchParams();if(type.trim())p.set('type',type.trim());if(value.trim())p.set('value',value.trim());setParams(p)}
  return <div className="page-stack"><div className="page-heading"><div><p className="eyebrow">OBSERVED INDICATORS</p><h1>IOC explorer</h1><p className="subtle-copy">Indicators are observed in telemetry. Their presence alone does not establish maliciousness.</p></div></div>
    <form className="filter-panel panel" aria-label="IOC filters" onSubmit={submit}><div className="filter-grid"><label className="field-label">Type (exact)<input value={type} onChange={(e)=>setType(e.target.value)} placeholder="ip, domain, hash…"/></label><label className="field-label">Value (exact)<input value={value} onChange={(e)=>setValue(e.target.value)}/></label></div><div className="filter-actions"><button className="button button-primary">Apply</button><button className="button button-secondary" type="button" onClick={()=>{setType('');setValue('');setParams(new URLSearchParams())}}>Clear</button></div></form>
    <section className="panel table-panel"><div className="table-heading"><h2>Indicators</h2><span className="count-pill">{data?.total??'—'} records</span></div>{loading?<LoadingState label="Loading indicators…"/>:error?<ErrorState error={error} retry={retry}/>:!data?.items?.length?<EmptyState>No indicators found.</EmptyState>:<><div className="table-scroll"><table aria-label="Indicators"><thead><tr><th>Type</th><th>Value</th><th>First seen</th><th>Last seen</th><th>Occurrences</th></tr></thead><tbody>{data.items.map((ioc,index)=><tr key={String(ioc.ioc_id||index)}><td>{sanitizeSecurityText(ioc.type||'Unknown')}</td><td><IOCValue iocId={ioc.ioc_id??undefined} value={ioc.value||''} type={ioc.type??undefined}/></td><td><time>{utcOrLocalTimestamp(ioc.first_seen,mode)}</time></td><td><time>{utcOrLocalTimestamp(ioc.last_seen,mode)}</time></td><td>{ioc.occurrence_count??'Open for detail'}</td></tr>)}</tbody></table></div><Pager total={data.total} limit={data.limit}/></>}</section>
  </div>
}

export function IOCDetailPage() {
  const {iocId=''}=useParams(),load=useCallback((signal:AbortSignal)=>api.ioc(iocId,signal),[iocId]),{data,error,loading,retry}=useApiResource(load),mode=useTimeMode()
  return <div className="page-stack"><Link to="/iocs" className="back-link">← IOC explorer</Link>{loading?<LoadingState label="Loading IOC relationships…"/>:error?<ErrorState error={error} retry={retry}/>:!data?<EmptyState>Indicator not found.</EmptyState>:<>
    <section className="incident-hero panel"><p className="eyebrow">OBSERVED INDICATOR · {sanitizeSecurityText(data.type||'UNKNOWN')}</p><h1><span className="ioc-inert">{sanitizeSecurityText(data.value,400)}</span></h1><p className="subtle-copy">Observed · occurrence count {data.occurrence_count??0}. This record carries no standalone malicious verdict.</p><div className="incident-meta"><div><span>FIRST SEEN · {mode}</span><time>{utcOrLocalTimestamp(data.first_seen,mode)}</time></div><div><span>LAST SEEN · {mode}</span><time>{utcOrLocalTimestamp(data.last_seen,mode)}</time></div><div><span>CLASSIFICATION</span><strong>{data.type?.toLowerCase()==='ip'?classifySafe(data.value||''):'Observed'}</strong></div></div></section>
    <section className="panel detail-card"><h2>Related incidents</h2>{!data.incidents?.length?<EmptyState>No related incidents.</EmptyState>:<ul className="reference-list">{data.incidents.map((item)=><li key={item.incident_id}><Link to={`/incidents/${encodeURIComponent(item.incident_id)}`} className="table-link">{sanitizeSecurityText(item.title||item.incident_id)}</Link><span>{sanitizeSecurityText(item.status||'Unknown')}</span></li>)}</ul>}</section>
    <section className="panel detail-card"><h2>Related detections</h2>{!data.detections?.length?<EmptyState>No related detections.</EmptyState>:<ul className="reference-list">{data.detections.map((item)=><li key={item.alert_id}><Link to={`/alerts/${encodeURIComponent(item.alert_id||'')}`} className="table-link">{sanitizeSecurityText(item.rule_id||item.alert_id||'Detection')}</Link><span>{sanitizeSecurityText(item.severity||'Unknown')}</span></li>)}</ul>}</section>
    <section className="panel detail-card"><h2>Related events</h2>{!data.events?.length?<EmptyState>No related events.</EmptyState>:<div className="table-scroll"><table aria-label="Related events"><thead><tr><th>Timestamp</th><th>Type</th><th>Host</th><th>User</th><th>Source IP</th><th>Destination IP</th></tr></thead><tbody>{data.events.slice(0,100).map((event,index)=><tr key={String(event.event_id||index)}><td>{utcOrLocalTimestamp(event.timestamp,mode)}</td><td>{sanitizeSecurityText(event.event_type||'Unknown')}</td><td>{sanitizeSecurityText(event.host||'—')}</td><td>{sanitizeSecurityText(event.user||'—')}</td><td>{sanitizeSecurityText(event.src_ip||'—')}</td><td>{sanitizeSecurityText(event.dst_ip||'—')}</td></tr>)}</tbody></table></div>}</section>
  </>}</div>
}
function classifySafe(value:string):string { return classifyIP(value) }
