import { useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, type DashboardActivityQuery } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { SeverityBadge } from '../components/SeverityBadge'
import { LongText } from '../components/LongText'
import { useTimeMode } from '../layouts/SocLayout'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'
import { AssistantChat } from '../components/AssistantChat'

const KPI = [
  ['active_incidents','Active incidents','/incidents'],
  ['critical_incidents','Critical incidents','/incidents?severity=CRITICAL'],
  ['high_severity_alerts','High severity alerts','/alerts?severity=HIGH'],
  ['unresolved_alerts','Unresolved alerts','/alerts'],
  ['recent_investigations','Investigations · 7 days','/investigations'],
  ['ioc_count','Observed IOCs','/iocs'],
  ['detection_count','Detections','/alerts'],
] as const

export function DashboardPage() {
  const timeMode=useTimeMode()
  const [activityParams,setActivityParams]=useSearchParams()
  const activityQuery=new URLSearchParams(activityParams.toString())
  const activityKind=(activityQuery.get('activity_kind')||undefined) as DashboardActivityQuery['kind']
  const activitySeverity=activityQuery.get('activity_severity')||''
  const activityWindow=activityQuery.get('activity_window')||'24h'
  const summaryLoad=useCallback((signal:AbortSignal)=>api.dashboardSummary(signal),[])
  const trendLoad=useCallback((signal:AbortSignal)=>api.dashboardTrends(14,signal),[])
  const statusLoad=useCallback((signal:AbortSignal)=>api.systemStatus(signal),[])
  const activityLoad=useCallback((signal:AbortSignal)=>{
    const hours=activityWindow==='24h'?24:activityWindow==='7d'?168:activityWindow==='30d'?720:0
    const since=hours?new Date(Date.now()-hours*3600000).toISOString():undefined
    return api.dashboardActivity({kind:activityKind,severity:activitySeverity||undefined,since,limit:12},signal)
  },[activityKind,activitySeverity,activityWindow])
  const summary=useApiResource(summaryLoad), trends=useApiResource(trendLoad), activity=useApiResource(activityLoad), system=useApiResource(statusLoad)
  const maxTrend=Math.max(1,...(trends.data?.alert_activity||[]).map((row)=>row.count))
  return <div className="page-stack">
    <div className="page-heading"><div><p className="eyebrow">SECURITY OPERATIONS · {system.data?.environment==='demo'?'SYNTHETIC DATA':'LIVE DATA'}</p><h1>SOC overview</h1><p className="subtle-copy">Evidence-led operational view from persisted detections, incidents, indicators, and investigations.</p></div><div><span className="read-only-chip">ANALYST CONTROLLED</span>{system.data?.environment==='demo'&&<span className="read-only-chip">DEMO DATA</span>}</div></div>
    <section aria-label="SOC metrics" className="kpi-grid">
      {summary.loading?<LoadingState label="Loading SOC metrics…"/>:summary.error?<ErrorState error={summary.error} retry={summary.retry}/>:KPI.map(([key,label,to])=><Link key={key} to={to} className="kpi-card"><span>{label}</span><strong>{summary.data?.[key]??0}</strong><small>View records <span aria-hidden="true">→</span></small></Link>)}
    </section>
    <section className="panel detail-card" aria-label="System status"><div className="table-heading"><div><p className="eyebrow">SYSTEM STATUS</p><h2>Operational dependencies</h2></div><span className="read-only-chip">SIMULATION MODE</span></div>
      {system.loading?<LoadingState label="Loading system status…"/>:system.error?<ErrorState error={system.error} retry={system.retry}/>:<div className="source-grid"><div className="source-column"><h3>API</h3><p className="subtle-copy">● {system.data?.status==='ok'?'Healthy':'Degraded'}</p><p className="subtle-copy">Environment: {sanitizeSecurityText(system.data?.environment||'unknown',32)}</p></div><div className="source-column"><h3>Database</h3><p className="subtle-copy">● {system.data?.database==='ok'?'Connected':'Unavailable'}</p><p className="subtle-copy">Schema: {system.data?.schema_version??'unknown'}</p></div><div className="source-column"><h3>AI Provider</h3><p className="subtle-copy">● {sanitizeSecurityText(system.data?.ai_provider_status||'unknown',32)}</p><p className="subtle-copy">Provider: {sanitizeSecurityText(system.data?.ai_provider||'unknown',32)}</p></div></div>}
    </section>
    <AssistantChat />
    <section className="dashboard-columns">
      <article className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">DETECTION SIGNAL</p><h2>Severity distribution</h2></div><Link to="/alerts" className="table-link">Open alert queue</Link></div>
        {trends.loading?<LoadingState/>:trends.error?<ErrorState error={trends.error} retry={trends.retry}/>:!trends.data?.severity_distribution.length?<EmptyState>No detections are available for this view.</EmptyState>:<ul className="severity-bars">{['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].map((level)=>{const value=trends.data?.severity_distribution.find((row)=>row.severity===level)?.count||0;const maximum=Math.max(1,...trends.data!.severity_distribution.map((row)=>row.count));return <li key={level}><SeverityBadge value={level}/><span className="bar-track"><span style={{width:`${Math.max(value?4:0,value/maximum*100)}%`}}/></span><strong>{value}</strong></li>})}</ul>}
      </article>
      <article className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">14 DAY TREND</p><h2>Alert activity</h2></div></div>
        {trends.loading?<LoadingState/>:trends.error?<ErrorState error={trends.error} retry={trends.retry}/>:<div className="trend-list">{(trends.data?.alert_activity||[]).map((row)=><div className="trend-row" key={row.date}><time>{sanitizeSecurityText(row.date,20)}</time><span className="bar-track"><span style={{width:`${Math.max(2,row.count/maxTrend*100)}%`}}/></span><strong>{row.count}</strong></div>)}{!trends.data?.alert_activity.length&&<EmptyState>No alerts in the selected period.</EmptyState>}</div>}
        <p className="subtle-copy">Daily alert counts · backend aggregate · last {trends.data?.days||14} days</p>
      </article>
      <article className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">14 DAY TREND</p><h2>Incident creation</h2></div></div>{trends.loading?<LoadingState/>:trends.error?<ErrorState error={trends.error} retry={trends.retry}/>:trends.data?.incident_activity.length?<div className="trend-list">{trends.data.incident_activity.map((row)=><div className="trend-row" key={row.date}><time>{sanitizeSecurityText(row.date,20)}</time><span className="bar-track"><span style={{width:`${Math.max(3,row.count/Math.max(1,...trends.data!.incident_activity.map((item)=>item.count))*100)}%`}}/></span><strong>{row.count}</strong></div>)}</div>:<EmptyState>No incidents in the selected period.</EmptyState>}</article>
    </section>
    <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">OBSERVED SOURCE CONCENTRATION</p><h2>Top sources in detections</h2></div><Link to="/alerts" className="table-link">Review alerts</Link></div>{trends.loading?<LoadingState/>:trends.error?<ErrorState error={trends.error} retry={trends.retry}/>:<div className="source-grid">{(['source_ip','user','host','rule'] as const).map((kind)=><div className="source-column" key={kind}><h3>{kind==='source_ip'?'Source IP':kind==='user'?'User':kind==='host'?'Host':'Rule'}</h3>{(trends.data?.top_sources[kind]||[]).length?<ol>{trends.data?.top_sources[kind].map((row,index)=><li key={`${String(row.value)}-${index}`}><LongText value={row.value} limit={100}/><strong>{row.count}</strong></li>)}</ol>:<p className="subtle-copy">No values available.</p>}</div>)}</div>}</section>
    <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">RECENT SOC ACTIVITY</p><h2>Analyst activity stream</h2></div><Link to="/audit" className="table-link">Audit history</Link></div>
      <form className="responsive-filters" aria-label="Activity filters" onSubmit={(event)=>{event.preventDefault();const form=new FormData(event.currentTarget),next=new URLSearchParams(activityParams.toString());for(const [key,param] of [['kind','activity_kind'],['severity','activity_severity'],['window','activity_window']]){const value=String(form.get(key)||'');if(value)next.set(param,value);else next.delete(param)}setActivityParams(next)}}>
        <label className="field-label">Type<select name="kind" defaultValue={activityKind||''}><option value="">All activity</option><option value="detection">Detections</option><option value="incident">Incidents</option><option value="investigation">Investigations</option></select></label>
        <label className="field-label">Severity<select name="severity" defaultValue={activitySeverity}><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFORMATIONAL</option></select></label>
        <label className="field-label">Time range<select name="window" defaultValue={activityWindow}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="all">All time</option></select></label><button className="button button-secondary" type="submit">Apply activity filters</button>
      </form>
      {activity.loading?<LoadingState label="Loading recent activity…"/>:activity.error?<ErrorState error={activity.error} retry={activity.retry}/>:!activity.data?.items?.length?<EmptyState>No recent SOC activity.</EmptyState>:<ol className="activity-list">{activity.data.items.map((item)=><li key={`${item.kind}-${item.id}`}><time dateTime={item.timestamp}>{utcOrLocalTimestamp(item.timestamp,timeMode)}</time><span className="activity-kind">{sanitizeSecurityText(item.kind,32)}</span><LongText value={item.title||item.id} limit={180}/><Link className="table-link" to={item.kind==='incident'?`/incidents/${encodeURIComponent(item.id)}`:item.kind==='investigation'?`/investigations/${encodeURIComponent(item.id)}`:`/alerts/${encodeURIComponent(item.id)}`}>Open</Link></li>)}</ol>}
    </section>
    <section className="overview-grid" aria-label="SOC workspaces"><Link className="quick-card" to="/alerts"><span><strong>Alert queue</strong><small>Filter, search, and triage deterministic detections</small></span><span className="arrow" aria-hidden="true">→</span></Link><Link className="quick-card" to="/incidents"><span><strong>Incident workspace</strong><small>Review linked events, IOCs, mappings, and investigations</small></span><span className="arrow" aria-hidden="true">→</span></Link></section>
  </div>
}
