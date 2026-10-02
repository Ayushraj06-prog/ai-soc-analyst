import { Children, useCallback, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { sanitizeSecurityText } from '../utils/security'

export function SearchPage() {
  const [params]=useSearchParams(),query=params.get('q')||''
  const load=useCallback((signal:AbortSignal)=>query.length>=2?api.search(query,10,signal):Promise.resolve({query,incidents:[],alerts:[],iocs:[]}),[query]),{data,error,loading,retry}=useApiResource(load)
  return <div className="page-stack"><div className="page-heading"><div><p className="eyebrow">BOUNDED API SEARCH</p><h1>Search SOC data</h1><p className="subtle-copy">Results are limited to incidents, detections, and observed indicators.</p></div></div>
    {query.length<2?<EmptyState>Enter at least two characters in the global search field.</EmptyState>:loading?<LoadingState label="Searching SOC records…"/>:error?<ErrorState error={error} retry={retry}/>:<>
      <SearchGroup title="Incidents" empty="No matching incidents.">{data?.incidents.map((item)=><li key={item.incident_id}><Link to={`/incidents/${encodeURIComponent(item.incident_id)}`} className="table-link">{sanitizeSecurityText(item.title||item.incident_id)}</Link><span>{sanitizeSecurityText(item.status||'Unknown')} · {sanitizeSecurityText(item.severity||'Unknown')} · risk {item.risk_score??'—'}</span></li>)}</SearchGroup>
      <SearchGroup title="Alerts" empty="No matching alerts.">{data?.alerts.map((item)=><li key={item.alert_id}><Link to={`/alerts/${encodeURIComponent(item.alert_id||'')}`} className="table-link">{sanitizeSecurityText(item.rule_id||item.alert_id)}</Link><span>{sanitizeSecurityText(item.severity||'Unknown')} · {sanitizeSecurityText(item.host||'')} · {sanitizeSecurityText(item.user||'')}</span></li>)}</SearchGroup>
      <SearchGroup title="IOCs" empty="No matching IOCs.">{data?.iocs.map((item)=><li key={item.ioc_id}><span className="ioc-inert">{sanitizeSecurityText(item.value||'')}</span><span>{sanitizeSecurityText(item.type||'Unknown')} · observed indicator</span><Link to={`/iocs/${encodeURIComponent(item.ioc_id||'')}`} className="table-link">View IOC</Link></li>)}</SearchGroup>
    </>}
  </div>
}
function SearchGroup({title,empty,children}:{title:string;empty:string;children:ReactNode}) {const list=Children.toArray(children);return <section className="panel detail-card"><h2>{title}</h2>{!list.length?<EmptyState>{empty}</EmptyState>:<ul className="reference-list">{children}</ul>}</section>}
