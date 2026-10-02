import { useCallback } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { api } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { Pager, PAGE_SIZE } from '../components/Pager'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'
import { LongText } from '../components/LongText'

export function AuditPage() {
  const [params]=useSearchParams(),page=Math.max(1,Number(params.get('page')||1)),mode=useTimeMode(),resourceType=params.get('resource_type')||undefined,resourceId=params.get('resource_id')||undefined
  const load=useCallback((signal:AbortSignal)=>api.audit({resource_type:resourceType,resource_id:resourceId,limit:PAGE_SIZE,offset:(page-1)*PAGE_SIZE},signal),[page,resourceType,resourceId]),{data,error,loading,retry}=useApiResource(load)
  return <div className="page-stack"><div className="page-heading"><div><p className="eyebrow">ACCOUNTABILITY</p><h1>Audit history</h1><p className="subtle-copy">Recorded analyst workflow and system activity from the audit store.</p></div></div><section className="panel table-panel"><h2>Audit records</h2>{loading?<LoadingState label="Loading audit records…"/>:error?<ErrorState error={error} retry={retry}/>:!data?.items?.length?<EmptyState>No audit records found.</EmptyState>:<div className="table-scroll"><table aria-label="Audit history"><thead><tr><th>Timestamp</th><th>Action</th><th>Actor</th><th>Target</th><th>Summary</th></tr></thead><tbody>{data.items.map((item)=><tr key={item.audit_id}><td>{utcOrLocalTimestamp(item.timestamp,mode)}</td><td>{sanitizeSecurityText(item.action,120)}</td><td>{sanitizeSecurityText(item.actor||'Not available',100)}</td><td>{item.resource_type==='incident'&&item.resource_id?<Link className="table-link" to={`/incidents/${encodeURIComponent(item.resource_id)}`}>{sanitizeSecurityText(item.resource_id)}</Link>:sanitizeSecurityText(item.resource_id||item.resource_type,180)}</td><td><LongText value={JSON.stringify(item.details||{})} limit={240} label="audit summary"/></td></tr>)}</tbody></table></div>}</section>{data&&<Pager total={data.total} limit={data.limit}/>}</div>
}
