import { useCallback } from 'react'
import { api } from '../api/client'
import { AttackMappingCard } from '../components/AttackMappingCard'
import { LoadingState, ErrorState, EmptyState } from '../components/States'
import { Pager, PAGE_SIZE } from '../components/Pager'
import { useApiResource } from '../hooks/useApiResource'

export function AttackPage() {
  const load=useCallback((signal:AbortSignal)=>api.attackMappings({limit:PAGE_SIZE,offset:0},signal),[]),{data,error,loading,retry}=useApiResource(load)
  return <div className="page-stack"><div className="page-heading"><div><p className="eyebrow">DETERMINISTIC & ENRICHMENT CONTEXT</p><h1>MITRE ATT&CK</h1><p className="subtle-copy">Only stored mappings are shown. Evidence references and baseline disagreements remain explicit.</p></div></div><section className="panel detail-card"><div className="table-heading"><h2>Evidence-backed mappings</h2><span className="count-pill">{data?.total??'—'}</span></div>{loading?<LoadingState label="Loading ATT&CK mappings…"/>:error?<ErrorState error={error} retry={retry}/>:!data?.items?.length?<EmptyState>No ATT&CK mappings are available.</EmptyState>:<div className="attack-grid">{data.items.map((mapping)=><AttackMappingCard key={mapping.id} mapping={mapping}/>)}</div>}</section>{data&&<Pager total={data.total} limit={data.limit}/>}</div>
}
