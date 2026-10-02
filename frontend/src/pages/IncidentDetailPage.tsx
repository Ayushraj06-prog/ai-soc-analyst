import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError, type IncidentPatch } from '../api/client'
import { CopyButton } from '../components/CopyButton'
import { LongText } from '../components/LongText'
import { SeverityBadge } from '../components/SeverityBadge'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'
import { IncidentTimeline } from '../components/IncidentTimeline'
import { AttackMappingCard } from '../components/AttackMappingCard'
import { IOCValue } from '../components/IOCValue'

type AnalystFields = { status: string; notes: string }

export function IncidentDetailPage() {
  const { incidentId = '' } = useParams()
  const [reloadVersion, setReloadVersion] = useState(0)
  const [fields, setFields] = useState<AnalystFields>({ status:'',notes:'' })
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [conflict, setConflict] = useState(false)
  const [runningInvestigation,setRunningInvestigation]=useState(false)
  const [investigationError,setInvestigationError]=useState('')
  const [latestInvestigation,setLatestInvestigation]=useState<import('../api/client').Investigation|null>(null)
  const reloadRef = useRef<HTMLButtonElement>(null)
  const timeMode = useTimeMode()
  const load = useCallback((signal: AbortSignal) => api.incident(incidentId,signal),[incidentId])
  const { data, error, loading, retry } = useApiResource(load)
  const loadInvestigations=useCallback((signal:AbortSignal)=>api.incidentInvestigations(incidentId,signal),[incidentId])
  const history=useApiResource(loadInvestigations)
  const loadAudit=useCallback((signal:AbortSignal)=>api.audit({resource_type:'incident',resource_id:incidentId,limit:50,offset:0},signal),[incidentId])
  const audit=useApiResource(loadAudit)

  useEffect(()=>{if(reloadVersion>0)retry()},[reloadVersion,retry])

  useEffect(() => {
    if (!data) return
    const dynamic = data as Record<string, unknown>
    setFields({ status:typeof data.status === 'string' ? data.status : '', notes:typeof dynamic.analyst_notes === 'string' ? dynamic.analyst_notes : '' })
  },[data])

  useEffect(() => {
    if (!conflict) return
    reloadRef.current?.focus()
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setConflict(false) }
    window.addEventListener('keydown',onKey)
    return () => window.removeEventListener('keydown',onKey)
  },[conflict])

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();setSaving(true);setSaveError('');setConflict(false)
    const patch: IncidentPatch = { status:fields.status,notes:fields.notes }
    try {
      await api.patchIncident(incidentId,patch)
      setReloadVersion((version) => version+1)
    } catch (reason) {
      if (reason instanceof ApiError && reason.status===409) setConflict(true)
      else setSaveError(safeMessage(reason))
    } finally { setSaving(false) }
  }

  const runInvestigation=async()=>{
    setRunningInvestigation(true);setInvestigationError('');setLatestInvestigation(null)
    try{const result=await api.investigate(incidentId);setLatestInvestigation(result);history.retry()}
    catch(reason){setInvestigationError(reason instanceof Error?reason.message:'Investigation could not be started.')}
    finally{setRunningInvestigation(false)}
  }
  const investigationComparison=()=>{
    const runs=history.data?.items||[]
    if(runs.length<2)return null
    const [newer,older]=runs
    const values=(input:unknown)=>Array.isArray(input)?input.map((value)=>JSON.stringify(value)):[]
    const newerFindings=values(newer.findings),olderFindings=values(older.findings),newerActions=values(newer.recommendations),olderActions=values(older.recommendations)
    const addedFindings=newerFindings.filter((value)=>!olderFindings.includes(value)),removedFindings=olderFindings.filter((value)=>!newerFindings.includes(value))
    const addedActions=newerActions.filter((value)=>!olderActions.includes(value)),removedActions=olderActions.filter((value)=>!newerActions.includes(value))
    return <article className="comparison-card"><h3>Run comparison · #{newer.run_number} vs #{older.run_number}</h3><p>Classification: {sanitizeSecurityText(older.classification||'not provided')} → {sanitizeSecurityText(newer.classification||'not provided')}</p><p>AI confidence: {sanitizeSecurityText(older.ai_confidence||'not provided')} → {sanitizeSecurityText(newer.ai_confidence||'not provided')}</p><p>Findings added: {addedFindings.length} · removed: {removedFindings.length}. Recommendations changed: {addedActions.length+removedActions.length>0?'yes':'no'}.</p>{addedFindings.length>0&&<p><strong>Added findings:</strong> <LongText value={addedFindings.join(' · ')} limit={800}/></p>}{removedFindings.length>0&&<p><strong>Removed findings:</strong> <LongText value={removedFindings.join(' · ')} limit={800}/></p>}{addedActions.length>0&&<p><strong>Added recommendations:</strong> <LongText value={addedActions.join(' · ')} limit={800}/></p>}{removedActions.length>0&&<p><strong>Removed recommendations:</strong> <LongText value={removedActions.join(' · ')} limit={800}/></p>}</article>
  }

  return <div className="page-stack">
    <div className="back-row"><Link to="/incidents" className="back-link">← Incidents</Link><span className="read-only-chip">CORRELATED INCIDENT</span></div>
    {loading ? <LoadingState label="Loading incident evidence…" /> : error ? <ErrorState error={error} retry={retry} /> : !data ? <EmptyState>Incident not found.</EmptyState> : <>
      <section className="incident-hero panel">
        <div className="incident-hero-top"><div><p className="eyebrow">INCIDENT</p><h1><LongText value={data.title || data.incident_id} limit={180} /></h1><p className="mono subdued-id">{sanitizeSecurityText(data.incident_id,180)}</p></div>
          <div className="risk-score-card"><span>RISK SCORE</span><strong>{data.risk_score ?? '—'}</strong><SeverityBadge value={data.risk_level} /></div></div>
        <div className="incident-meta"><div><span>STATUS</span><strong>{sanitizeSecurityText(data.status || 'Unknown')}</strong></div><div><span>CONFIDENCE</span><strong>{typeof data.confidence==='number'?`${Math.round(data.confidence*100)}%`:sanitizeSecurityText(data.confidence||'Not available')}</strong></div>
          <div><span>FIRST SEEN · {timeMode}</span><time dateTime={data.first_seen||undefined}>{utcOrLocalTimestamp(data.first_seen,timeMode)}</time></div><div><span>LAST SEEN · {timeMode}</span><time dateTime={data.last_seen||undefined}>{utcOrLocalTimestamp(data.last_seen,timeMode)}</time></div></div>
      </section>
      <section className="detail-grid" aria-label="Incident details">
        <article className="panel detail-card"><p className="eyebrow">PRIMARY FIELDS</p><h2>Observed entities</h2>
          <dl className="detail-list"><div><dt>Primary host</dt><dd><LongText value={data.primary_host} /></dd></div><div><dt>Primary user</dt><dd><LongText value={data.primary_user} /></dd></div><div><dt>Primary source IP</dt><dd className="copyable-value"><LongText value={data.primary_src_ip} /><CopyButton value={data.primary_src_ip || ''} /></dd></div></dl>
        </article>
        <article className="panel detail-card"><p className="eyebrow">CASE SUMMARY</p><h2>Description</h2><p className="body-copy description-text"><LongText value={data.description} limit={600} label="description" /></p></article>
      </section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">LINKED DETECTIONS</p><h2>Evidence references</h2></div><span className="count-pill">{data.detection_ids?.length ?? 0} detections</span></div>
        {!data.detection_ids?.length ? <EmptyState>No detection references are linked to this incident.</EmptyState> : <ul className="reference-list">{data.detection_ids.map((id) => <li key={id}><span className="mono">{sanitizeSecurityText(id,180)}</span><Link to={`/alerts/${encodeURIComponent(id)}`} className="table-link">View detection</Link></li>)}</ul>}
        <h3 className="section-subtitle">Incident timeline · chronological evidence</h3>
        {data.events?.length?<IncidentTimeline events={data.events as unknown as Record<string,unknown>[]}/>:<EmptyState>No linked event evidence is available.</EmptyState>}
      </section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">OBSERVED INDICATORS</p><h2>IOC references</h2></div><span className="count-pill">{data.iocs?.length ?? 0}</span></div>
        {!data.iocs?.length ? <EmptyState>No IOC references are linked to this incident.</EmptyState> : <ul className="reference-list">{data.iocs.map((ioc,index) => { const value=typeof ioc.value==='string'?ioc.value:'';return <li key={typeof ioc.ioc_id==='string'?ioc.ioc_id:String(index)}><IOCValue iocId={ioc.ioc_id??undefined} value={value} type={ioc.type??undefined}/></li> })}</ul>}
      </section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">RELATIONSHIPS</p><h2>Detection graph</h2></div></div><div className="relationship-tree"><div className="relationship-root"><strong>Incident</strong><span className="mono">{sanitizeSecurityText(data.incident_id)}</span></div>{data.detection_ids?.map((id)=><article key={id} className="relationship-branch"><strong>Detection</strong><Link to={`/alerts/${encodeURIComponent(id)}`} className="table-link mono">{sanitizeSecurityText(id,160)}</Link><span>Evidence: {data.events?.length||0} linked event(s)</span><span>ATT&CK: {(data.attack_mappings||[]).filter((mapping)=>mapping.detection_id===id).length} mapping(s)</span></article>)}{data.iocs?.map((ioc,index)=><article key={String(ioc.ioc_id||index)} className="relationship-branch"><strong>IOC</strong><IOCValue iocId={ioc.ioc_id??undefined} value={ioc.value||''} type={ioc.type??undefined}/></article>)}</div></section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">ATT&CK CONTEXT</p><h2>Evidence-backed technique mappings</h2></div><Link to="/attack" className="table-link">All mappings</Link></div>{!data.attack_mappings?.length?<EmptyState>No ATT&CK mappings are linked to this incident.</EmptyState>:<div className="attack-grid">{data.attack_mappings.map((mapping,index)=><AttackMappingCard key={String(mapping.id||index)} mapping={mapping}/>)}</div>}</section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">EVIDENCE-BOUNDED AI · ADVISORY</p><h2>Investigation</h2></div><span className="confidence-chip">AI-generated output</span></div><p className="subtle-copy">Before execution: incident {sanitizeSecurityText(data.incident_id)} · {data.events?.length||0} linked events · next stored run #{(history.data?.total||0)+1} · {history.data?.items?.[0]?`${sanitizeSecurityText(history.data.items[0].provider||'Provider unavailable')} / ${sanitizeSecurityText(history.data.items[0].model||'Model unavailable')}`:'provider/model will be reported by the run'}.</p>{!data.events?.length&&<p className="security-warning">This incident has no linked event evidence. Phase 6 may return an empty-evidence result.</p>}{investigationError&&<div role="alert" className="inline-error">{sanitizeSecurityText(investigationError,500)}</div>}<button className="button button-primary" type="button" onClick={()=>void runInvestigation()} disabled={runningInvestigation}>{runningInvestigation?'Investigating evidence… validating output…':'Run AI Investigation'}</button>{latestInvestigation&&<article className="ai-result"><p className="eyebrow">INVESTIGATION RESULT · AI-GENERATED</p><h3>{sanitizeSecurityText(latestInvestigation.status)} · run #{latestInvestigation.run_number??'—'}</h3><p><LongText value={latestInvestigation.summary} limit={1500} label="AI investigation summary"/></p><p className="subtle-copy">Classification {sanitizeSecurityText(latestInvestigation.classification||'not provided')} · confidence {sanitizeSecurityText(latestInvestigation.ai_confidence||'not provided')}</p><Link to={`/investigations/${encodeURIComponent(latestInvestigation.investigation_id)}`} className="table-link">Review full evidence and recommendations</Link></article>}{history.loading?<LoadingState label="Loading prior runs…"/>:history.error?<ErrorState error={history.error} retry={history.retry}/>:history.data?.items?.length?<>{investigationComparison()}<ul className="reference-list">{history.data.items.map((run)=><li key={run.investigation_id}><Link className="table-link" to={`/investigations/${encodeURIComponent(run.investigation_id)}`}>Run #{run.run_number} · {sanitizeSecurityText(run.status)}</Link><span>{utcOrLocalTimestamp(run.started_at,timeMode)}</span><span>{sanitizeSecurityText(run.provider||'')} / {sanitizeSecurityText(run.model||'')}</span></li>)}</ul></>:<EmptyState>No investigation history.</EmptyState>}</section>
      <section className="panel detail-card"><div className="table-heading"><div><p className="eyebrow">AUDIT HISTORY</p><h2>Incident activity</h2></div><Link to={`/audit?resource_type=incident&resource_id=${encodeURIComponent(data.incident_id)}`} className="table-link">Open audit log</Link></div>{audit.loading?<LoadingState label="Loading audit history…"/>:audit.error?<ErrorState error={audit.error} retry={audit.retry}/>:!audit.data?.items?.length?<EmptyState>No audit history is recorded for this incident.</EmptyState>:<ol className="activity-list">{audit.data.items.map((entry)=><li key={entry.audit_id}><time>{utcOrLocalTimestamp(entry.timestamp,timeMode)}</time><span className="activity-kind">{sanitizeSecurityText(entry.action)}</span><span>{sanitizeSecurityText(entry.actor||'System')}</span><LongText value={JSON.stringify(entry.details||{})} limit={240} label="audit detail"/></li>)}</ol>}</section>
      <section className="panel detail-card analyst-editor"><div><p className="eyebrow">ANALYST FIELDS</p><h2>Update incident notes</h2><p className="subtle-copy">Updates use the backend PATCH contract and are recorded in the audit log.</p></div>
        {saveError&&<div role="alert" className="inline-error">{saveError}</div>}
        <form onSubmit={(event)=>void save(event)} className="analyst-form">
          <label className="field-label">Status<input maxLength={32} value={fields.status} onChange={(event)=>setFields({...fields,status:event.target.value})}/></label>
          <label className="field-label">Analyst notes<textarea maxLength={4000} rows={4} value={fields.notes} onChange={(event)=>setFields({...fields,notes:event.target.value})}/></label>
          <button className="button button-primary" type="submit" disabled={saving}>{saving?'Saving…':'Save analyst fields'}</button>
        </form>
      </section>
    </>}
    {conflict&&<div className="dialog-backdrop"><section className="conflict-dialog" role="dialog" aria-modal="true" aria-labelledby="conflict-title"><p className="eyebrow">EDIT CONFLICT</p><h2 id="conflict-title">This incident changed elsewhere. Reload the latest version before editing.</h2><p className="subtle-copy">Your changes were not retried or applied again.</p><button ref={reloadRef} className="button button-primary" type="button" onClick={()=>{setConflict(false);setReloadVersion((v)=>v+1)}}>Reload</button><button className="text-button" type="button" onClick={()=>setConflict(false)}>Close</button></section></div>}
  </div>
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unable to connect to SOC API.'
}
