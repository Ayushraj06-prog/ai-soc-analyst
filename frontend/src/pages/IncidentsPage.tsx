import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, type IncidentQuery } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import { LongText } from '../components/LongText'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { Pager, PAGE_SIZE } from '../components/Pager'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'

type Filters = { status: string; severity: string; risk_level: string; min_risk_score:string; max_risk_score:string; confidence:string; primary_host: string; primary_user: string; primary_src_ip: string; since:string; until:string; sort: string }
const KEYS: (keyof Filters)[] = ['status','severity','risk_level','min_risk_score','max_risk_score','confidence','primary_host','primary_user','primary_src_ip','since','until','sort']
const DEFAULTS: Filters = { status:'',severity:'',risk_level:'',min_risk_score:'',max_risk_score:'',confidence:'',primary_host:'',primary_user:'',primary_src_ip:'',since:'',until:'',sort:'created_desc' }
function fromParams(params: URLSearchParams): Filters {
  return Object.fromEntries(KEYS.map((key) => [key, params.get(key) ?? (key === 'sort' ? 'created_desc' : '')])) as Filters
}

export function IncidentsPage() {
  const [search, setSearch] = useSearchParams()
  const queryKey = search.toString()
  const [filters, setFilters] = useState(() => fromParams(new URLSearchParams(queryKey)))
  const timeMode = useTimeMode()
  useEffect(() => { setFilters(fromParams(new URLSearchParams(queryKey))) }, [queryKey])
  const query = useMemo<IncidentQuery>(() => {
    const params = new URLSearchParams(queryKey)
    const sort = params.get('sort') || 'created_desc'
    return {
      status: params.get('status') || undefined,
      severity: params.get('severity') || undefined,
      risk_level: params.get('risk_level') || undefined,
      min_risk_score:params.get('min_risk_score')?Number(params.get('min_risk_score')):undefined,
      max_risk_score:params.get('max_risk_score')?Number(params.get('max_risk_score')):undefined,
      confidence:params.get('confidence')||undefined,
      primary_host: params.get('primary_host') || undefined,
      primary_user: params.get('primary_user') || undefined,
      primary_src_ip: params.get('primary_src_ip') || undefined,
      since:params.get('since')||undefined,
      until:params.get('until')||undefined,
      sort: sort as IncidentQuery['sort'],
      limit: PAGE_SIZE,
      offset: (Math.max(1, Number(params.get('page') || 1)) - 1) * PAGE_SIZE,
    }
  }, [queryKey])
  const load = useCallback((signal: AbortSignal) => api.incidents(query, signal), [query])
  const { data, error, loading, retry } = useApiResource(load)
  const apply = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const next = new URLSearchParams()
    for (const key of KEYS) {
      const value = filters[key].trim()
      if (value && (key !== 'sort' || value !== 'created_desc')) next.set(key, value)
    }
    setSearch(next)
  }
  const reset = () => { setFilters(DEFAULTS); setSearch(new URLSearchParams()) }

  return <div className="page-stack">
    <div className="page-heading"><div><p className="eyebrow">CASE MANAGEMENT</p><h1>Incidents</h1><p className="subtle-copy">Correlated incidents, risk, and evidence from the SOC engine.</p></div><span className="read-only-chip">ANALYST WORKFLOW</span></div>
    <form className="filter-panel panel" onSubmit={apply} aria-label="Incident filters">
      <div className="filter-heading"><div><h2>Filters</h2><span className="subtle-copy">Exact match · server-side pagination</span></div><button className="button button-secondary" type="button" onClick={reset}>Clear</button></div>
      <div className="filter-grid">
        <label className="field-label">Status (exact)<input value={filters.status} onChange={(e) => setFilters({ ...filters, status:e.target.value })} /></label>
        <label className="field-label">Severity (exact)<input value={filters.severity} onChange={(e) => setFilters({ ...filters, severity:e.target.value })} /></label>
        <label className="field-label">Risk level (exact)<input value={filters.risk_level} onChange={(e) => setFilters({ ...filters, risk_level:e.target.value })} /></label>
        <label className="field-label">Minimum risk score<input type="number" min="0" max="100" value={filters.min_risk_score} onChange={(e)=>setFilters({...filters,min_risk_score:e.target.value})}/></label>
        <label className="field-label">Maximum risk score<input type="number" min="0" max="100" value={filters.max_risk_score} onChange={(e)=>setFilters({...filters,max_risk_score:e.target.value})}/></label>
        <label className="field-label">Confidence (exact)<input value={filters.confidence} onChange={(e)=>setFilters({...filters,confidence:e.target.value})}/></label>
        <label className="field-label">Primary host (exact)<input value={filters.primary_host} onChange={(e) => setFilters({ ...filters, primary_host:e.target.value })} /></label>
        <label className="field-label">Primary user (exact)<input value={filters.primary_user} onChange={(e) => setFilters({ ...filters, primary_user:e.target.value })} /></label>
        <label className="field-label">Primary source IP (exact)<input value={filters.primary_src_ip} onChange={(e) => setFilters({ ...filters, primary_src_ip:e.target.value })} inputMode="decimal" /></label>
        <label className="field-label">Since (UTC ISO)<input value={filters.since} onChange={(e)=>setFilters({...filters,since:e.target.value})} placeholder="2026-01-01T00:00:00Z"/></label>
        <label className="field-label">Until (UTC ISO)<input value={filters.until} onChange={(e)=>setFilters({...filters,until:e.target.value})} placeholder="2026-01-31T23:59:59Z"/></label>
        <label className="field-label">Sort<select value={filters.sort} onChange={(e) => setFilters({ ...filters, sort:e.target.value })}>
          <option value="created_desc">Newest first</option><option value="created_asc">Oldest first</option><option value="risk_desc">Highest risk</option><option value="risk_asc">Lowest risk</option>
        </select></label>
      </div>
      <div className="filter-actions"><button className="button button-primary" type="submit">Apply filters</button></div>
    </form>
    <section className="panel table-panel" aria-labelledby="incidents-table-title">
      <div className="table-heading"><div><p className="eyebrow">CORRELATED CASES</p><h2 id="incidents-table-title">Incident queue</h2></div><span className="count-pill">{data?.total ?? '—'} records</span></div>
      {loading ? <LoadingState label="Loading incidents…" /> : error ? <ErrorState error={error} retry={retry} /> : !data?.items?.length ? <EmptyState>No incidents found.</EmptyState> : <>
        <div className="table-scroll"><table aria-label="Incidents"><thead><tr><th>Risk</th><th>Severity</th><th>Incident</th><th>Title</th><th>Score</th><th>Confidence</th><th>Status</th><th>Primary host</th><th>Primary user</th><th>Source IP</th><th>First seen</th><th>Last seen</th><th>Detections</th></tr></thead>
          <tbody>{(data.items ?? []).map((incident) => <tr key={incident.incident_id}>
            <td><SeverityBadge value={incident.risk_level} /></td><td><SeverityBadge value={incident.severity}/></td>
            <td className="mono"><Link className="table-link" to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>{sanitizeSecurityText(incident.incident_id,160)}</Link></td>
            <td><LongText value={incident.title} limit={120} /></td><td className="risk-score">{incident.risk_score ?? 'Not available'}</td>
            <td>{typeof incident.confidence === 'number' ? `${Math.round(incident.confidence * 100)}%` : sanitizeSecurityText(incident.confidence || 'Not available')}</td>
            <td><span className="status-text">{sanitizeSecurityText(incident.status || 'Unknown')}</span></td>
            <td><LongText value={incident.primary_host} limit={90} /></td><td><LongText value={incident.primary_user} limit={90} /></td>
            <td className="mono">{sanitizeSecurityText(incident.primary_src_ip || 'Not available')}</td>
            <td><time dateTime={incident.first_seen || undefined}>{utcOrLocalTimestamp(incident.first_seen,timeMode)}</time></td>
            <td><time dateTime={incident.last_seen || undefined}>{utcOrLocalTimestamp(incident.last_seen,timeMode)}</time></td><td>{incident.detection_count??'—'}</td>
          </tr>)}</tbody></table></div><Pager total={data.total} limit={data.limit} />
      </>}
    </section>
  </div>
}
