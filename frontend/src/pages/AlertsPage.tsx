import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, type AlertQuery } from '../api/client'
import { EnumBadge, SeverityBadge } from '../components/SeverityBadge'
import { LongText } from '../components/LongText'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import { Pager, PAGE_SIZE } from '../components/Pager'
import { useApiResource } from '../hooks/useApiResource'
import { useTimeMode } from '../layouts/SocLayout'
import { ALERT_STATUSES, sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'

type AlertFilters = { severity: string; status: string; rule_id: string; mitre_technique: string; source_ip: string; user: string; host: string; since: string; until: string; search: string; sort: string }
const keys: (keyof AlertFilters)[] = ['severity','status','rule_id','mitre_technique','source_ip','user','host','since','until','search','sort']
const emptyFilters: AlertFilters = { severity: '', status: '', rule_id: '', mitre_technique:'', source_ip: '', user: '', host: '', since: '', until: '', search:'', sort:'timestamp_desc' }
function valuesFrom(params: URLSearchParams): AlertFilters {
  return Object.fromEntries(keys.map((key) => [key, params.get(key) ?? ''])) as AlertFilters
}
function toUtc(value: string): string {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toISOString()
}
function confidence(value: unknown): string {
  if (typeof value === 'number') return `${Math.round(value * 100)}%`
  return typeof value === 'string' ? sanitizeSecurityText(value) : 'Not available'
}
function toLocalInput(value: string): string {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toISOString().slice(0, 16)
}

export function AlertsPage() {
  const [search, setSearch] = useSearchParams()
  const queryKey = search.toString()
  const initial = valuesFrom(new URLSearchParams(queryKey))
  const [filters, setFilters] = useState<AlertFilters>(initial)
  const timeMode = useTimeMode()
  const page = Math.max(1, Number(new URLSearchParams(queryKey).get('page') || 1))
  useEffect(() => { setFilters(valuesFrom(new URLSearchParams(queryKey))) }, [queryKey])
  const query = useMemo<AlertQuery>(() => {
    const params = new URLSearchParams(queryKey)
    return {
      severity: params.get('severity') || undefined,
      status: params.get('status') || undefined,
      rule_id: params.get('rule_id') || undefined,
      mitre_technique: params.get('mitre_technique') || undefined,
      source_ip: params.get('source_ip') || undefined,
      user: params.get('user') || undefined,
      host: params.get('host') || undefined,
      since: params.get('since') || undefined,
      until: params.get('until') || undefined,
      search: params.get('search') || undefined,
      sort: (params.get('sort') || 'timestamp_desc') as AlertQuery['sort'],
      limit: PAGE_SIZE,
      offset: (Math.max(1, Number(params.get('page') || 1)) - 1) * PAGE_SIZE,
    }
  }, [queryKey])
  const load = useCallback((signal: AbortSignal) => api.alerts(query, signal), [query])
  const { data, error, loading, retry } = useApiResource(load)
  const apply = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const next = new URLSearchParams()
    for (const key of keys) {
      const value = key === 'since' || key === 'until' ? toUtc(filters[key]) : filters[key].trim()
      if (value && (key !== 'sort' || value !== 'timestamp_desc')) next.set(key, value)
    }
    setSearch(next)
  }
  const reset = () => { setFilters(emptyFilters); setSearch(new URLSearchParams()) }

  return <div className="page-stack">
    <div className="page-heading"><div><p className="eyebrow">DETECTION OPERATIONS</p><h1>Alert queue</h1><p className="subtle-copy">Phase 3 deterministic detections from the persisted alert store.</p></div><span className="read-only-chip">READ ONLY</span></div>
    <form className="filter-panel panel" onSubmit={apply} aria-label="Alert filters">
      <div className="filter-heading"><div><h2>Filters</h2><span className="subtle-copy">Exact match · UTC timestamps</span></div><button className="button button-secondary" type="button" onClick={reset}>Clear</button></div>
      <div className="filter-grid">
        <label className="field-label">Severity (exact)<input value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })} placeholder="e.g. high" /></label>
        <label className="field-label">Status (exact)<input value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })} placeholder="e.g. NEW" /></label>
        <label className="field-label">Rule ID (exact)<input value={filters.rule_id} onChange={(e) => setFilters({ ...filters, rule_id: e.target.value })} placeholder="R001" /></label>
        <label className="field-label">MITRE technique (exact)<input value={filters.mitre_technique} onChange={(e) => setFilters({ ...filters, mitre_technique:e.target.value })} placeholder="T1110" /></label>
        <label className="field-label">Search text<input value={filters.search} onChange={(e) => setFilters({ ...filters, search:e.target.value })} placeholder="ID, rule, user, host…" /></label>
        <label className="field-label">Source IP (exact)<input value={filters.source_ip} onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })} inputMode="decimal" /></label>
        <label className="field-label">User (exact)<input value={filters.user} onChange={(e) => setFilters({ ...filters, user: e.target.value })} /></label>
        <label className="field-label">Host (exact)<input value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} /></label>
        <label className="field-label">Since (local input, sent as UTC)<input type="datetime-local" value={toLocalInput(filters.since)} onChange={(e) => setFilters({ ...filters, since: e.target.value })} /></label>
        <label className="field-label">Until (local input, sent as UTC)<input type="datetime-local" value={toLocalInput(filters.until)} onChange={(e) => setFilters({ ...filters, until: e.target.value })} /></label>
        <label className="field-label">Sort<select value={filters.sort} onChange={(e)=>setFilters({...filters,sort:e.target.value})}><option value="timestamp_desc">Newest first</option><option value="timestamp_asc">Oldest first</option><option value="severity_desc">Highest severity</option></select></label>
      </div>
      <div className="filter-actions"><button className="button button-primary" type="submit">Apply filters</button></div>
    </form>
    <section className="panel table-panel" aria-labelledby="alerts-table-title">
      <div className="table-heading"><div><p className="eyebrow">DETECTIONS</p><h2 id="alerts-table-title">Alert queue</h2></div><span className="count-pill">{data?.total ?? '—'} records</span></div>
      {loading ? <LoadingState label="Loading alerts…" /> : error ? <ErrorState error={error} retry={retry} /> : !data?.items?.length ? <EmptyState>No alerts found.</EmptyState> : <>
        <div className="table-scroll"><table aria-label="Alerts"><thead><tr><th>Severity</th><th>Alert ID</th><th>Timestamp</th><th>Rule</th><th>Source IP</th><th>User</th><th>Host</th><th>Confidence</th><th>MITRE</th><th>Status</th><th>Incident</th></tr></thead>
          <tbody>{(data.items ?? []).map((alert) => <tr key={alert.alert_id}>
            <td><SeverityBadge value={alert.severity} /></td><td className="mono"><Link className="table-link" to={`/alerts/${encodeURIComponent(alert.alert_id || '')}`}>{sanitizeSecurityText(alert.alert_id || 'Not available', 160)}</Link></td>
            <td><time dateTime={alert.timestamp || undefined}>{utcOrLocalTimestamp(alert.timestamp, timeMode)}</time></td>
            <td className="mono">{sanitizeSecurityText(alert.rule_id || 'Not available', 100)}</td>
            <td className="mono">{sanitizeSecurityText(alert.source_ip || 'Not available', 100)}</td><td><LongText value={alert.username} limit={80} /></td><td><LongText value={alert.hostname} limit={80} /></td>
            <td>{confidence(alert.confidence)}</td><td>{sanitizeSecurityText(alert.mitre_technique||'Not available')}</td><td><EnumBadge value={alert.status} values={ALERT_STATUSES} /></td>
            <td>{alert.incident_id?<Link className="table-link" to={`/incidents/${encodeURIComponent(alert.incident_id)}`}>View incident</Link>:'—'}</td>
          </tr>)}</tbody></table></div>
        <Pager total={data.total} limit={data.limit} />
      </>}
    </section>
    <span className="sr-only" aria-live="polite">Page {page}</span>
  </div>
}
