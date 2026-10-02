import type { paths, components } from './generated'

export type Alert = components['schemas']['AlertResponse']
export type Event = components['schemas']['EventResponse']
export type IOC = components['schemas']['IOCResponse']
export type Incident = components['schemas']['IncidentResponse']
export type IncidentDetail = components['schemas']['IncidentDetailResponse']
export type Investigation = components['schemas']['InvestigationResponse']
export type AuditEntry = components['schemas']['AuditResponse']
export type IOCDetail = IOC
export type DashboardSummary = components['schemas']['DashboardSummary']
export type DashboardTrends = components['schemas']['DashboardTrends']
export type DashboardActivity = paths['/api/v1/dashboard/activity']['get']['responses'][200]['content']['application/json']
export type IOCPage = paths['/api/v1/iocs']['get']['responses'][200]['content']['application/json']
export type InvestigationPage = paths['/api/v1/investigations']['get']['responses'][200]['content']['application/json']
export type AuditPage = paths['/api/v1/audit']['get']['responses'][200]['content']['application/json']
export type AttackMappingPage = paths['/api/v1/attack/mappings']['get']['responses'][200]['content']['application/json']
export type SearchResults = components['schemas']['SearchResponse']
export type AlertPage = paths['/api/v1/alerts']['get']['responses'][200]['content']['application/json']
export type IncidentPage = paths['/api/v1/incidents']['get']['responses'][200]['content']['application/json']
export type AlertQuery = NonNullable<paths['/api/v1/alerts']['get']['parameters']['query']>
export type IncidentQuery = NonNullable<paths['/api/v1/incidents']['get']['parameters']['query']>
export type IncidentPatch = paths['/api/v1/incidents/{incident_id}']['patch']['requestBody']['content']['application/json']
export type InvestigationQuery = NonNullable<paths['/api/v1/investigations']['get']['parameters']['query']>
export type DashboardActivityQuery = NonNullable<paths['/api/v1/dashboard/activity']['get']['parameters']['query']>
export type IOCQuery = NonNullable<paths['/api/v1/iocs']['get']['parameters']['query']>
export type AuditQuery = NonNullable<paths['/api/v1/audit']['get']['parameters']['query']>
export type AttackMappingQuery = NonNullable<paths['/api/v1/attack/mappings']['get']['parameters']['query']>
export type IncidentInvestigationHistory = paths['/api/v1/incidents/{incident_id}/investigations']['get']['responses'][200]['content']['application/json']
export type SystemStatus = {
  status: string
  environment: string
  application_version: string
  schema_version: number | null
  database: string
  ai_provider: string
  ai_provider_status: string
}
export type AssistantChatResponse = { answer: string; provider: string; model: string | null; warning?: string | null }

const SESSION_KEY = 'soc-auth-token'
const LOCAL_KEY = 'soc-auth-token-remembered'
const API_URL_KEY = 'soc-api-base-url'

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message)
    this.name = 'ApiError'
  }
}

export function getToken(): string | null {
  try { return window.sessionStorage.getItem(SESSION_KEY) || window.localStorage.getItem(LOCAL_KEY) } catch { return null }
}

export function storeToken(token: string, remember: boolean): void {
  clearToken()
  if (!token) return
  try {
    if (remember) window.localStorage.setItem(LOCAL_KEY, token)
    else window.sessionStorage.setItem(SESSION_KEY, token)
  } catch {
    throw new Error('Browser storage is unavailable. Allow storage to keep this session signed in.')
  }
}

export function clearToken(): void {
  try { window.sessionStorage.removeItem(SESSION_KEY); window.localStorage.removeItem(LOCAL_KEY) } catch { /* Storage may be disabled. */ }
}

export function getApiBaseUrl(): string {
  try { return (window.localStorage.getItem(API_URL_KEY) || import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '') }
  catch { return (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '') }
}

export function setApiBaseUrl(value: string): void {
  const trimmed = value.trim().replace(/\/+$/, '')
  if (!trimmed) throw new Error('Enter an API base URL.')
  const parsed = new URL(trimmed, window.location.origin)
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('API URL must use HTTP or HTTPS.')
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('API URL cannot contain credentials, query parameters, or fragments.')
  window.localStorage.setItem(API_URL_KEY, trimmed)
  window.dispatchEvent(new Event('soc:api-config-change'))
}

export function isAuthEnabled(): boolean { return import.meta.env.VITE_API_AUTH_ENABLED === 'true' }

export function safeErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return 'You do not have permission to view this information.'
    if (error.status === 401) return 'Your session expired. Sign in again.'
    if (error.status === 404) return 'This record could not be found.'
    if (error.status === 409) return 'This incident changed elsewhere. Reload the latest version before editing.'
    if (error.status === 422) return 'The request could not be validated. Review the provided fields and try again.'
    if (error.status === 0) return 'Unable to connect to SOC API.'
    if (error.status >= 500) return 'The SOC API could not complete the request.'
    return error.message || 'The SOC API could not complete the request.'
  }
  return 'Unable to connect to SOC API.'
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const base = getApiBaseUrl()
  const url = new URL(`${base}${path.startsWith('/') ? path : `/${path}`}`, window.location.origin)
  const token = getToken()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)
  let response: Response
  try { response = await fetch(url, { ...init, headers, credentials: 'same-origin' }) }
  catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    throw new ApiError('Unable to connect to SOC API.', 0)
  }
  if (response.status === 401) {
    clearToken()
    window.dispatchEvent(new Event('soc:unauthorized'))
  }
  if (!response.ok) {
    let message = 'The SOC API could not complete the request.'
    let code: string | undefined
    try {
      const body = (await response.json()) as { error?: { code?: string; message?: string } }
      code = body.error?.code
      if (response.status !== 403 && response.status !== 401 && body.error?.message) {
        message = body.error.message.replaceAll(token || '\u0000', '[redacted]').replace(/[\u0000-\u001f\u007f]/g, '')
      }
    } catch { /* Never display raw response bodies or tracebacks. */ }
    throw new ApiError(message, response.status, code)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function withQuery<T extends object>(query: T): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export const api = {
  health: (signal?: AbortSignal) => request<components['schemas']['HealthResponse']>('/health', { signal }),
  ready: (signal?: AbortSignal) => request<components['schemas']['ReadyResponse']>('/ready', { signal }),
  systemStatus: (signal?: AbortSignal) => request<SystemStatus>('/system/status', { signal }),
  assistantChat: (question: string, context: Record<string, string | number | boolean | null> = {}, signal?: AbortSignal) =>
    request<AssistantChatResponse>('/assistant/chat', { method: 'POST', body: JSON.stringify({ question, context }), signal }),
  alerts: (query: AlertQuery, signal?: AbortSignal) => request<AlertPage>(`/alerts${withQuery(query)}`, { signal }),
  alert: (id: string, signal?: AbortSignal) => request<Alert>(`/alerts/${encodeURIComponent(id)}`, { signal }),
  event: (id: string, signal?: AbortSignal) => request<Event>(`/events/${encodeURIComponent(id)}`, { signal }),
  incidents: (query: IncidentQuery, signal?: AbortSignal) => request<IncidentPage>(`/incidents${withQuery(query)}`, { signal }),
  incident: (id: string, signal?: AbortSignal) => request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, { signal }),
  patchIncident: (id: string, body: IncidentPatch, signal?: AbortSignal) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body), signal }),
  dashboardSummary: (signal?: AbortSignal) => request<DashboardSummary>('/dashboard/summary', { signal }),
  dashboardTrends: (days: number, signal?: AbortSignal) => request<DashboardTrends>(`/dashboard/trends${withQuery({ days })}`, { signal }),
  dashboardActivity: (query: DashboardActivityQuery, signal?: AbortSignal) => request<DashboardActivity>(`/dashboard/activity${withQuery(query)}`, { signal }),
  search: (query: string, limit = 10, signal?: AbortSignal) => request<SearchResults>(`/search${withQuery({ q: query, limit })}`, { signal }),
  iocs: (query: IOCQuery, signal?: AbortSignal) => request<IOCPage>(`/iocs${withQuery(query)}`, { signal }),
  ioc: (id: string, signal?: AbortSignal) => request<IOCDetail>(`/iocs/${encodeURIComponent(id)}`, { signal }),
  investigations: (query: InvestigationQuery, signal?: AbortSignal) => request<InvestigationPage>(`/investigations${withQuery(query)}`, { signal }),
  investigation: (id: string, signal?: AbortSignal) => request<Investigation>(`/investigations/${encodeURIComponent(id)}`, { signal }),
  incidentInvestigations: (id: string, signal?: AbortSignal) => request<IncidentInvestigationHistory>(`/incidents/${encodeURIComponent(id)}/investigations`, { signal }),
  investigate: (id: string, force = false, signal?: AbortSignal) => request<Investigation>(`/incidents/${encodeURIComponent(id)}/investigate`, { method: 'POST', body: JSON.stringify({ force }), signal }),
  audit: (query: AuditQuery, signal?: AbortSignal) => request<AuditPage>(`/audit${withQuery(query)}`, { signal }),
  attackMappings: (query: AttackMappingQuery, signal?: AbortSignal) => request<AttackMappingPage>(`/attack/mappings${withQuery(query)}`, { signal }),
}
