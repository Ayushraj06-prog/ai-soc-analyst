import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCallback } from 'react'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { AlertsPage } from '../pages/AlertsPage'
import { AlertDetailPage } from '../pages/AlertDetailPage'
import { IncidentsPage } from '../pages/IncidentsPage'
import { IncidentDetailPage } from '../pages/IncidentDetailPage'
import { LoginPage } from '../auth/LoginPage'
import { AuthProvider } from '../auth/AuthContext'
import { api, ApiError, safeErrorMessage, storeToken } from '../api/client'
import { LongText } from '../components/LongText'
import { SeverityBadge } from '../components/SeverityBadge'
import { sanitizeSecurityText, utcOrLocalTimestamp } from '../utils/security'
import { useApiResource } from '../hooks/useApiResource'
import { DashboardPage } from '../pages/DashboardPage'
import { IOCExplorerPage, IOCDetailPage } from '../pages/IOCExplorerPage'
import { InvestigationDetailPage } from '../pages/InvestigationPages'
import { SearchPage } from '../pages/SearchPage'
import { AttackPage } from '../pages/AttackPage'
import { IncidentTimeline } from '../components/IncidentTimeline'
import type { ReactNode } from 'react'

const incident = {
  incident_id:'inc-1',title:'Suspicious sign-in',description:'Repeated sign-in failures',status:'open',severity:'HIGH',risk_score:81,
  risk_level:'HIGH',confidence:'medium',primary_host:'srv-1',primary_user:'alice',primary_src_ip:'198.51.100.9',
  created_at:'2026-01-02T12:00:00Z',updated_at:'2026-01-02T12:00:00Z',first_seen:'2026-01-01T10:00:00Z',last_seen:'2026-01-02T12:00:00Z',
  detection_ids:[],events:[],iocs:[],attack_mappings:[],correlation_edges:[],merge_history:[],analyst_notes:'',
}
const alert = { alert_id:'det-1',timestamp:'2026-01-02T12:00:00Z',severity:'HIGH',status:'NEW',rule_id:'R001',title:'Repeated authentication failures',hostname:'srv-1',username:'alice',source_ip:'198.51.100.9',confidence:'high',evidence_refs:['event-1'] }

function response(body: unknown, status=200): Response {
  return { ok:status>=200&&status<300,status,json:async()=>body } as Response
}
function page<T>(items:T[],total=items.length,limit=50,offset=0) { return {items,total,limit,offset} }
function TestRouter({initial,children}:{initial:string;children:ReactNode}) {
  return <MemoryRouter initialEntries={[initial]}><Routes>
    <Route path="/alerts" element={<AlertsPage/>}/><Route path="/alerts/:alertId" element={<AlertDetailPage/>}/>
    <Route path="/incidents" element={<IncidentsPage/>}/><Route path="/incidents/:incidentId" element={<IncidentDetailPage/>}/>
    <Route path="/login" element={children}/>
    <Route path="/" element={<p>Connected</p>}/>
    <Route path="/dashboard-test" element={<DashboardPage/>}/>
    <Route path="/iocs" element={<IOCExplorerPage/>}/><Route path="/iocs/:iocId" element={<IOCDetailPage/>}/>
    <Route path="/investigations/:investigationId" element={<InvestigationDetailPage/>}/>
    <Route path="/search" element={<SearchPage/>}/><Route path="/attack" element={<AttackPage/>}/>
  </Routes><Location/></MemoryRouter>
}
function Location(){const location=useLocation();return <output data-testid="location">{location.pathname}{location.search}</output>}

describe('Phase 8A dashboard',()=>{
  beforeEach(()=>{window.sessionStorage.clear();window.localStorage.clear();vi.stubEnv('VITE_API_AUTH_ENABLED','false');vi.stubGlobal('fetch',vi.fn())})
  afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.unstubAllEnvs();vi.restoreAllMocks()})

  it('stores login credentials in sessionStorage by default and never displays or URLs the token',async()=>{
    vi.stubEnv('VITE_API_AUTH_ENABLED','true')
    vi.mocked(fetch).mockResolvedValue(response({status:'ok',service:'ai-soc-analyst'}))
    const user=userEvent.setup();render(<AuthProvider><TestRouter initial="/login" ><LoginPage/></TestRouter></AuthProvider>)
    const token='never-in-dom-super-secret'
    await user.type(screen.getByLabelText('API bearer token'),token)
    await user.click(screen.getByRole('button',{name:'Connect to SOC API'}))
    await waitFor(()=>expect(window.sessionStorage.getItem('soc-auth-token')).toBe(token))
    expect(window.localStorage.getItem('soc-auth-token-remembered')).toBeNull()
    expect(document.body.textContent).not.toContain(token)
    expect(screen.queryByLabelText('API bearer token')).not.toBeInTheDocument()
    expect(screen.getByTestId('location').textContent).not.toContain(token)
  })

  it('uses localStorage only after explicit remember-on-device choice',async()=>{
    vi.stubEnv('VITE_API_AUTH_ENABLED','true');vi.mocked(fetch).mockResolvedValue(response({status:'ok'}))
    const user=userEvent.setup();render(<AuthProvider><TestRouter initial="/login"><LoginPage/></TestRouter></AuthProvider>)
    await user.type(screen.getByLabelText('API bearer token'),'remember-this')
    await user.click(screen.getByLabelText('Remember on this device'))
    expect(screen.getByText(/keeps it after closing the browser/i)).toBeInTheDocument()
    await user.click(screen.getByRole('button',{name:'Connect to SOC API'}))
    await waitFor(()=>expect(window.localStorage.getItem('soc-auth-token-remembered')).toBe('remember-this'))
    expect(window.sessionStorage.getItem('soc-auth-token')).toBeNull()
  })

  it('sends the token only in Authorization and clears it on 401',async()=>{
    const token='bearer-secret';storeToken(token,false)
    const fetchMock=vi.mocked(fetch);fetchMock.mockResolvedValue(response({error:{code:'unauthorized',message:'Authentication is required.'}},401))
    await expect(api.health()).rejects.toMatchObject({status:401})
    const [url,init]=fetchMock.mock.calls[0]
    expect(String(url)).not.toContain(token)
    expect(new Headers(init?.headers).get('Authorization')).toBe(`Bearer ${token}`)
    expect(window.sessionStorage.getItem('soc-auth-token')).toBeNull()
  })

  it('clears remembered tokens on 401 and treats 403 as a distinct permission error',async()=>{
    window.localStorage.setItem('soc-auth-token-remembered','persisted-secret')
    vi.mocked(fetch).mockResolvedValue(response({error:{code:'unauthorized'}},401))
    await expect(api.health()).rejects.toBeInstanceOf(ApiError)
    expect(window.localStorage.getItem('soc-auth-token-remembered')).toBeNull()
    expect(safeErrorMessage(new ApiError('denied',403))).toMatch(/permission/i)
    expect(safeErrorMessage(new ApiError('expired',401))).toMatch(/expired/i)
  })

  it('renders the alert queue and links the alert ID to its detail view',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(page([alert])))
    render(<TestRouter initial="/alerts" ><></></TestRouter>)
    expect(await screen.findByRole('table',{name:'Alerts'})).toBeInTheDocument()
    expect(screen.getByText('R001')).toBeInTheDocument()
    expect(screen.getByRole('link',{name:'det-1'})).toHaveAttribute('href','/alerts/det-1')
    expect(screen.queryByRole('button',{name:/resolve|suppress|delete|investigate/i})).not.toBeInTheDocument()
  })

  it('applies exact alert filters to URL and API, restoring values from copied URLs',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(page([alert])))
    const user=userEvent.setup();render(<TestRouter initial="/alerts?status=NEW&page=2"><></></TestRouter>)
    await screen.findByRole('table',{name:'Alerts'})
    expect(screen.getByLabelText('Status (exact)')).toHaveValue('NEW')
    await user.clear(screen.getByLabelText('Rule ID (exact)'));await user.type(screen.getByLabelText('Rule ID (exact)'),'R001')
    await user.click(screen.getByRole('button',{name:'Apply filters'}))
    await waitFor(()=>expect(screen.getByTestId('location')).toHaveTextContent('rule_id=R001'))
    const called=vi.mocked(fetch).mock.calls.map(([url])=>String(url))
    expect(called.some((url)=>url.includes('status=NEW')&&url.includes('offset=50'))).toBe(true)
    expect(called.some((url)=>url.includes('rule_id=R001'))).toBe(true)
  })

  it('renders empty alert state and retries an API failure safely',async()=>{
    vi.mocked(fetch).mockResolvedValueOnce(response({error:{code:'internal_error',message:'SQL C:\\private\\db'}},500)).mockResolvedValueOnce(response(page([])))
    const user=userEvent.setup();render(<TestRouter initial="/alerts"><></></TestRouter>)
    expect(await screen.findByRole('alert')).toHaveTextContent('The SOC API could not complete the request.')
    expect(screen.getByRole('alert').textContent).not.toContain('private')
    await user.click(screen.getByRole('button',{name:'Retry'}))
    expect(await screen.findByText('No alerts found.')).toBeInTheDocument()
  })

  it('uses backend page offsets and synchronizes pagination with the URL',async()=>{
    vi.mocked(fetch).mockImplementation(async(input)=>{
      const url=new URL(String(input));const offset=Number(url.searchParams.get('offset')||0)
      return response(page(offset?[{...alert,alert_id:'det-51'}]:[alert],60,50,offset))
    })
    const user=userEvent.setup();render(<TestRouter initial="/alerts"><></></TestRouter>)
    await screen.findByRole('table',{name:'Alerts'});await user.click(screen.getByRole('button',{name:'Next'}))
    expect(await screen.findByText('det-51')).toBeInTheDocument()
    expect(screen.getByTestId('location')).toHaveTextContent('page=2')
    expect(vi.mocked(fetch).mock.calls.map(([url])=>String(url)).some((url)=>url.includes('offset=50'))).toBe(true)
  })

  it('renders incidents and restores URL status/page/sort without downloading all rows',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(page([incident],81,50,50)))
    render(<TestRouter initial="/incidents?status=open&page=2&sort=risk_desc"><></></TestRouter>)
    expect(await screen.findByRole('table',{name:'Incidents'})).toBeInTheDocument()
    expect(screen.getByLabelText('Status (exact)')).toHaveValue('open')
    const called=String(vi.mocked(fetch).mock.calls[0][0])
    expect(called).toContain('offset=50');expect(called).toContain('sort=risk_desc')
  })

  it('applies incident filters and the supported server sort to URL state',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(page([incident])))
    const user=userEvent.setup();render(<TestRouter initial="/incidents"><></></TestRouter>)
    await screen.findByRole('table',{name:'Incidents'})
    await user.type(screen.getByLabelText('Primary host (exact)'),'srv-1')
    await user.selectOptions(screen.getByLabelText('Sort'),'risk_desc')
    await user.click(screen.getByRole('button',{name:'Apply filters'}))
    expect(await screen.findByTestId('location')).toHaveTextContent('primary_host=srv-1')
    expect(screen.getByTestId('location')).toHaveTextContent('sort=risk_desc')
  })

  it('renders the incident detail deep link and analyst fields',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(incident))
    render(<TestRouter initial="/incidents/inc-1"><></></TestRouter>)
    expect(await screen.findByRole('heading',{name:'Suspicious sign-in'})).toBeInTheDocument()
    expect(screen.getByText('Primary host')).toBeInTheDocument()
    expect(screen.getByLabelText('Analyst notes')).toBeInTheDocument()
    expect(screen.getByText(/Incident timeline · chronological evidence/)).toBeInTheDocument()
  })

  it('refetches analyst updates and does not optimistically change fields',async()=>{
    vi.mocked(fetch).mockImplementation(async(_input,init)=>init?.method==='PATCH'?response({...incident,status:'investigating',analyst_notes:'review'}):response(incident))
    const user=userEvent.setup();render(<TestRouter initial="/incidents/inc-1"><></></TestRouter>)
    await screen.findByRole('heading',{name:'Suspicious sign-in'})
    await user.clear(screen.getByLabelText('Analyst notes'));await user.type(screen.getByLabelText('Analyst notes'),'review')
    await user.click(screen.getByRole('button',{name:'Save analyst fields'}))
    await waitFor(()=>expect(vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='PATCH')).toHaveLength(1))
    expect(vi.mocked(fetch).mock.calls.some(([url,init])=>String(url).endsWith('/incidents/inc-1')&&(!init?.method||init.method==='GET'))).toBe(true)
  })

  it('shows 409 conflict dialog, allows Escape, and never retries the PATCH',async()=>{
    vi.mocked(fetch).mockImplementation(async(_input,init)=>init?.method==='PATCH'?response({error:{code:'conflict',message:'conflict'}},409):response(incident))
    const user=userEvent.setup();render(<TestRouter initial="/incidents/inc-1"><></></TestRouter>)
    await screen.findByRole('heading',{name:'Suspicious sign-in'})
    await user.click(screen.getByRole('button',{name:'Save analyst fields'}))
    expect(await screen.findByRole('dialog')).toHaveTextContent('This incident changed elsewhere. Reload the latest version before editing.')
    expect(vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='PATCH')).toHaveLength(1)
    fireEvent.keyDown(window,{key:'Escape'})
    await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('renders API 403 as a permission message',async()=>{
    vi.mocked(fetch).mockResolvedValue(response({error:{code:'forbidden',message:'secret internal path'}},403))
    render(<TestRouter initial="/alerts"><></></TestRouter>)
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission')
    expect(screen.getByRole('alert').textContent).not.toContain('secret')
  })

  it('keeps javascript IOC values inert text rather than links',async()=>{
    vi.mocked(fetch).mockResolvedValue(response({...incident,iocs:[{ioc_id:'ioc-1',value:'javascript:alert(1)',type:'url'}]}))
    render(<TestRouter initial="/incidents/inc-1"><></></TestRouter>)
    const values=await screen.findAllByText('javascript:alert(1)')
    expect(values.every((value)=>value.closest('a')===null)).toBe(true)
  })

  it('renders XSS-shaped alert content as escaped inert text',async()=>{
    vi.mocked(fetch).mockResolvedValue(response({...alert,explanation:'<img src=x onerror=alert(1)>'}))
    render(<TestRouter initial="/alerts/det-1"><></></TestRouter>)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  it('renders unknown severity neutrally with an explicit text label',()=>{
    render(<SeverityBadge value="quantum" />)
    expect(screen.getByLabelText('Severity: Unknown')).toHaveTextContent('Unknown')
  })

  it('strips ANSI, controls, bidi and zero-width characters and truncates long values',async()=>{
    const clean=sanitizeSecurityText('\u001b[31mHIGH\u001b[0m\u0000\u202eabc\u200b')
    expect(clean).toBe('HIGHabc')
    expect(utcOrLocalTimestamp('2026-01-01T00:00:00Z','UTC')).toContain('UTC')
    const text='x'.repeat(9000);render(<LongText value={text} limit={20} label="log" />)
    expect(screen.getByText(/^x{20}…$/)).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button',{name:'Show more log'}))
    expect(screen.getByText('Show less')).toBeInTheDocument()
  })

  it('cancels an older request and prevents its late result from replacing newer data',async()=>{
    let resolveOld:(value:string)=>void=()=>undefined
    function Harness({version}:{version:number}){
      const load=useCallback(()=>version===1?new Promise<string>((resolve)=>{resolveOld=resolve}):Promise.resolve('new result'),[version])
      const state=useApiResource(load)
      return <p>{state.data||'loading'}</p>
    }
    const view=render(<Harness version={1}/>);view.rerender(<Harness version={2}/>)
    expect(await screen.findByText('new result')).toBeInTheDocument()
    resolveOld('stale result')
    await waitFor(()=>expect(screen.getByText('new result')).toBeInTheDocument())
    expect(screen.queryByText('stale result')).not.toBeInTheDocument()
  })

  it('uses semantic labelled table/forms and never submits mutations during initial reads',async()=>{
    vi.mocked(fetch).mockResolvedValue(response(page([alert])))
    render(<TestRouter initial="/alerts"><></></TestRouter>)
    await screen.findByRole('table',{name:'Alerts'})
    expect(screen.getByRole('form',{name:'Alert filters'})).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.every(([,init])=>!init?.method||init.method==='GET')).toBe(true)
  })

  it('renders exact dashboard metrics, aggregate trends and bounded activity from the API',async()=>{
    vi.mocked(fetch).mockImplementation(async(input)=>{
      const url=String(input)
      if(url.includes('/dashboard/summary'))return response({active_incidents:3,critical_incidents:1,high_severity_alerts:6,unresolved_alerts:7,recent_investigations:2,ioc_count:9,detection_count:20})
      if(url.includes('/dashboard/trends'))return response({days:14,severity_distribution:[{severity:'HIGH',count:6}],alert_activity:[{date:'2026-10-01',count:4}],incident_activity:[],top_sources:{source_ip:[],user:[],host:[],rule:[]}})
      return response({items:[{id:'inc-1',timestamp:'2026-10-01T00:00:00Z',kind:'incident',title:'Observed incident'}],total:1,limit:12,offset:0})
    })
    render(<TestRouter initial="/dashboard-test"><></></TestRouter>)
    expect(await screen.findByText('Active incidents')).toBeInTheDocument()
    expect(screen.getByText('20')).toBeInTheDocument()
    expect(await screen.findByText('Observed incident')).toBeInTheDocument()
    expect(document.querySelector('a[href="/incidents"]')).toBeInTheDocument()
  })

  it('renders IOC values as inert hostile text and exposes observed relationships',async()=>{
    const payload='<img src=x onerror=alert(1)>'
    vi.mocked(fetch).mockResolvedValue(response({ioc_id:'ioc-1',value:payload,type:'domain',first_seen:'2026-01-01T00:00:00Z',last_seen:'2026-01-02T00:00:00Z',occurrence_count:2,events:[],detections:[],incidents:[{incident_id:'inc-1',title:'<script>alert(1)</script>',status:'open'}]}))
    render(<TestRouter initial="/iocs/ioc-1"><></></TestRouter>)
    expect(await screen.findByText(payload)).toBeInTheDocument()
    expect(screen.getByText('Observed')).toBeInTheDocument()
    expect(screen.getByRole('link',{name:'<script>alert(1)</script>'})).toHaveAttribute('href','/incidents/inc-1')
    expect(document.querySelector('img')).toBeNull()
  })

  it('shows bounded investigation results as advisory inert text',async()=>{
    vi.mocked(fetch).mockResolvedValue(response({investigation_id:'run-1',incident_id:'inc-1',status:'completed',run_number:2,provider:'local',model:'analyst-model',started_at:'2026-01-02T00:00:00Z',completed_at:'2026-01-02T00:01:00Z',summary:'<script>alert(1)</script>',findings:[{description:'<img src=x onerror=alert(1)>'}],recommendations:[{description:'Review evidence'}],evidence_ids:[{evidence_type:'event',evidence_id:'event-1',relationship:'supports'}]}))
    render(<TestRouter initial="/investigations/run-1"><></></TestRouter>)
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(screen.getByText(/AI-generated interpretation/)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText('Review evidence')).toBeInTheDocument()
  })

  it('runs Phase 6 only after analyst activation and shows an advisory result',async()=>{
    vi.mocked(fetch).mockImplementation(async(input)=>{
      const url=String(input)
      if(url.endsWith('/investigate'))return response({investigation_id:'run-created',incident_id:'inc-1',status:'completed',run_number:1,provider:'local',model:'test-model',summary:'Evidence reviewed',findings:[],recommendations:[],evidence_ids:[]})
      if(url.endsWith('/investigations'))return response({items:[],total:0})
      if(url.includes('/audit?'))return response({items:[],total:0,limit:50,offset:0})
      return response(incident)
    })
    const user=userEvent.setup()
    render(<TestRouter initial="/incidents/inc-1"><></></TestRouter>)
    await user.click(await screen.findByRole('button',{name:'Run AI Investigation'}))
    expect(await screen.findByText('Evidence reviewed')).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.some(([,init])=>init?.method==='POST')).toBe(true)
    expect(screen.getByText(/AI-generated output/)).toBeInTheDocument()
  })

  it('groups global API search results and safely encodes hostile queries',async()=>{
    const query='<svg/onload=alert(1)>'
    vi.mocked(fetch).mockResolvedValue(response({query,incidents:[{incident_id:'inc-1',title:query,status:'open',severity:'HIGH',risk_score:90}],alerts:[],iocs:[{ioc_id:'ioc-1',value:query,type:'url'}]}))
    render(<TestRouter initial="/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E"><></></TestRouter>)
    expect(await screen.findByRole('heading',{name:'Incidents'})).toBeInTheDocument()
    expect(screen.getAllByText(query).length).toBeGreaterThan(0)
    expect(document.querySelector('svg')).toBeNull()
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toContain('%3Csvg%2Fonload%3Dalert%281%29%3E')
  })

  it('renders incident timeline in backend chronological order with event links',()=>{
    render(<MemoryRouter><IncidentTimeline events={[{id:'e-1',timestamp:'2026-01-01T00:00:00Z',event_type:'earlier',raw:'safe'},{id:'e-2',timestamp:'2026-01-01T00:01:00Z',event_type:'later',raw:'safe'}]}/></MemoryRouter>)
    expect(screen.getAllByText(/earlier|later/)[0]).toHaveTextContent('earlier')
    expect(screen.getAllByRole('link',{name:'View evidence'})[0]).toHaveAttribute('href','/events/e-1')
  })

  it('keeps ATT&CK mapping initial loads read-only',async()=>{
    vi.mocked(fetch).mockResolvedValue(response({items:[],total:0,limit:50,offset:0}))
    render(<TestRouter initial="/attack"><></></TestRouter>)
    expect(await screen.findByText('No ATT&CK mappings are available.')).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.every(([,init])=>!init?.method||init.method==='GET')).toBe(true)
  })
})
