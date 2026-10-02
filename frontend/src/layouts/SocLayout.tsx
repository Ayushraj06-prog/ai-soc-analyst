import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'
import { useApiResource } from '../hooks/useApiResource'
import { useAuth } from '../auth/AuthContext'

const primaryLinks = [
  { label: 'Dashboard', to: '/', icon: '◈' },
  { label: 'Alerts', to: '/alerts', icon: '⌁' },
  { label: 'Incidents', to: '/incidents', icon: '▣' },
  { label: 'IOCs', to: '/iocs', icon: '⌖' },
  { label: 'Investigations', to: '/investigations', icon: '◉' },
  { label: 'ATT&CK', to: '/attack', icon: '⌘' },
  { label: 'Audit history', to: '/audit', icon: '≡' },
]

function ApiConnection() {
  const load = useCallback((signal: AbortSignal) => api.health(signal), [])
  const { data, error, loading } = useApiResource(load)
  return <span className={`connection ${error ? 'connection-down' : data ? 'connection-up' : 'connection-wait'}`} role="status">
    <span className="connection-dot" aria-hidden="true" />{loading ? 'Checking API' : error ? 'API unavailable' : 'API connected'}
  </span>
}

function pageTitle(path: string): string {
  if (path.startsWith('/alerts/')) return 'Alert detail'
  if (path.startsWith('/alerts')) return 'Alert queue'
  if (path.startsWith('/incidents/')) return 'Incident detail'
  if (path.startsWith('/incidents')) return 'Incidents'
  if (path.startsWith('/iocs')) return 'IOC explorer'
  if (path.startsWith('/investigations')) return 'Investigations'
  if (path.startsWith('/attack')) return 'MITRE ATT&CK'
  if (path.startsWith('/audit')) return 'Audit history'
  if (path.startsWith('/search')) return 'SOC search'
  if (path.startsWith('/settings')) return 'Settings'
  return 'SOC overview'
}

function savedTimeMode(): 'UTC' | 'LOCAL' {
  try { return window.localStorage.getItem('soc-time-mode') === 'LOCAL' ? 'LOCAL' : 'UTC' } catch { return 'UTC' }
}

export function SocLayout() {
  const location = useLocation()
  const navigate = useNavigate()
  const { signOut } = useAuth()
  const [timeMode, setTimeMode] = useState(savedTimeMode)

  useEffect(() => { document.getElementById('main-content')?.focus() }, [location.pathname, location.search])
  useEffect(() => {
    const configChanged = () => window.dispatchEvent(new Event('soc:refresh'))
    window.addEventListener('soc:api-config-change', configChanged)
    return () => window.removeEventListener('soc:api-config-change', configChanged)
  }, [])

  const refresh = () => window.dispatchEvent(new Event('soc:refresh'))
  const toggleTime = () => {
    const next = timeMode === 'UTC' ? 'LOCAL' : 'UTC'
    try { window.localStorage.setItem('soc-time-mode', next) } catch { /* Keep the current view usable if storage is disabled. */ }
    setTimeMode(next)
    window.dispatchEvent(new Event('soc:time-mode-change'))
  }

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar" aria-label="Primary navigation">
      <NavLink to="/" className="brand-link" aria-label="AI SOC Analyst home">
        <span className="brand-mark" aria-hidden="true">S</span><span><strong>Sentinel Desk</strong><small>AI SOC ANALYST</small></span>
      </NavLink>
      <div className="nav-label">WORKSPACE</div>
      <nav>{primaryLinks.map((item) => <NavLink key={item.to} to={item.to} end={item.to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'nav-active' : ''}`}>
        <span className="nav-icon" aria-hidden="true">{item.icon}</span>{item.label}
      </NavLink>)}</nav>
      <div className="nav-label deferred-label">PLATFORM</div>
      <ul className="deferred-nav" aria-label="Planned modules"><li aria-disabled="true"><span aria-hidden="true">○</span><span>Events</span><small>Incident evidence</small></li></ul>
      <div className="sidebar-bottom">
        <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'nav-active' : ''}`}><span className="nav-icon" aria-hidden="true">⚙</span>Settings</NavLink>
        <button type="button" className="nav-item signout-button" onClick={signOut}><span className="nav-icon" aria-hidden="true">⇥</span>Sign out</button>
        <div className="phase-stamp">PHASE 8B + 8C · ANALYST WORKSPACE</div>
      </div>
    </aside>
    <div className="main-column">
      <header className="topbar">
        <div className="crumb"><span>OPERATIONS</span><span aria-hidden="true">/</span><strong>{pageTitle(location.pathname)}</strong></div>
        <div className="topbar-tools">
          <form className="global-search" role="search" onSubmit={(event)=>{event.preventDefault();const form=new FormData(event.currentTarget);const q=String(form.get('q')||'').trim();if(q.length>=2){const params=new URLSearchParams({q});navigate(`/search?${params.toString()}`)}}}>
            <label className="sr-only" htmlFor="global-search-input">Search incidents, alerts, IOCs</label><input id="global-search-input" name="q" type="search" minLength={2} maxLength={120} placeholder="Search SOC data…" defaultValue={location.pathname==='/search'?new URLSearchParams(location.search).get('q')||'':''}/><button type="submit" aria-label="Search SOC data">Search</button>
          </form>
          <ApiConnection />
          <button type="button" className="icon-button" onClick={refresh} aria-label="Refresh current view"><span aria-hidden="true">↻</span> Refresh</button>
          <button type="button" className="icon-button time-toggle" onClick={toggleTime} aria-label={`Display time in ${timeMode === 'UTC' ? 'local time' : 'UTC'}`}>{timeMode === 'UTC' ? 'UTC' : 'Local'} <span aria-hidden="true">⌄</span></button>
          <span className="avatar" aria-label="Analyst">A</span>
        </div>
      </header>
      <main id="main-content" className="main-content" tabIndex={-1} data-time-mode={timeMode}><Outlet /></main>
    </div>
  </div>
}

export function useTimeMode(): 'UTC' | 'LOCAL' {
  const [mode, setMode] = useState(savedTimeMode)
  useEffect(() => {
    const update = () => setMode(savedTimeMode())
    window.addEventListener('soc:time-mode-change', update)
    return () => window.removeEventListener('soc:time-mode-change', update)
  }, [])
  return mode
}
