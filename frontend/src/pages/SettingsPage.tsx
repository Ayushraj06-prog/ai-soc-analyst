import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, getApiBaseUrl, getToken, safeErrorMessage, setApiBaseUrl } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { ErrorState, LoadingState } from '../components/States'
import { useApiResource } from '../hooks/useApiResource'
import { isNonLoopbackHttp } from '../utils/security'

function getTimeMode(): 'UTC' | 'LOCAL' {
  try { return window.localStorage.getItem('soc-time-mode') === 'LOCAL' ? 'LOCAL' : 'UTC' } catch { return 'UTC' }
}

export function SettingsPage() {
  const [address,setAddress]=useState(getApiBaseUrl())
  const [saved,setSaved]=useState(false)
  const [message,setMessage]=useState('')
  const [timeMode,setTimeMode]=useState<'UTC'|'LOCAL'>(getTimeMode)
  const { signOut }=useAuth()
  const navigate=useNavigate()
  const load=useCallback((signal:AbortSignal)=>api.ready(signal),[])
  const {data,error,loading,retry}=useApiResource(load)
  const investigationLoad=useCallback((signal:AbortSignal)=>api.investigations({limit:1,offset:0},signal),[])
  const investigationStatus=useApiResource(investigationLoad)
  const tokenStored=Boolean(getToken())
  useEffect(()=>{
    const handler=()=>setAddress(getApiBaseUrl())
    window.addEventListener('soc:api-config-change',handler)
    return()=>window.removeEventListener('soc:api-config-change',handler)
  },[])
  const save=(event:FormEvent<HTMLFormElement>)=>{
    event.preventDefault();setMessage('');setSaved(false)
    try{setApiBaseUrl(address);setSaved(true);setMessage('API URL saved for this browser.')}
    catch(reason){setMessage(safeErrorMessage(reason))}
  }
  const toggleTime=()=>{
    const next=timeMode==='UTC'?'LOCAL':'UTC';setTimeMode(next)
    try{window.localStorage.setItem('soc-time-mode',next)}catch{/* Keep the current view usable when storage is blocked. */}
    window.dispatchEvent(new Event('soc:time-mode-change'))
  }
  return <div className="page-stack">
    <div className="page-heading"><div><p className="eyebrow">PREFERENCES</p><h1>Settings</h1><p className="subtle-copy">Configure this browser’s connection and display preferences.</p></div></div>
    <section className="panel settings-card"><p className="eyebrow">API CONNECTION</p><h2>Backend URL</h2><form onSubmit={save} className="settings-form">
      <label className="field-label">API base URL<input type="text" inputMode="url" value={address} onChange={(e)=>setAddress(e.target.value)} required placeholder="/api/v1 or https://soc.example/api/v1" /></label>
      <button className="button button-primary" type="submit">Save API URL</button>
    </form>{saved&&<p role="status" className="success-message">{message}</p>}{message&&!saved&&<p role="alert" className="inline-error">{message}</p>}
      {isNonLoopbackHttp(address)&&<div className="security-warning" role="alert">This is a non-loopback HTTP endpoint. Bearer tokens are not encrypted in transit; configure HTTPS before remote use.</div>}
    </section>
    <section className="panel settings-card"><p className="eyebrow">AUTHENTICATION</p><h2>Token storage</h2><p className="body-copy">{tokenStored?'A bearer token is stored in this browser. The token value is never shown here.':'No bearer token is stored.'}</p>
      <button className="button button-secondary" type="button" disabled={!tokenStored} onClick={()=>{signOut();navigate('/login',{replace:true})}}>Clear stored token</button>
      <p className="subtle-copy">Session storage clears when the browser session ends. Remembered tokens use localStorage and persist after closing the browser.</p>
    </section>
    <section className="panel settings-card"><p className="eyebrow">DISPLAY</p><h2>Time zone</h2><p className="body-copy">Times display in {timeMode==='UTC'?'UTC':'your local time'}.</p><button className="button button-secondary" type="button" onClick={toggleTime}>Switch to {timeMode==='UTC'?'local time':'UTC'}</button></section>
    <section className="panel settings-card"><p className="eyebrow">PHASE 6 INVESTIGATION</p><h2>AI investigation configuration</h2>{investigationStatus.loading?<LoadingState label="Checking investigation history…"/>:investigationStatus.error?<ErrorState error={investigationStatus.error} retry={investigationStatus.retry}/>:investigationStatus.data?.items?.[0]?<p className="body-copy">Last recorded provider/model: {investigationStatus.data.items[0].provider||'not reported'} / {investigationStatus.data.items[0].model||'not reported'}. The API investigation workflow is available; provider reachability is determined by each run.</p>:<p className="body-copy">The API investigation workflow is available. No prior run has reported a provider/model yet. No provider credentials or secrets are displayed.</p>}</section>
    <section className="panel settings-card"><p className="eyebrow">VERSIONS</p><h2>Build information</h2><dl className="version-list"><div><dt>Frontend build</dt><dd>{import.meta.env.VITE_APP_VERSION||'0.1.0'}</dd></div><div><dt>Backend schema</dt><dd>{loading?<LoadingState label="Checking…"/>:error?<ErrorState error={error} retry={retry}/>:data?.schema_version??'Not available'}</dd></div></dl></section>
  </div>
}
