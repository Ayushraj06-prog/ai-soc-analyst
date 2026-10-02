import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { api, getApiBaseUrl, isAuthEnabled, safeErrorMessage } from '../api/client'
import { isNonLoopbackHttp } from '../utils/security'
import { useAuth } from './AuthContext'

export function LoginPage() {
  const { authenticated, signIn, signOut } = useAuth()
  const [token, setToken] = useState('')
  const [remember, setRemember] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const apiBase = getApiBaseUrl()
  const params = new URLSearchParams(location.search)
  const requested = params.get('next')
  const destination = requested?.startsWith('/') && !requested.startsWith('//') ? requested : '/'
  const tokenRequired = isAuthEnabled()

  if (authenticated) return <Navigate to={destination} replace />

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (tokenRequired && !token) throw new Error('Enter the API bearer token.')
      signIn(token, remember)
      setToken('')
      await api.health()
      navigate(destination, { replace: true })
    } catch (reason) {
      signOut()
      setError(safeErrorMessage(reason))
    } finally { setBusy(false) }
  }

  return <main className="login-page">
    <section className="login-card" aria-labelledby="login-title">
      <div className="brand-mark login-mark" aria-hidden="true">S</div>
      <p className="eyebrow">SECURE ACCESS</p>
      <h1 id="login-title">Sign in to Sentinel Desk</h1>
      <p className="subtle-copy">Connect to the SOC API to review persisted alerts and incidents.</p>
      {isNonLoopbackHttp(apiBase) && <div className="security-warning" role="alert">This API uses plain HTTP over a non-loopback connection. Your bearer token could be observed in transit. Use HTTPS for remote access.</div>}
      {params.get('reason') === 'session-expired' && <div className="inline-error" role="alert">Your session expired. Sign in again.</div>}
      {error && <div className="inline-error" role="alert">{error}</div>}
      <form onSubmit={(event) => void submit(event)}>
        {tokenRequired && <label className="field-label" htmlFor="api-token">API bearer token
          <input id="api-token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} required />
        </label>}
        {tokenRequired && <label className="remember-control"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /><span>Remember on this device</span></label>}
        {remember && <p className="storage-warning">This stores the token in localStorage and keeps it after closing the browser. Use this only on a trusted device.</p>}
        <button className="button button-primary full-width" type="submit" disabled={busy}>{busy ? 'Connecting…' : 'Connect to SOC API'}</button>
      </form>
      {!tokenRequired && <p className="local-mode-hint">The API is configured for local/lab access without authentication.</p>}
      <p className="api-address"><span>API</span> {apiBase}</p>
    </section>
  </main>
}
