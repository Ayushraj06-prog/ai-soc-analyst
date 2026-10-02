import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { clearToken, getToken, storeToken } from '../api/client'

type AuthContextValue = { authenticated: boolean; signIn: (token: string, remember: boolean) => void; signOut: () => void }
const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authenticated, setAuthenticated] = useState(() => Boolean(getToken()))
  useEffect(() => {
    const unauthorized = () => setAuthenticated(false)
    window.addEventListener('soc:unauthorized', unauthorized)
    return () => window.removeEventListener('soc:unauthorized', unauthorized)
  }, [])
  const value = useMemo<AuthContextValue>(() => ({
    authenticated,
    signIn(token, remember) { storeToken(token, remember); setAuthenticated(true) },
    signOut() { clearToken(); setAuthenticated(false) },
  }), [authenticated])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used within AuthProvider')
  return value
}
