import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { LoginPage } from './auth/LoginPage'
import { SocLayout } from './layouts/SocLayout'
import { DashboardPage } from './pages/DashboardPage'
import { AlertsPage } from './pages/AlertsPage'
import { AlertDetailPage } from './pages/AlertDetailPage'
import { IncidentsPage } from './pages/IncidentsPage'
import { IncidentDetailPage } from './pages/IncidentDetailPage'
import { SettingsPage } from './pages/SettingsPage'
import { IOCDetailPage, IOCExplorerPage } from './pages/IOCExplorerPage'
import { InvestigationsPage, InvestigationDetailPage } from './pages/InvestigationPages'
import { AttackPage } from './pages/AttackPage'
import { AuditPage } from './pages/AuditPage'
import { SearchPage } from './pages/SearchPage'
import { EventDetailPage } from './pages/EventDetailPage'
import { isAuthEnabled } from './api/client'

function ProtectedRoute() {
  const { authenticated } = useAuth()
  const location = useLocation()
  if (!isAuthEnabled() || authenticated) return <Outlet />
  const next = encodeURIComponent(`${location.pathname}${location.search}`)
  return <Navigate to={`/login?next=${next}&reason=session-expired`} replace />
}

export function App() {
  return <AuthProvider><Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route element={<ProtectedRoute />}><Route element={<SocLayout />}>
      <Route index element={<DashboardPage />} />
      <Route path="alerts" element={<AlertsPage />} />
      <Route path="alerts/:alertId" element={<AlertDetailPage />} />
      <Route path="incidents" element={<IncidentsPage />} />
      <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
      <Route path="iocs" element={<IOCExplorerPage />} />
      <Route path="iocs/:iocId" element={<IOCDetailPage />} />
      <Route path="events/:eventId" element={<EventDetailPage />} />
      <Route path="investigations" element={<InvestigationsPage />} />
      <Route path="investigations/:investigationId" element={<InvestigationDetailPage />} />
      <Route path="attack" element={<AttackPage />} />
      <Route path="audit" element={<AuditPage />} />
      <Route path="search" element={<SearchPage />} />
      <Route path="settings" element={<SettingsPage />} />
    </Route></Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes></AuthProvider>
}
