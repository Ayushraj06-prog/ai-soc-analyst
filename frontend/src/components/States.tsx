import { safeErrorMessage } from '../api/client'

export function LoadingState({ label = 'Loading SOC data…' }: { label?: string }) {
  return <div className="state-panel" role="status" aria-live="polite"><span className="loading-dot" aria-hidden="true" />{label}</div>
}
export function EmptyState({ children }: { children: string }) {
  return <div className="state-panel empty-state" role="status">{children}</div>
}
export function ErrorState({ error, retry }: { error: unknown; retry: () => void }) {
  return <div className="state-panel error-state" role="alert"><span>{safeErrorMessage(error)}</span><button className="button button-secondary" type="button" onClick={retry}>Retry</button></div>
}
