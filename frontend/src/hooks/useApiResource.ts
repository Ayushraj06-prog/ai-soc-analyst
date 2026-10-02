import { useCallback, useEffect, useState } from 'react'

type ResourceState<T> = { data: T | null; error: unknown; loading: boolean; retry: () => void }

export function useApiResource<T>(load: (signal: AbortSignal) => Promise<T>): ResourceState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    let current = true
    setData(null)
    setLoading(true)
    setError(null)
    load(controller.signal).then(
      (value) => { if (current) setData(value) },
      (reason: unknown) => { if (current && !(reason instanceof Error && reason.name === 'AbortError')) setError(reason) },
    ).finally(() => { if (current) setLoading(false) })
    return () => { current = false; controller.abort() }
  }, [load, attempt])
  useEffect(() => {
    const refresh = () => setAttempt((value) => value + 1)
    window.addEventListener('soc:refresh', refresh)
    return () => window.removeEventListener('soc:refresh', refresh)
  }, [])
  return { data, error, loading, retry: useCallback(() => setAttempt((value) => value + 1), []) }
}
