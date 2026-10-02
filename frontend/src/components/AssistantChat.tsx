import { FormEvent, useState } from 'react'
import { api } from '../api/client'
import { safeErrorMessage } from '../api/client'

export function AssistantChat() {
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState<string | null>(null)
  const [provider, setProvider] = useState<string | null>(null)
  const [warning, setWarning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    const trimmed = question.trim()
    if (!trimmed || loading) return
    setLoading(true); setError(null); setWarning(null)
    try {
      const result = await api.assistantChat(trimmed, { page: 'dashboard' })
      setAnswer(result.answer); setProvider(result.provider); setWarning(result.warning || null)
    } catch (cause) {
      setError(safeErrorMessage(cause))
    } finally {
      setLoading(false)
    }
  }

  return <section className="panel detail-card assistant-chat" aria-label="SOC assistant">
    <div className="table-heading"><div><p className="eyebrow">LOCAL SOC ASSISTANT</p><h2>Ask about this workspace</h2></div><span className="read-only-chip">OLLAMA / SAFE FALLBACK</span></div>
    <p className="subtle-copy">Ask about alerts, incidents, IOCs, investigations, ATT&CK mappings, or simulated response.</p>
    <form className="assistant-form" onSubmit={submit}>
      <label className="sr-only" htmlFor="assistant-question">Question for SOC assistant</label>
      <textarea id="assistant-question" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={2000} rows={3} placeholder="Example: What should I review first in this incident?" />
      <button className="button button-primary" type="submit" disabled={loading || !question.trim()}>{loading ? 'Thinking…' : 'Ask assistant'}</button>
    </form>
    {error && <p className="error-copy" role="alert">{error}</p>}
    {answer && <div className="assistant-answer"><div className="assistant-meta">Provider: {provider === 'ollama' ? 'Ollama' : 'safe fallback'}</div><p>{answer}</p>{warning && <small>{warning}</small>}</div>}
  </section>
}
