import { useSearchParams } from 'react-router-dom'

export const PAGE_SIZE = 50

export function Pager({ total, limit = PAGE_SIZE }: { total: number; limit?: number }) {
  const [search, setSearch] = useSearchParams()
  const page = Math.max(1, Number(search.get('page') || 1))
  const pages = Math.max(1, Math.ceil(total / limit))
  const go = (next: number) => {
    const params = new URLSearchParams(search)
    if (next === 1) params.delete('page')
    else params.set('page', String(next))
    setSearch(params)
  }
  return <nav className="pager" aria-label="Pagination">
    <span>Page {page} of {pages} · {total.toLocaleString()} records</span>
    <div><button className="button button-secondary" type="button" onClick={() => go(page - 1)} disabled={page <= 1}>Previous</button>
      <button className="button button-secondary" type="button" onClick={() => go(page + 1)} disabled={page >= pages}>Next</button></div>
  </nav>
}
