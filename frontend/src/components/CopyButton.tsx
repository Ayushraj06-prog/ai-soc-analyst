export function CopyButton({ value }: { value: string }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value) } catch { /* Keep the inert value selectable if clipboard access is unavailable. */ }
  }
  return <button className="icon-button copy-button" type="button" aria-label="Copy value" onClick={() => void copy()}>Copy</button>
}
