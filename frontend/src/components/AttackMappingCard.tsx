import { Link } from 'react-router-dom'
import { sanitizeSecurityText } from '../utils/security'

export type AttackMapping = Record<string, unknown>
function list(value: unknown): string[] { return Array.isArray(value)?value.filter((item):item is string=>typeof item==='string'):[] }
export function AttackMappingCard({ mapping }: { mapping: AttackMapping }) {
  const evidence=list(mapping.evidence_ids), tactics=list(mapping.tactic_ids), baseline=list(mapping.baseline_techniques)
  const conflict=mapping.baseline_disagreement===true
  return <article className="attack-card"><header><span className="mono technique-id">{sanitizeSecurityText(mapping.technique_id||'Unknown',32)}</span><strong>{sanitizeSecurityText(mapping.technique_name||'Technique name unavailable',200)}</strong><span className="confidence-chip">{typeof mapping.confidence==='number'?`${Math.round(mapping.confidence*100)}% mapping confidence`:sanitizeSecurityText(mapping.confidence||'Confidence unavailable')}</span></header>
    <p><span className="eyebrow">TACTICS</span> {tactics.length?tactics.map((id)=><span className="tactic-chip" key={id}>{sanitizeSecurityText(id,32)}</span>):'Not available'}</p>
    <p><span className="eyebrow">MAPPING SOURCE</span> {sanitizeSecurityText(mapping.mapping_source||'Not available',80)}</p>
    <p><span className="eyebrow">EVIDENCE BASIS</span> {evidence.length?evidence.map((id)=><span className="evidence-chip mono" key={id}>{sanitizeSecurityText(id,100)}</span>):'No evidence reference provided'}</p>
    {conflict&&<div className="security-warning" role="status">Phase 3 baseline mapping differs from this enrichment mapping: {baseline.length?baseline.map((id)=><span key={id} className="evidence-chip mono">{sanitizeSecurityText(id,32)}</span>):'baseline unavailable'}. Both mappings are preserved.</div>}
    {typeof mapping.detection_id==='string'&&<Link className="table-link" to={`/alerts/${encodeURIComponent(mapping.detection_id)}`}>View detection</Link>}
  </article>
}
