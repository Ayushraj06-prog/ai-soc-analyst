import { Link } from 'react-router-dom'
import { CopyButton } from './CopyButton'
import { LongText } from './LongText'
import { sanitizeSecurityText } from '../utils/security'

export function classifyIP(value: string): 'Internal' | 'External' | 'Observed' {
  const ip=value.trim().toLowerCase()
  if(ip==='::1'||ip==='localhost'||ip.startsWith('fc')||ip.startsWith('fd')||ip.startsWith('fe80:'))return 'Internal'
  if(ip.includes(':'))return /^2[0-9a-f]{3}:/.test(ip)&&!ip.startsWith('2001:db8:')?'External':'Observed'
  const parts=ip.split('.').map(Number)
  if(parts.length!==4||parts.some((x)=>!Number.isInteger(x)||x<0||x>255))return 'Observed'
  const [a,b]=parts
  if(a===10||a===127||a===0||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168)return 'Internal'
  if(a===100&&b>=64&&b<=127||a===192&&b===0&&parts[2]===2||a===192&&b===88&&parts[2]===99||a===198&&(b===18||b===19||b===51&&parts[2]===100)||a===203&&b===0&&parts[2]===113||a>=224)return 'Observed'
  return a>0&&a<224?'External':'Observed'
}
export function IOCValue({iocId,value,type,showLink=true}:{iocId?:string;value:string;type?:string;showLink?:boolean}) {
  return <span className="ioc-value"><span className="ioc-type">{sanitizeSecurityText(type||'Unknown',40)}</span><span className="ioc-inert"><LongText value={value} limit={160}/></span><span className="confidence-chip">{type?.toLowerCase()==='ip'?classifyIP(value):'Observed'}</span><CopyButton value={value}/>{showLink&&iocId&&<Link to={`/iocs/${encodeURIComponent(iocId)}`} className="table-link">View IOC</Link>}</span>
}
