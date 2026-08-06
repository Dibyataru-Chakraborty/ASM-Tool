'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { Network, RefreshCw } from 'lucide-react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider, useAuth } from '@/lib/auth'
import asm from '@/lib/api'

const TYPE_ORDER=['domain','subdomain','ip','service','certificate','candidate_domain']
const TYPE_LABEL:Record<string,string>={domain:'Domains',subdomain:'Hosts',ip:'IPs',service:'Services',certificate:'Certificates',candidate_domain:'Investigation'}
const STATUS_CLASS:Record<string,string>={confirmed:'text-emerald-400',high_confidence:'text-cyan-400',requires_investigation:'text-amber-400',rejected:'text-gray-600'}
type Point={x:number;y:number}

function AssetMapContent(){
  const {user}=useAuth(); const organizationId=user?.organization_id||''
  const [graph,setGraph]=useState<any>({nodes:[],edges:[]}); const [loading,setLoading]=useState(false)
  const load=()=>{if(!organizationId){setGraph({nodes:[],edges:[]});return}setLoading(true);asm.getAttackSurfaceGraph(organizationId).then((d:any)=>setGraph(d||{nodes:[],edges:[]})).finally(()=>setLoading(false))}
  useEffect(()=>{load()},[organizationId])
  const layout=useMemo(()=>{const groups:Record<string,any[]>={};TYPE_ORDER.forEach(t=>groups[t]=[]);(graph.nodes||[]).forEach((n:any)=>(groups[n.asset_type]||(groups[n.asset_type]=[])).push(n));const points:Record<string,Point>={};const xs:Record<string,number>={domain:30,subdomain:245,ip:460,service:675,certificate:890,candidate_domain:1105};let maxRows=1;TYPE_ORDER.forEach(type=>{maxRows=Math.max(maxRows,(groups[type]||[]).length);(groups[type]||[]).forEach((n:any,i:number)=>{points[n.id]={x:xs[type]??30,y:65+i*92}})});return{groups,points,height:Math.max(360,120+maxRows*92),width:1310}},[graph])
  return <AppLayout><div className="space-y-4">
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"><div><h1 className="text-lg font-bold text-gray-100">Asset Relationship Map</h1><p className="mt-1 text-xs text-gray-500">{user?.organization_name||'Your organization'} · domains, hosts, IPs, services, certificates and investigation candidates.</p></div><button className="btn-gray flex items-center gap-1 text-xs" onClick={load} disabled={!organizationId||loading}><RefreshCw className={`h-4 w-4 ${loading?'animate-spin':''}`}/>Refresh</button></div>
    <div className="card overflow-hidden"><div className="flex items-center justify-between border-b border-[#21262d] px-4 py-3"><div className="flex items-center gap-2"><Network className="h-4 w-4 text-blue-400"/><span className="text-xs font-semibold text-gray-300">{graph.nodes?.length||0} assets · {graph.edges?.length||0} active relationships</span></div><span className="text-[10px] text-gray-600">Tenant-scoped graph</span></div>
      {!organizationId?<div className="py-20 text-center text-xs text-gray-600">No organization context is active.</div>:loading?<div className="py-20 text-center text-xs text-gray-600">Building relationship map…</div>:(graph.nodes||[]).length===0?<div className="py-20 text-center text-xs text-gray-600">No persistent inventory yet. Run Discovery first.</div>:<div className="overflow-auto bg-[#080b10] p-4"><div className="relative" style={{width:layout.width,height:layout.height}}><svg className="absolute inset-0 h-full w-full" viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden="true">{(graph.edges||[]).map((e:any)=>{const a=layout.points[e.source],b=layout.points[e.target];if(!a||!b)return null;return <g key={e.id}><line x1={a.x+175} y1={a.y+29} x2={b.x} y2={b.y+29} stroke="currentColor" className="text-gray-800" strokeWidth="1.5"/><circle cx={b.x} cy={b.y+29} r="2.5" fill="currentColor" className="text-gray-600"/></g>})}</svg>
        {TYPE_ORDER.map(type=><div key={type} className="absolute top-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-600" style={{left:layout.points[(layout.groups[type]?.[0]||{}).id]?.x??({domain:30,subdomain:245,ip:460,service:675,certificate:890,candidate_domain:1105} as any)[type]}}>{TYPE_LABEL[type]}</div>)}
        {(graph.nodes||[]).map((node:any)=>{const p=layout.points[node.id];if(!p)return null;return <Link href={`/attack-surface/${node.id}`} key={node.id} className="absolute block w-[175px] rounded-md border border-[#30363d] bg-[#0d1117] px-3 py-2 shadow-sm hover:border-blue-500/50 hover:bg-[#111820]" style={{left:p.x,top:p.y}}><div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-[11px] font-medium text-gray-300" title={node.display_name||node.value}>{node.display_name||node.value}</span><span className={`text-[10px] font-bold ${(node.risk_score||0)>=85?'text-red-400':(node.risk_score||0)>=70?'text-orange-400':'text-gray-600'}`}>{node.risk_score||0}</span></div><div className="mt-1 flex items-center justify-between"><span className="text-[9px] uppercase text-gray-600">{node.asset_type.replace(/_/g,' ')}</span><span className={`text-[9px] ${STATUS_CLASS[node.ownership_status]||'text-gray-600'}`}>{node.ownership_status==='requires_investigation'?'review':node.status}</span></div></Link>})}
      </div></div>}
    </div>
  </div></AppLayout>
}
export default function AssetMapPage(){return <AuthProvider><AssetMapContent/></AuthProvider>}
