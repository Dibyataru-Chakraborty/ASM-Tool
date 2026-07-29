'use client'
import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const SEVS = ['','critical','high','medium','low','info']
const SEV_CLS: Record<string,string> = {critical:'tag-crit',high:'tag-high',medium:'tag-med',low:'tag-low',info:'tag-info'}

export default function VulnsPage() {
  const [vulns, setVulns]   = useState<any[]>([])
  const [total, setTotal]   = useState(0)
  const [sev, setSev]       = useState('')
  const [tool, setTool]     = useState('')
  const [skip, setSkip]     = useState(0)
  const [loading, setLoading] = useState(true)
  const LIMIT = 20

  const load = useCallback(async () => {
    setLoading(true)
    const p: any = { skip, limit: LIMIT }
    if (sev)  p.severity    = sev
    if (tool) p.source_tool = tool
    const r = await asm.getVulns(p)
    setVulns(r.vulnerabilities || [])
    setTotal(r.total || 0)
    setLoading(false)
  }, [sev, tool, skip])

  useEffect(() => { load() }, [load])

  const markFP = async (id: string) => { await asm.markFP(id); load() }

  const counts: Record<string,number> = {critical:0,high:0,medium:0,low:0,info:0}
  vulns.forEach(v=>{ counts[v.severity]=(counts[v.severity]||0)+1 })

  return (
    <AuthProvider><AppLayout>
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Vulnerabilities</h1>
          <p className="text-xs text-gray-500">{total} total findings from real scans</p>
        </div>
      </div>

      {/* Severity stats */}
      <div className="grid grid-cols-5 gap-2">
        {['critical','high','medium','low','info'].map(s=>(
          <button key={s} onClick={()=>{setSev(sev===s?'':s);setSkip(0)}}
            className={`card p-3 text-center transition hover:border-blue-500/30 ${sev===s?'border-blue-500/50':''}`}>
            <p className={`text-xl font-bold ${SEV_CLS[s]?.split(' ')[0]||'text-gray-400'}`}>{counts[s]||0}</p>
            <p className="text-[10px] text-gray-600 capitalize">{s}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <select className="input py-1.5 text-xs w-36" value={sev} onChange={e=>{setSev(e.target.value);setSkip(0)}}>
          {SEVS.map(s=><option key={s} value={s}>{s||'All Severity'}</option>)}
        </select>
        <select className="input py-1.5 text-xs w-36" value={tool} onChange={e=>{setTool(e.target.value);setSkip(0)}}>
          {['','nuclei','xsstrike'].map(t=><option key={t} value={t}>{t||'All Tools'}</option>)}
        </select>
        <button onClick={()=>{setSev('');setTool('');setSkip(0)}} className="btn-gray text-xs">Clear</button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="py-12 text-center animate-pulse text-gray-600 text-sm">Loading…</div>
        ) : vulns.length===0 ? (
          <div className="py-12 text-center">
            <p className="text-2xl mb-2">🐛</p>
            <p className="text-sm text-gray-500">No vulnerabilities found</p>
            <p className="text-xs text-gray-600 mt-1">Run a scan to discover real vulnerabilities</p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead><tr className="border-b border-[#21262d]">
              {['Title','Severity','CVSS','CVE','Host','Tool','Date','Actions'].map(h=>(
                <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {vulns.map((v:any)=>(
                <tr key={v.id} className={`border-b border-[#21262d] hover:bg-[#1c2128] transition ${v.is_false_positive?'opacity-40':''}`}>
                  <td className="px-4 py-2.5 max-w-xs">
                    <Link href={`/vulnerabilities/${v.id}`} className="text-gray-200 hover:text-blue-400 block truncate">{v.title}</Link>
                    {v.is_false_positive && <span className="text-[10px] text-gray-600">False positive</span>}
                  </td>
                  <td className="px-4 py-2.5"><span className={SEV_CLS[v.severity]||'tag-info'}>{v.severity}</span></td>
                  <td className="px-4 py-2.5">
                    <span className={`font-bold text-xs ${(v.cvss_score||0)>=9?'text-red-400':(v.cvss_score||0)>=7?'text-orange-400':(v.cvss_score||0)>=4?'text-yellow-400':'text-blue-400'}`}>
                      {v.cvss_score?.toFixed(1)||'—'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-blue-400 text-[10px]">{v.cve_id||'—'}</td>
                  <td className="px-4 py-2.5 font-mono text-gray-400 truncate max-w-[120px]">{v.host||'—'}</td>
                  <td className="px-4 py-2.5 text-gray-500">{v.source_tool||'—'}</td>
                  <td className="px-4 py-2.5 text-gray-500">{v.created_at ? new Date(v.created_at).toLocaleDateString():''}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-2">
                      <Link href={`/vulnerabilities/${v.id}`} className="text-xs text-blue-400 hover:text-blue-300">Detail</Link>
                      <span className="text-gray-700">|</span>
                      <button onClick={()=>markFP(v.id)} className="text-xs text-gray-500 hover:text-gray-300">
                        {v.is_false_positive?'Restore':'FP'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {total > LIMIT && (
          <div className="px-4 py-3 border-t border-[#21262d] flex items-center justify-between">
            <span className="text-xs text-gray-500">Showing {skip+1}–{Math.min(skip+LIMIT,total)} of {total}</span>
            <div className="flex gap-1">
              <button disabled={skip===0} onClick={()=>setSkip(Math.max(0,skip-LIMIT))} className="btn-gray text-xs disabled:opacity-40">← Prev</button>
              <button disabled={skip+LIMIT>=total} onClick={()=>setSkip(skip+LIMIT)} className="btn-gray text-xs disabled:opacity-40">Next →</button>
            </div>
          </div>
        )}
      </div>
    </div>
    </AppLayout></AuthProvider>
  )
}
