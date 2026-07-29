'use client'
import { useState, useEffect } from 'react'
import Link from 'next/link'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const STATUS_CLS: Record<string,string> = {
  running:'text-blue-400',queued:'text-yellow-400',completed:'text-green-400',
  failed:'text-red-400',cancelled:'text-gray-500',paused:'text-orange-400'
}
const STATUS_DOT: Record<string,string> = {
  running:'bg-blue-400 animate-pulse',queued:'bg-yellow-400',completed:'bg-green-400',
  failed:'bg-red-400',cancelled:'bg-gray-600',paused:'bg-orange-400'
}

export default function ScansPage() {
  const [scans, setScans]   = useState<any[]>([])
  const [assets, setAssets] = useState<any[]>([])
  const [filter, setFilter] = useState('')
  const [assetFilter, setAssetFilter] = useState('')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    const p: any = {}
    if (filter) p.status = filter
    if (assetFilter) p.asset_id = assetFilter
    const [s, a] = await Promise.all([asm.getScans(p), asm.getAssets()])
    setScans(s.scans || [])
    setAssets(a.assets || [])
    setLoading(false)
  }

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t) }, [filter, assetFilter])

  const cancel = async (id: string) => { await asm.cancelScan(id); load() }

  return (
    <AuthProvider><AppLayout>
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Scan History</h1>
          <p className="text-xs text-gray-500">{scans.length} scans · Auto-refreshes every 5s</p>
        </div>
        <div className="flex gap-2">
          <select className="input py-1.5 text-xs w-40" value={assetFilter} onChange={e=>setAssetFilter(e.target.value)}>
            <option value="">All Assets</option>
            {assets.map((a:any)=><option key={a.id} value={a.id}>{a.target}</option>)}
          </select>
          <select className="input py-1.5 text-xs w-36" value={filter} onChange={e=>setFilter(e.target.value)}>
            <option value="">All Status</option>
            {['queued','running','completed','failed','cancelled'].map(s=><option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="card overflow-hidden">
        {loading ? (
          <div className="py-12 text-center animate-pulse text-gray-600 text-sm">Loading scans…</div>
        ) : scans.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-2xl mb-2">🔭</p>
            <p className="text-sm text-gray-500">No scans found</p>
            <Link href="/assets" className="btn-blue text-xs mt-3 inline-block">Go to Assets → Trigger Scan</Link>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead><tr className="border-b border-[#21262d]">
              {['Target','Status','Progress','Tool','Triggered','Started','Duration','Actions'].map(h=>(
                <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {scans.map((j:any)=>(
                <tr key={j.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                  <td className="px-4 py-3">
                    <p className="font-mono text-gray-200">{j.asset_target}</p>
                    <p className="text-gray-600 text-[10px]">{j.id.slice(0,8)}</p>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[j.status]||'bg-gray-600'}`} />
                      <span className={STATUS_CLS[j.status]||'text-gray-400'}>{j.status}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 w-32">
                    <div className="h-1.5 bg-[#21262d] rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 transition-all duration-500 rounded-full" style={{width:`${j.progress||0}%`}} />
                    </div>
                    <p className="text-gray-600 mt-0.5">{j.progress||0}%</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-gray-400">{j.current_tool || '—'}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 capitalize">{j.triggered_by}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {j.started_at ? new Date(j.started_at).toLocaleTimeString() : '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {j.duration_seconds ? `${Math.round(j.duration_seconds/60)}m ${j.duration_seconds%60}s` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <Link href={`/scans/${j.id}`} className="text-xs text-blue-400 hover:text-blue-300">View</Link>
                      {['running','queued'].includes(j.status) && (
                        <><span className="text-gray-700">|</span>
                        <button onClick={()=>cancel(j.id)} className="text-xs text-red-400 hover:text-red-300">Cancel</button></>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
    </AppLayout></AuthProvider>
  )
}
