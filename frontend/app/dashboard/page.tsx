'use client'
import { useState, useEffect } from 'react'
import Link from 'next/link'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const SEV_CLS: Record<string,string> = {
  critical:'text-red-400',high:'text-orange-400',medium:'text-yellow-400',low:'text-blue-400',info:'text-gray-400'
}
const STATUS_CLS: Record<string,string> = {
  running:'text-blue-400',queued:'text-yellow-400',completed:'text-green-400',failed:'text-red-400',cancelled:'text-gray-500'
}
const TOOL_ICONS: Record<string,string> = {
  subfinder:'🌐',dnsx:'🔍',httpx:'🌍',naabu:'🚪',nmap:'🗺️',
  katana:'🕷️',dirsearch:'📁',nuclei:'⚡',xsstrike:'💉',gowitness:'📸',report:'📄'
}

export default function Dashboard() {
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  const load = () => asm.getDashboard().then(setData).catch(()=>{}).finally(()=>setLoading(false))

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t) }, [])

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin text-4xl">⚡</div></div>

  const scans = data?.scans || {}
  const vulns = data?.vulnerabilities || {}
  const running = data?.running_scans || []

  return (
    <AuthProvider><AppLayout>
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-base font-bold text-gray-100">Dashboard</h1>
        <div className="flex gap-2">
          <Link href="/assets" className="btn-blue text-xs">+ Add Asset</Link>
        </div>
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          {l:'Assets',v:data?.assets||0,e:'🖥️',href:'/assets'},
          {l:'Total Scans',v:scans.total||0,e:'🔭',href:'/scans'},
          {l:'Vulnerabilities',v:vulns.total||0,e:'🐛',href:'/vulnerabilities'},
          {l:'Running',v:(scans.running||0)+(scans.queued||0),e:'⚡',href:'/scans'},
        ].map(s=>(
          <Link key={s.l} href={s.href} className="card p-4 hover:border-blue-500/40 transition block">
            <div className="text-2xl mb-1">{s.e}</div>
            <div className="text-2xl font-bold text-gray-100">{s.v}</div>
            <div className="text-xs text-gray-500">{s.l}</div>
          </Link>
        ))}
      </div>

      {/* Severity breakdown */}
      <div className="card p-4">
        <p className="text-xs font-semibold text-gray-400 mb-3">Vulnerability Breakdown</p>
        <div className="grid grid-cols-4 gap-3">
          {['critical','high','medium','low'].map(s=>(
            <div key={s} className="text-center">
              <p className={`text-xl font-bold ${SEV_CLS[s]}`}>{vulns[s]||0}</p>
              <p className="text-xs text-gray-600 capitalize">{s}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Scan queue */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#21262d]">
          <p className="text-xs font-semibold text-gray-300">Scan Queue</p>
          <Link href="/scans" className="text-xs text-blue-400">View all →</Link>
        </div>
        {running.length === 0 ? (
          <div className="py-10 text-center text-sm text-gray-600">
            No active scans · <Link href="/assets" className="text-blue-400">Start one</Link>
          </div>
        ) : (
          <div className="divide-y divide-[#21262d]">
            {running.map((job: any) => (
              <div key={job.id} className="px-4 py-3 flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-mono text-gray-200 truncate">{job.asset_target}</span>
                    <span className={`text-xs ${STATUS_CLS[job.status]}`}>● {job.status}</span>
                  </div>
                  {job.current_tool && (
                    <div className="flex items-center gap-1.5 text-xs text-gray-500">
                      <span>{TOOL_ICONS[job.current_tool]||'🔧'}</span>
                      <span>Running: {job.current_tool}</span>
                    </div>
                  )}
                  {/* Progress bar */}
                  <div className="mt-2 h-1 bg-[#21262d] rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 transition-all duration-500 rounded-full" style={{width:`${job.progress||0}%`}} />
                  </div>
                  <p className="text-[10px] text-gray-600 mt-0.5">{job.progress||0}% complete</p>
                </div>
                <Link href={`/scans/${job.id}`} className="text-xs text-blue-400 hover:text-blue-300 shrink-0">View →</Link>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scan stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          {l:'Queued',v:scans.queued||0,c:'text-yellow-400'},
          {l:'Running',v:scans.running||0,c:'text-blue-400'},
          {l:'Completed',v:scans.completed||0,c:'text-green-400'},
          {l:'Failed',v:scans.failed||0,c:'text-red-400'},
        ].map(s=>(
          <div key={s.l} className="card p-3 text-center">
            <p className={`text-xl font-bold ${s.c}`}>{s.v}</p>
            <p className="text-xs text-gray-600">{s.l}</p>
          </div>
        ))}
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          {l:'Manage Assets',href:'/assets',e:'🖥️'},
          {l:'Scan Scheduler',href:'/scheduler',e:'🕐'},
          {l:'View Reports',href:'/reports',e:'📄'},
          {l:'AI Pentest',href:'/shannon',e:'🤖'},
        ].map(c=>(
          <Link key={c.l} href={c.href} className="card p-3 flex items-center gap-2 hover:border-blue-500/40 transition">
            <span className="text-xl">{c.e}</span>
            <span className="text-sm text-gray-300">{c.l}</span>
          </Link>
        ))}
      </div>
    </div>
    </AppLayout></AuthProvider>
  )
}
