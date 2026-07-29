'use client'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useState, useEffect, useRef, use } from 'react'
import Link from 'next/link'
import asm from '@/lib/api'

const TOOL_ICONS: Record<string,string> = {
  subfinder:'🌐',dnsx:'🔍',httpx:'🌍',naabu:'🚪',nmap:'🗺️',
  katana:'🕷️',dirsearch:'📁',nuclei:'⚡',xsstrike:'💉',gowitness:'📸'
}
const STATUS_STYLE: Record<string,{icon:string;cls:string}> = {
  completed:  {icon:'✅',cls:'text-green-400'},
  running:    {icon:'🔄',cls:'text-blue-400 animate-pulse'},
  failed:     {icon:'❌',cls:'text-red-400'},
  skipped:    {icon:'⏭',cls:'text-gray-500'},
  pending:    {icon:'⏳',cls:'text-gray-600'},
}
const SEV_CLS: Record<string,string> = {
  critical:'tag-crit',high:'tag-high',medium:'tag-med',low:'tag-low',info:'tag-info'
}

function ScanDetailPageInner({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const [job, setJob]       = useState<any>(null)
  const [tools, setTools]   = useState<any[]>([])
  const [logs, setLogs]     = useState<any[]>([])
  const [vulns, setVulns]   = useState<any[]>([])
  const [tab, setTab]       = useState<'progress'|'logs'|'vulns'|'raw'>('progress')
  const [activeTool, setActiveTool] = useState<string|null>(null)
  const lastLogId = useRef<string|null>(null)
  const logsRef = useRef<HTMLDivElement>(null)

  const loadJob = async () => {
    const [j, t] = await Promise.all([asm.getScan(id), asm.getScanTools(id)])
    setJob(j)
    setTools(t.tools || [])
  }

  const loadLogs = async () => {
    const r = await asm.getScanLogs(id, lastLogId.current || undefined)
    if (r.logs?.length) {
      setLogs(prev => [...prev, ...r.logs])
      lastLogId.current = r.logs[r.logs.length - 1].id
      setTimeout(() => logsRef.current?.scrollTo(0, logsRef.current.scrollHeight), 50)
    }
  }

  const loadVulns = async () => {
    const r = await asm.getVulns({ scan_job_id: id, limit: 100 })
    setVulns(r.vulnerabilities || [])
  }

  useEffect(() => {
    loadJob(); loadLogs(); loadVulns()
    const t = setInterval(() => {
      loadJob(); loadLogs()
      if (tab === 'vulns') loadVulns()
    }, 3000)
    return () => clearInterval(t)
  }, [id, tab])

  if (!job) return <div className="flex items-center justify-center h-64"><div className="animate-spin text-4xl">🔭</div></div>

  const isActive = ['running','queued'].includes(job.status)
  const sevCounts = { critical:0, high:0, medium:0, low:0 }
  vulns.forEach(v => { sevCounts[v.severity as keyof typeof sevCounts] = (sevCounts[v.severity as keyof typeof sevCounts]||0)+1 })

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link href="/scans" className="text-gray-600 hover:text-gray-300 text-sm">← Scans</Link>
        <span className="text-gray-700">/</span>
        <h1 className="text-base font-bold text-gray-100">{job.asset_target}</h1>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${
          job.status==='running'?'text-blue-400 bg-blue-500/10 border-blue-500/20 animate-pulse':
          job.status==='completed'?'text-green-400 bg-green-500/10 border-green-500/20':
          job.status==='failed'?'text-red-400 bg-red-500/10 border-red-500/20':
          'text-gray-400 bg-gray-500/10 border-gray-500/20'
        }`}>
          {job.status}
        </span>
      </div>

      {/* Overview cards */}
      <div className="grid grid-cols-4 gap-3">
        <div className="card p-3">
          <p className="text-xs text-gray-500 mb-0.5">Progress</p>
          <div className="flex items-end gap-2">
            <p className="text-xl font-bold text-gray-100">{job.progress||0}%</p>
            {isActive && <div className="w-2 h-2 rounded-full bg-blue-400 animate-ping mb-1" />}
          </div>
          <div className="mt-1 h-1 bg-[#21262d] rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 transition-all duration-700" style={{width:`${job.progress||0}%`}} />
          </div>
        </div>
        <div className="card p-3">
          <p className="text-xs text-gray-500 mb-0.5">Current Tool</p>
          <p className="text-sm font-bold text-gray-100">
            {job.current_tool ? `${TOOL_ICONS[job.current_tool]||'🔧'} ${job.current_tool}` : '—'}
          </p>
        </div>
        <div className="card p-3">
          <p className="text-xs text-gray-500 mb-0.5">Vulnerabilities</p>
          <div className="flex gap-2">
            {Object.entries(sevCounts).map(([s,c])=>c>0 && (
              <span key={s} className={`text-xs font-bold ${SEV_CLS[s]}`}>{c} {s[0].toUpperCase()}</span>
            ))}
            {vulns.length===0 && <p className="text-gray-600 text-xs">None yet</p>}
          </div>
        </div>
        <div className="card p-3">
          <p className="text-xs text-gray-500 mb-0.5">Duration</p>
          <p className="text-sm font-bold text-gray-100">
            {job.duration_seconds ? `${Math.floor(job.duration_seconds/60)}m ${job.duration_seconds%60}s` : isActive ? 'Running…' : '—'}
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#21262d] pb-2">
        {[
          {id:'progress',label:'🔧 Tools'},
          {id:'logs',    label:`📋 Live Logs (${logs.length})`},
          {id:'vulns',   label:`🐛 Findings (${vulns.length})`},
          {id:'raw',     label:'📄 Raw Output'},
        ].map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id as any)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${tab===t.id?'bg-blue-600 text-white':'text-gray-500 hover:text-gray-300 hover:bg-[#21262d]'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tools tab */}
      {tab==='progress' && (
        <div className="space-y-2">
          {tools.length===0 ? (
            <div className="card p-6 text-center text-gray-600 text-sm">Tools starting…</div>
          ) : tools.map((t:any)=>{
            const st = STATUS_STYLE[t.status] || STATUS_STYLE.pending
            const isSelected = activeTool === t.id
            return (
              <div key={t.id} className="card overflow-hidden">
                <button onClick={()=>setActiveTool(isSelected?null:t.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[#1c2128] transition text-left">
                  <span className="text-lg shrink-0">{TOOL_ICONS[t.tool_name]||'🔧'}</span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono font-semibold text-gray-200">{t.tool_name}</span>
                      <span className={`text-xs ${st.cls}`}>{st.icon} {t.status}</span>
                      {t.result_count > 0 && (
                        <span className="text-xs text-gray-500 bg-[#0d1117] border border-[#30363d] px-1.5 py-0.5 rounded">{t.result_count} results</span>
                      )}
                    </div>
                    {t.status === 'running' && (
                      <div className="mt-1 h-0.5 bg-[#21262d] rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500 animate-pulse w-1/2" />
                      </div>
                    )}
                  </div>
                  <div className="text-right text-xs text-gray-600 shrink-0">
                    {t.duration_seconds ? `${t.duration_seconds}s` : ''}
                  </div>
                  <span className="text-gray-600 text-xs ml-1">{isSelected?'▲':'▼'}</span>
                </button>
                {isSelected && (
                  <div className="border-t border-[#21262d] px-4 py-3 space-y-2 bg-[#0d1117]">
                    {t.command && (
                      <div>
                        <p className="text-[10px] text-gray-500 mb-0.5">Command</p>
                        <code className="text-xs text-gray-400 font-mono">{t.command}</code>
                      </div>
                    )}
                    {t.error_message && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-2">
                        <p className="text-xs text-red-400">{t.error_message}</p>
                      </div>
                    )}
                    {t.raw_output_preview && (
                      <div>
                        <p className="text-[10px] text-gray-500 mb-0.5">Output preview</p>
                        <pre className="text-[10px] text-gray-400 font-mono whitespace-pre-wrap overflow-auto max-h-40 bg-[#161b22] border border-[#21262d] rounded p-2">{t.raw_output_preview}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Logs tab */}
      {tab==='logs' && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#21262d]">
            <span className="text-xs text-gray-500">Live execution logs</span>
            {isActive && <span className="text-xs text-blue-400 animate-pulse">● Live</span>}
          </div>
          <div ref={logsRef} className="h-96 overflow-y-auto p-3 space-y-0.5 font-mono text-xs">
            {logs.length === 0 ? (
              <p className="text-gray-600 p-2">No logs yet…</p>
            ) : logs.map((l:any)=>(
              <div key={l.id} className={`flex gap-2 ${l.level==='error'?'text-red-400':l.level==='warn'?'text-yellow-400':'text-gray-400'}`}>
                <span className="text-gray-600 shrink-0">{new Date(l.logged_at).toLocaleTimeString()}</span>
                {l.tool && <span className="text-blue-400 shrink-0">[{l.tool}]</span>}
                <span>{l.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulns tab */}
      {tab==='vulns' && (
        <div className="card overflow-hidden">
          {vulns.length===0 ? (
            <div className="py-10 text-center text-gray-600 text-sm">No findings yet — scan in progress</div>
          ) : (
            <table className="w-full text-xs">
              <thead><tr className="border-b border-[#21262d]">
                {['Title','Severity','CVSS','Host/URL','Tool','CVE'].map(h=>(
                  <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {vulns.map((v:any)=>(
                  <tr key={v.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                    <td className="px-4 py-2.5 max-w-xs">
                      <Link href={`/vulnerabilities/${v.id}`} className="text-gray-200 hover:text-blue-400 truncate block">{v.title}</Link>
                    </td>
                    <td className="px-4 py-2.5"><span className={SEV_CLS[v.severity]||'tag-info'}>{v.severity}</span></td>
                    <td className="px-4 py-2.5">
                      <span className={`font-bold ${(v.cvss_score||0)>=9?'text-red-400':(v.cvss_score||0)>=7?'text-orange-400':(v.cvss_score||0)>=4?'text-yellow-400':'text-blue-400'}`}>
                        {v.cvss_score?.toFixed(1)||'—'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-gray-400 truncate max-w-xs">{v.host||v.url||'—'}</td>
                    <td className="px-4 py-2.5 text-gray-500">{v.source_tool||'—'}</td>
                    <td className="px-4 py-2.5 text-blue-400 font-mono">{v.cve_id||'—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Raw output tab */}
      {tab==='raw' && (
        <div className="card overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#21262d]">
            <div className="flex gap-2 overflow-x-auto">
              {tools.filter(t=>t.raw_output_preview).map((t:any)=>(
                <button key={t.id} onClick={()=>setActiveTool(activeTool===t.id?null:t.id)}
                  className={`shrink-0 px-3 py-1 rounded-lg text-xs transition ${activeTool===t.id?'bg-blue-600 text-white':'btn-gray'}`}>
                  {TOOL_ICONS[t.tool_name]||'🔧'} {t.tool_name}
                </button>
              ))}
            </div>
          </div>
          {activeTool ? (
            <pre className="p-4 text-xs text-gray-400 font-mono whitespace-pre-wrap overflow-auto max-h-[500px] leading-relaxed">
              {tools.find(t=>t.id===activeTool)?.raw_output_preview || 'No output'}
            </pre>
          ) : (
            <p className="p-4 text-xs text-gray-600">Select a tool above to view its output</p>
          )}
        </div>
      )}
    </div>
  )
}

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <AuthProvider>
      <AppLayout>
        <ScanDetailPageInner params={params} />
      </AppLayout>
    </AuthProvider>
  )
}
