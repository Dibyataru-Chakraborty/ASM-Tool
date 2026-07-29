'use client'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useState, useEffect, use } from 'react'
import Link from 'next/link'
import asm from '@/lib/api'

const SEV_CLS: Record<string,string> = {critical:'tag-crit',high:'tag-high',medium:'tag-med',low:'tag-low',info:'tag-info'}
const RISK_CLS: Record<string,string> = {
  Critical:'text-red-400',High:'text-orange-400',Medium:'text-yellow-400',
  Low:'text-blue-400',Informational:'text-gray-400'
}

function ReportDetailPageInner({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const [report, setReport] = useState<any>(null)
  const [tab, setTab]       = useState<'summary'|'attack'|'vulns'|'markdown'>('summary')
  const [vulns, setVulns]   = useState<any[]>([])

  useEffect(() => {
    asm.getReport(id).then(r => {
      setReport(r)
      if (r.scan_job_id) {
        asm.getVulns({ scan_job_id: r.scan_job_id, limit: 200 }).then(v => setVulns(v.vulnerabilities || []))
      }
    }).catch(() => {})
  }, [id])

  if (!report) return <div className="flex items-center justify-center h-64"><div className="animate-spin text-4xl">📄</div></div>

  const riskCls = RISK_CLS[report.risk_rating] || 'text-gray-400'

  return (
    <div className="max-w-4xl space-y-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <Link href="/reports" className="hover:text-gray-300">← Reports</Link>
        <span>/</span>
        <span className="text-gray-400">{report.id.slice(0, 8)}</span>
      </div>

      {/* Header card */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              <span className={`text-2xl font-bold ${riskCls}`}>{report.risk_score?.toFixed(1)}/10</span>
              <span className={`text-sm font-semibold ${riskCls}`}>{report.risk_rating} Risk</span>
              <span className="text-xs text-gray-500">
                Generated {report.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}
              </span>
            </div>

            {/* Severity stats */}
            <div className="grid grid-cols-5 gap-3 mb-4">
              {[
                {l:'Critical',v:report.critical_count,c:'text-red-400 bg-red-500/10 border-red-500/20'},
                {l:'High',    v:report.high_count,    c:'text-orange-400 bg-orange-500/10 border-orange-500/20'},
                {l:'Medium',  v:report.medium_count,  c:'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'},
                {l:'Low',     v:report.low_count,     c:'text-blue-400 bg-blue-500/10 border-blue-500/20'},
                {l:'Info',    v:report.info_count,    c:'text-gray-400 bg-gray-500/10 border-gray-500/20'},
              ].map(s => (
                <div key={s.l} className={`rounded-xl border p-3 text-center ${s.c}`}>
                  <p className={`text-xl font-bold ${s.c.split(' ')[0]}`}>{s.v}</p>
                  <p className="text-[10px] text-gray-500">{s.l}</p>
                </div>
              ))}
            </div>

            {/* Technologies */}
            {report.technologies?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {report.technologies.map((t: string) => (
                  <span key={t} className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-300 px-2 py-0.5 rounded">{t}</span>
                ))}
              </div>
            )}
          </div>

          {/* Export buttons */}
          <div className="flex flex-col gap-2 shrink-0">
            <a href={asm.exportReport(id, 'markdown')} download className="btn-blue text-xs text-center">⬇ Download .md</a>
            <a href={asm.exportReport(id, 'json')}     download className="btn-gray text-xs text-center">⬇ Download .json</a>
            <Link href={`/scans/${report.scan_job_id}`} className="btn-gray text-xs text-center">🔭 View Scan</Link>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#21262d] pb-2">
        {[
          {id:'summary',  label:'📋 Executive Summary'},
          {id:'attack',   label:'🗺 Attack Surface'},
          {id:'vulns',    label:`🐛 Findings (${report.total_vulns})`},
          {id:'markdown', label:'📄 Full Report'},
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id as any)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${tab === t.id ? 'bg-blue-600 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-[#21262d]'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Summary tab */}
      {tab === 'summary' && (
        <div className="space-y-4">
          {report.executive_summary && (
            <div className="card p-5">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Executive Summary</p>
              <p className="text-sm text-gray-300 leading-relaxed">{report.executive_summary}</p>
            </div>
          )}
          {report.technical_summary && (
            <div className="card p-5">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Technical Summary</p>
              <p className="text-sm text-gray-300 leading-relaxed">{report.technical_summary}</p>
            </div>
          )}
          {report.recommendations && (
            <div className="card p-5 bg-green-500/5 border-green-500/20">
              <p className="text-xs font-semibold text-green-400 uppercase tracking-wide mb-3">🛠 Recommendations</p>
              <div className="text-sm text-gray-300 leading-relaxed whitespace-pre-line">{report.recommendations}</div>
            </div>
          )}
        </div>
      )}

      {/* Attack surface tab */}
      {tab === 'attack' && (
        <div className="space-y-4">
          {report.attack_surface && (
            <div className="card p-5">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Attack Surface Metrics</p>
              <div className="grid grid-cols-3 gap-4">
                {Object.entries(report.attack_surface).map(([k, v]: any) => (
                  <div key={k} className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3">
                    <p className="text-lg font-bold text-gray-100">{Array.isArray(v) ? v.length : v}</p>
                    <p className="text-xs text-gray-500 capitalize mt-0.5">{k.replace(/_/g, ' ')}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.subdomains_found?.length > 0 && (
            <div className="card p-5">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
                Subdomains Discovered ({report.subdomains_found.length})
              </p>
              <div className="grid grid-cols-2 gap-1 max-h-64 overflow-y-auto">
                {report.subdomains_found.map((s: string) => (
                  <p key={s} className="text-xs font-mono text-gray-300 bg-[#0d1117] border border-[#21262d] px-2 py-1 rounded">{s}</p>
                ))}
              </div>
            </div>
          )}

          {report.open_ports?.length > 0 && (
            <div className="card p-5">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Open Ports</p>
              <div className="flex flex-wrap gap-1.5">
                {report.open_ports.flat().slice(0, 50).map((p: number) => (
                  <span key={p} className="text-xs font-mono bg-[#0d1117] border border-[#30363d] text-gray-300 px-2 py-0.5 rounded">{p}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Findings tab */}
      {tab === 'vulns' && (
        <div className="card overflow-hidden">
          {vulns.length === 0 ? (
            <div className="py-10 text-center text-gray-600 text-sm">No vulnerabilities in this report</div>
          ) : (
            <table className="w-full text-xs">
              <thead><tr className="border-b border-[#21262d]">
                {['Title','Severity','CVSS','CVE','Host','Tool'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {vulns.map((v: any) => (
                  <tr key={v.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                    <td className="px-4 py-2.5 max-w-xs">
                      <Link href={`/vulnerabilities/${v.id}`} className="text-gray-200 hover:text-blue-400 truncate block">{v.title}</Link>
                    </td>
                    <td className="px-4 py-2.5"><span className={SEV_CLS[v.severity] || 'tag-info'}>{v.severity}</span></td>
                    <td className="px-4 py-2.5">
                      <span className={`font-bold ${(v.cvss_score||0)>=9?'text-red-400':(v.cvss_score||0)>=7?'text-orange-400':(v.cvss_score||0)>=4?'text-yellow-400':'text-blue-400'}`}>
                        {v.cvss_score?.toFixed(1) || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-blue-400 text-[10px]">{v.cve_id || '—'}</td>
                    <td className="px-4 py-2.5 font-mono text-gray-400 truncate max-w-[120px]">{v.host || '—'}</td>
                    <td className="px-4 py-2.5 text-gray-500">{v.source_tool || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Full markdown tab */}
      {tab === 'markdown' && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#21262d]">
            <span className="text-xs text-gray-500">Full AI-Generated Report</span>
            <a href={asm.exportReport(id, 'markdown')} download className="text-xs text-blue-400 hover:text-blue-300">⬇ Download</a>
          </div>
          <pre className="p-4 text-xs text-gray-300 leading-relaxed whitespace-pre-wrap overflow-auto max-h-[70vh] font-mono">
            {report.markdown_report || 'Report not yet generated'}
          </pre>
        </div>
      )}
    </div>
  )
}

export default function ReportDetailPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <AuthProvider>
      <AppLayout>
        <ReportDetailPageInner params={params} />
      </AppLayout>
    </AuthProvider>
  )
}
