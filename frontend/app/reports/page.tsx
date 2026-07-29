'use client'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useState, useEffect } from 'react'
import Link from 'next/link'
import asm from '@/lib/api'

const RISK_CLS: Record<string,string> = {
  Critical:'text-red-400 bg-red-500/10 border-red-500/20',
  High:'text-orange-400 bg-orange-500/10 border-orange-500/20',
  Medium:'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  Low:'text-blue-400 bg-blue-500/10 border-blue-500/20',
  Informational:'text-gray-400 bg-gray-500/10 border-gray-500/20',
}

function ReportsPageInner() {
  const [reports, setReports] = useState<any[]>([])
  const [assets,  setAssets]  = useState<any[]>([])
  const [active,  setActive]  = useState<string>('all')
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const [reportResult, assetResult] = await Promise.allSettled([
        asm.getReports(),
        asm.getAssets({ limit: 100 }),
      ])
      if (reportResult.status === 'fulfilled') {
        setReports(reportResult.value.reports || [])
      } else {
        setError(reportResult.reason?.response?.data?.detail || 'Failed to load reports')
      }
      if (assetResult.status === 'fulfilled') {
        setAssets(assetResult.value.items || assetResult.value.assets || [])
      } else {
        setError(current => current || (
          assetResult.reason?.response?.data?.detail || 'Failed to load assets'
        ))
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Group reports by asset
  const assetMap: Record<string, any[]> = { all: reports }
  reports.forEach(r => {
    if (!assetMap[r.asset_id]) assetMap[r.asset_id] = []
    assetMap[r.asset_id].push(r)
  })

  const assetName = (id: string) => assets.find(a => a.id === id)?.target || id.slice(0, 8)

  const displayed = active === 'all' ? reports : (assetMap[active] || [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Reports</h1>
          <p className="text-xs text-gray-500">{reports.length} AI-generated security reports</p>
        </div>
        <button onClick={load} className="btn-gray text-xs">🔄 Refresh</button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Asset tabs */}
      {assets.length > 0 && (
        <div className="flex gap-1 overflow-x-auto pb-1">
          <button onClick={() => setActive('all')}
            className={`shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium transition ${active === 'all' ? 'bg-blue-600 text-white' : 'btn-gray'}`}>
            All ({reports.length})
          </button>
          {Object.entries(assetMap).filter(([k]) => k !== 'all').map(([id, rpts]) => (
            <button key={id} onClick={() => setActive(id)}
              className={`shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium transition ${active === id ? 'bg-blue-600 text-white' : 'btn-gray'}`}>
              {assetName(id)} ({rpts.length})
            </button>
          ))}
        </div>
      )}

      {/* Reports grid */}
      {loading ? (
        <div className="py-16 text-center animate-pulse text-gray-600">Loading reports…</div>
      ) : displayed.length === 0 ? (
        <div className="card py-16 text-center">
          <p className="text-3xl mb-2">📄</p>
          <p className="text-sm text-gray-400 mb-1">No reports yet</p>
          <p className="text-xs text-gray-600">Reports are auto-generated after scans complete</p>
          <Link href="/assets" className="btn-blue text-xs mt-3 inline-block">Start a scan</Link>
        </div>
      ) : (
        <div className="space-y-3">
          {displayed.map((r: any) => (
            <div key={r.id} className="card p-5 hover:border-blue-500/30 transition">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  {/* Header */}
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className={`text-xs font-bold px-2 py-0.5 rounded border ${RISK_CLS[r.risk_rating] || RISK_CLS.Informational}`}>
                      {r.risk_rating || 'Unknown'} Risk
                    </span>
                    <span className="text-xs text-gray-500">Score: {r.risk_score?.toFixed(1) || '0.0'}/10</span>
                    <span className="text-xs text-gray-600">
                      {r.generated_at ? new Date(r.generated_at).toLocaleDateString('en', { day:'numeric', month:'short', year:'numeric' }) : ''}
                    </span>
                  </div>
                  <h2 className="text-sm font-semibold text-gray-100 font-mono mb-2">{assetName(r.asset_id)}</h2>

                  {/* Severity breakdown */}
                  <div className="flex gap-3 text-xs mb-3">
                    {[
                      {l:'Critical',v:r.critical_count,c:'text-red-400'},
                      {l:'High',    v:r.high_count,    c:'text-orange-400'},
                      {l:'Medium',  v:r.medium_count,  c:'text-yellow-400'},
                      {l:'Low',     v:r.low_count,     c:'text-blue-400'},
                    ].map(s => (
                      <div key={s.l} className="flex items-center gap-1">
                        <span className={`font-bold ${s.c}`}>{s.v}</span>
                        <span className="text-gray-600">{s.l}</span>
                      </div>
                    ))}
                    <span className="text-gray-600 ml-1">· {r.total_vulns} total</span>
                  </div>

                  {/* Technologies */}
                  {r.technologies?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {r.technologies.slice(0, 6).map((t: string) => (
                        <span key={t} className="text-[10px] bg-[#0d1117] border border-[#30363d] text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex flex-col gap-2 shrink-0">
                  <Link href={`/reports/${r.id}`} className="btn-blue text-xs text-center">View Report</Link>
                  <a href={asm.exportReport(r.id, 'markdown')} download className="btn-gray text-xs text-center">⬇ .md</a>
                  <a href={asm.exportReport(r.id, 'json')} download className="btn-gray text-xs text-center">⬇ .json</a>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function ReportsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <ReportsPageInner />
      </AppLayout>
    </AuthProvider>
  )
}
