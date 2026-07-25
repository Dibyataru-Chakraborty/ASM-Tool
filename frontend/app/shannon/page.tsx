'use client'

import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const token = () =>
  typeof window !== 'undefined' ? localStorage.getItem('access_token') : ''
const H = () => ({ Authorization: `Bearer ${token()}` })

// ── Types ────────────────────────────────────────────────────────────────────
type Status = 'idle' | 'queued' | 'running' | 'completed' | 'failed'

type Finding = {
  index: number
  title: string
  severity: string
  cvss_score: number
  vuln_class: string
  target_url: string
  parameter: string
  method: string
  payload: string
  evidence: string
  description: string
  poc: string
  curl_command: string
}

type ScanResult = {
  scan_id: string
  status: Status
  phase: string
  message: string
  target_url: string
  report?: {
    findings_count: number
    summary: string
    findings: Finding[]
    markdown: string
    attack_surface: any
    started_at: string
    finished_at: string
  }
}

// ── Severity helpers ─────────────────────────────────────────────────────────
const SEV: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: 'bg-red-500/10 border-red-500/30',    text: 'text-red-400',    dot: 'bg-red-400' },
  high:     { bg: 'bg-orange-500/10 border-orange-500/30', text: 'text-orange-400', dot: 'bg-orange-400' },
  medium:   { bg: 'bg-yellow-500/10 border-yellow-500/30', text: 'text-yellow-400', dot: 'bg-yellow-400' },
  low:      { bg: 'bg-blue-500/10 border-blue-500/30',   text: 'text-blue-400',   dot: 'bg-blue-400' },
}
const sev = (s: string) => SEV[s?.toLowerCase()] || SEV.low

// ── Phase progress tracker ────────────────────────────────────────────────────
const PHASES = [
  { id: 'phase2',  label: 'Crawling',         icon: '🌐' },
  { id: 'phase1',  label: 'Stack Analysis',   icon: '🔎' },
  { id: 'phase2b', label: 'Attack Surface',   icon: '🗺️' },
  { id: 'phase3',  label: 'Vuln Agents ×5',   icon: '🤖' },
  { id: 'phase4',  label: 'Exploitation',     icon: '💥' },
  { id: 'phase5',  label: 'Report',           icon: '📄' },
  { id: 'done',    label: 'Complete',         icon: '✅' },
]

function PhaseTracker({ phase, status }: { phase: string; status: Status }) {
  const current = PHASES.findIndex(p => p.id === phase)
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {PHASES.map((p, i) => {
        const done    = status === 'completed' || i < current
        const active  = i === current && status === 'running'
        return (
          <div key={p.id} className="flex items-center gap-1">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-all ${
              done    ? 'bg-green-500/10 border-green-500/30 text-green-400' :
              active  ? 'bg-blue-500/10 border-blue-500/30 text-blue-300 animate-pulse' :
                        'bg-[#0d1117] border-[#21262d] text-gray-600'
            }`}>
              <span>{p.icon}</span>
              <span>{p.label}</span>
              {active && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />}
              {done   && <span className="text-green-400">✓</span>}
            </div>
            {i < PHASES.length - 1 && (
              <span className={`text-xs ${done ? 'text-green-600' : 'text-gray-700'}`}>›</span>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Single finding card ───────────────────────────────────────────────────────
function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false)
  const s = sev(f.severity)

  return (
    <div className={`border rounded-xl overflow-hidden ${s.bg}`}>
      {/* Header — always visible */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
      >
        <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-bold uppercase ${s.text}`}>{f.severity}</span>
            <span className="text-xs text-gray-500">CVSS {f.cvss_score}</span>
            <span className="text-xs text-gray-600 bg-[#0d1117] border border-[#21262d] px-1.5 py-0.5 rounded">
              {f.vuln_class.toUpperCase()}
            </span>
          </div>
          <p className="text-sm font-medium text-gray-200 mt-0.5 truncate">{f.title}</p>
        </div>
        <span className="text-gray-500 text-xs shrink-0">{open ? '▲' : '▼'}</span>
      </button>

      {/* Expanded details */}
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-white/5 pt-3">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <p className="text-gray-500 mb-0.5">Target</p>
              <p className="font-mono text-blue-400 truncate">{f.target_url}</p>
            </div>
            <div>
              <p className="text-gray-500 mb-0.5">Parameter</p>
              <p className="font-mono text-gray-300">{f.parameter || '—'}</p>
            </div>
          </div>

          {f.description && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Description</p>
              <p className="text-xs text-gray-300 leading-relaxed">{f.description}</p>
            </div>
          )}

          {f.evidence && (
            <div className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">Evidence</p>
              <p className="text-xs text-yellow-300">{f.evidence}</p>
            </div>
          )}

          {f.payload && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Payload</p>
              <code className="block bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-2 text-xs text-green-400 font-mono whitespace-pre-wrap break-all">
                {f.payload}
              </code>
            </div>
          )}

          {f.curl_command && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Reproduce with curl</p>
              <code className="block bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-2 text-xs text-cyan-300 font-mono whitespace-pre-wrap break-all">
                {f.curl_command}
              </code>
            </div>
          )}

          {f.poc && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Steps to Reproduce</p>
              <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-line bg-[#0d1117] border border-[#21262d] rounded-lg p-3">
                {f.poc}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ShannonPage() {
  const [url, setUrl]           = useState('')
  const [scanId, setScanId]     = useState<string | null>(null)
  const [result, setResult]     = useState<ScanResult | null>(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [activeTab, setActiveTab] = useState<'findings' | 'surface' | 'markdown'>('findings')
  const pollRef = useRef<NodeJS.Timeout | null>(null)

  const startScan = async () => {
    if (!url.trim()) { setError('Enter a target URL'); return }
    setError('')
    setResult(null)
    setScanId(null)
    setLoading(true)
    try {
      const r = await axios.post(
        `${API}/api/v1/shannon/scan`,
        { target_url: url },
        { headers: H() }
      )
      setScanId(r.data.scan_id)
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to start scan')
      setLoading(false)
    }
  }

  // Poll for status
  useEffect(() => {
    if (!scanId) return
    const poll = async () => {
      try {
        const r = await axios.get(`${API}/api/v1/shannon/scan/${scanId}`, { headers: H() })
        setResult(r.data)
        if (r.data.status === 'completed' || r.data.status === 'failed') {
          setLoading(false)
          if (pollRef.current) clearInterval(pollRef.current)
        }
      } catch {}
    }
    poll()
    pollRef.current = setInterval(poll, 3000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [scanId])

  const findings   = result?.report?.findings || []
  const critical   = findings.filter(f => f.severity?.toLowerCase() === 'critical').length
  const high       = findings.filter(f => f.severity?.toLowerCase() === 'high').length
  const medium     = findings.filter(f => f.severity?.toLowerCase() === 'medium').length
  const low        = findings.filter(f => f.severity?.toLowerCase() === 'low').length

  return (
    <div className="min-h-screen bg-[#0d1117] text-gray-100">
      <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">

        {/* ── Header ─────────────────────────────────────────────── */}
        <div className="text-center space-y-2">
          <h1 className="text-2xl font-bold text-gray-100">🤖 Shannon AI Pentester</h1>
          <p className="text-sm text-gray-500">
            5-phase AI-driven pentest · No exploit = no report
          </p>
          <div className="flex justify-center gap-4 text-xs text-gray-600 pt-1">
            <span>Pre-Recon</span><span>›</span>
            <span>Recon</span><span>›</span>
            <span>5× Vuln Agents</span><span>›</span>
            <span>Exploitation</span><span>›</span>
            <span>Report</span>
          </div>
        </div>

        {/* ── Scan Input ─────────────────────────────────────────── */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-3">
          <label className="block text-sm font-medium text-gray-300">Target URL</label>
          <div className="flex gap-2">
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !loading && startScan()}
              placeholder="https://example.com"
              className="flex-1 bg-[#0d1117] border border-[#30363d] text-gray-100 placeholder-gray-600 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 transition"
            />
            <button
              onClick={startScan}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-6 py-2.5 rounded-lg text-sm font-semibold transition whitespace-nowrap"
            >
              {loading ? '⏳ Scanning...' : '🚀 Start Scan'}
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <p className="text-xs text-gray-600">
            ⚠️ Only scan targets you own or have explicit written permission to test.
          </p>
        </div>

        {/* ── Live Progress ──────────────────────────────────────── */}
        {result && result.status !== 'completed' && result.status !== 'failed' && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200">Live Progress</h2>
              <span className="text-xs text-blue-400 animate-pulse">● Running</span>
            </div>
            <PhaseTracker phase={result.phase} status={result.status} />
            <div className="flex items-center gap-2 text-xs text-gray-400 bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-2">
              <span className="animate-spin">⏳</span>
              <span>{result.message}</span>
            </div>
          </div>
        )}

        {/* ── Failed ─────────────────────────────────────────────── */}
        {result?.status === 'failed' && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-400 mb-1">Scan Failed</p>
            <p className="text-xs text-gray-400">{result.message}</p>
          </div>
        )}

        {/* ── Results ────────────────────────────────────────────── */}
        {result?.status === 'completed' && result.report && (
          <div className="space-y-5">

            {/* Phase tracker — final state */}
            <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
              <PhaseTracker phase="done" status="completed" />
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: 'Critical', count: critical, color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/20' },
                { label: 'High',     count: high,     color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
                { label: 'Medium',   count: medium,   color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
                { label: 'Low',      count: low,       color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/20' },
              ].map(s => (
                <div key={s.label} className={`rounded-xl border p-4 ${s.bg}`}>
                  <p className={`text-2xl font-bold ${s.color}`}>{s.count}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Summary */}
            {result.report.summary && (
              <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Executive Summary</p>
                <p className="text-sm text-gray-300 leading-relaxed">{result.report.summary}</p>
                <div className="flex gap-4 mt-3 text-xs text-gray-600">
                  <span>Started: {new Date(result.report.started_at).toLocaleString()}</span>
                  <span>·</span>
                  <span>Finished: {new Date(result.report.finished_at).toLocaleString()}</span>
                </div>
              </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-[#21262d] pb-2">
              {(['findings', 'surface', 'markdown'] as const).map(t => (
                <button key={t} onClick={() => setActiveTab(t)}
                  className={`px-4 py-1.5 rounded-lg text-xs font-medium transition ${
                    activeTab === t
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-500 hover:text-gray-300 hover:bg-[#21262d]'
                  }`}>
                  {t === 'findings' ? `🐛 Findings (${findings.length})` :
                   t === 'surface'  ? '🗺️ Attack Surface' :
                                     '📄 Markdown Report'}
                </button>
              ))}
            </div>

            {/* Findings tab */}
            {activeTab === 'findings' && (
              <div className="space-y-3">
                {findings.length === 0 ? (
                  <div className="bg-[#161b22] border border-[#30363d] rounded-xl py-14 text-center">
                    <p className="text-2xl mb-2">✅</p>
                    <p className="text-sm font-medium text-gray-300">No confirmed exploits</p>
                    <p className="text-xs text-gray-500 mt-1">Shannon policy: No exploit = No report finding</p>
                  </div>
                ) : (
                  findings.map((f, i) => <FindingCard key={i} f={f} />)
                )}
              </div>
            )}

            {/* Attack Surface tab */}
            {activeTab === 'surface' && result.report.attack_surface && (
              <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: 'Framework',  value: result.report.attack_surface.framework },
                    { label: 'Language',   value: result.report.attack_surface.language },
                    { label: 'Auth',       value: result.report.attack_surface.auth_mechanism },
                    { label: 'Target',     value: result.report.attack_surface.target_url },
                  ].map(row => (
                    <div key={row.label}>
                      <p className="text-xs text-gray-500 mb-0.5">{row.label}</p>
                      <p className="text-sm text-gray-200 font-mono">{row.value || '—'}</p>
                    </div>
                  ))}
                </div>

                {result.report.attack_surface.technologies?.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-500 mb-2">Technologies</p>
                    <div className="flex flex-wrap gap-1.5">
                      {result.report.attack_surface.technologies.map((t: string) => (
                        <span key={t} className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-300 px-2 py-0.5 rounded">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {result.report.attack_surface.endpoints?.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-500 mb-2">High-Value Endpoints</p>
                    <div className="space-y-1">
                      {result.report.attack_surface.endpoints.slice(0, 10).map((e: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-xs bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-1.5">
                          <span className="text-blue-400 font-mono">{e.method}</span>
                          <span className="text-gray-300 font-mono truncate">{e.url}</span>
                          {e.notes && <span className="text-gray-600 ml-auto">{e.notes}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Markdown tab */}
            {activeTab === 'markdown' && (
              <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#21262d]">
                  <span className="text-xs text-gray-500">Markdown Report</span>
                  <button
                    onClick={() => {
                      const blob = new Blob([result.report!.markdown], { type: 'text/markdown' })
                      const a = document.createElement('a')
                      a.href = URL.createObjectURL(blob)
                      a.download = `shannon-report-${result.scan_id || 'scan'}.md`
                      a.click()
                    }}
                    className="text-xs text-blue-400 hover:text-blue-300 transition"
                  >
                    ⬇ Download .md
                  </button>
                </div>
                <pre className="p-4 text-xs text-gray-300 overflow-auto max-h-[500px] leading-relaxed whitespace-pre-wrap">
                  {result.report.markdown}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
