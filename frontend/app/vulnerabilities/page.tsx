'use client'

import { useState } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useVulnerabilities } from '@/hooks/useVulnerabilities'
import { StatCard, LoadingState, ErrorState, SeverityBadge, Table, EmptyState, Modal } from '@/components/ui'
import { Bug, Shield, Search, Brain } from 'lucide-react'
import type { Vulnerability } from '@/types'
import api from '@/lib/api'

const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low']

function AIAnalysisModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  const [analysis, setAnalysis] = useState('')
  const [remediation, setRemediation] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [provider, setProvider] = useState('claude')

  const analyze = async () => {
    setLoading(true)
    try {
      const res = await api.analyzeVulnerability(vuln.id, provider)
      setAnalysis(res.analysis)
      const rem = await api.getRemediationSteps(vuln.id)
      setRemediation(rem.remediation_steps)
    } catch (e: any) {
      setAnalysis(`Error: ${e.response?.data?.detail || 'AI analysis failed. Check API key configuration.'}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg bg-[#0d1117] border border-[#30363d] space-y-1">
        <p className="text-xs text-gray-500">CVE ID: <span className="text-gray-300">{vuln.cve_id || 'N/A'}</span></p>
        <p className="text-xs text-gray-500">Severity: <SeverityBadge severity={vuln.severity} /></p>
        <p className="text-xs text-gray-500">CVSS Score: <span className="text-gray-300">{vuln.cvss_score || 'N/A'}</span></p>
      </div>

      <div className="flex gap-2">
        <select className="input text-xs flex-1" value={provider} onChange={e => setProvider(e.target.value)}>
          <option value="claude">Anthropic Claude</option>
          <option value="openai">OpenAI GPT-4</option>
          <option value="gemini">Google Gemini</option>
        </select>
        <button className="btn-primary text-xs flex items-center gap-1.5" onClick={analyze} disabled={loading}>
          <Brain className="w-3.5 h-3.5" />
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {analysis && (
        <div>
          <p className="text-xs font-medium text-gray-400 mb-2">AI Analysis</p>
          <div className="p-3 rounded-lg bg-[#0d1117] border border-[#30363d] text-xs text-gray-300 leading-relaxed max-h-48 overflow-y-auto">
            {analysis}
          </div>
        </div>
      )}

      {remediation.length > 0 && (
        <div>
          <p className="text-xs font-medium text-gray-400 mb-2">Remediation Steps</p>
          <ol className="space-y-1.5">
            {remediation.map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-gray-300">
                <span className="text-blue-400 font-bold shrink-0">{i + 1}.</span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}

      <button className="btn-secondary text-sm w-full" onClick={onClose}>Close</button>
    </div>
  )
}

function VulnerabilitiesContent() {
  const [filter, setFilter] = useState<string | undefined>(undefined)
  const [search, setSearch] = useState('')
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)
  const { vulnerabilities, total, loading, error } = useVulnerabilities(filter)

  if (loading) return <LoadingState text="Loading vulnerabilities..." />
  if (error) return <ErrorState message={error} />

  const counts = {
    Critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
    High:     vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
    Medium:   vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
    Low:      vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
  }

  const filtered = vulnerabilities.filter(v =>
    !search || v.title.toLowerCase().includes(search.toLowerCase()) || v.cve_id?.includes(search)
  )

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-gray-100">Vulnerabilities</h1>
          <p className="text-xs text-gray-500 mt-0.5">{total} vulnerabilities found</p>
        </div>
      </div>

      {/* Severity Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Critical" value={counts.Critical} icon={Bug} color="red" />
        <StatCard label="High"     value={counts.High}     color="yellow" />
        <StatCard label="Medium"   value={counts.Medium}   color="blue" />
        <StatCard label="Low"      value={counts.Low}      icon={Shield} color="green" />
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
          <input className="input pl-8 py-1.5 text-xs" placeholder="Search CVE ID or title..."
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => setFilter(s === 'All' ? undefined : s)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                (filter === s || (s === 'All' && !filter))
                  ? 'bg-blue-600 text-white'
                  : 'btn-secondary'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card">
        {filtered.length === 0 ? (
          <EmptyState title="No vulnerabilities found" description="Adjust your filters or run a scan" />
        ) : (
          <Table headers={['CVE ID', 'Title', 'Severity', 'CVSS', 'Published', 'AI Analysis']}>
            {filtered.map((v: Vulnerability) => (
              <tr key={v.id} className="table-row">
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-blue-400">{v.cve_id || '—'}</span>
                </td>
                <td className="px-4 py-3 max-w-xs">
                  <p className="text-xs text-gray-200 line-clamp-2">{v.title}</p>
                </td>
                <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-bold ${
                    (v.cvss_score || 0) >= 9 ? 'text-red-400' :
                    (v.cvss_score || 0) >= 7 ? 'text-orange-400' :
                    (v.cvss_score || 0) >= 4 ? 'text-yellow-400' : 'text-blue-400'
                  }`}>
                    {v.cvss_score?.toFixed(1) || '—'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-500">{v.published_date || '—'}</span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => setSelectedVuln(v)}
                    className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition"
                  >
                    <Brain className="w-3.5 h-3.5" /> Analyze
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>

      {/* AI Analysis Modal */}
      <Modal
        open={!!selectedVuln}
        onClose={() => setSelectedVuln(null)}
        title={selectedVuln?.title || 'AI Vulnerability Analysis'}
      >
        {selectedVuln && (
          <AIAnalysisModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
        )}
      </Modal>
    </div>
  )
}

export default function VulnerabilitiesPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <VulnerabilitiesContent />
      </AppLayout>
    </AuthProvider>
  )
}
