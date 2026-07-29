'use client'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'

import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

function authHeader() {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : ''
  return { Authorization: `Bearer ${token}` }
}

type Tab = 'start' | 'subdomains' | 'ips' | 'screenshots' | 'vulns' | 'enrich' | 'status'

function ReconPageInner() {
  const [tab, setTab]           = useState<Tab>('start')
  const [domainId, setDomainId] = useState('')
  const [domain, setDomain]     = useState('')
  const [assetId, setAssetId]   = useState('')
  const [taskId, setTaskId]     = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const [subdomains, setSubdomains]   = useState<any[]>([])
  const [ips, setIps]                 = useState<any[]>([])
  const [screenshots, setScreenshots] = useState<any[]>([])
  const [vulns, setVulns]             = useState<any[]>([])
  const [taskStatus, setTaskStatus]   = useState<any>(null)
  const [providers, setProviders]     = useState<any>(null)

  const [enrichIp, setEnrichIp]       = useState('')
  const [enrichResult, setEnrichResult] = useState<any>(null)

  // Load providers status on mount
  useEffect(() => {
    axios.get(`${API}/api/v1/recon/providers/status`, { headers: authHeader() })
      .then(r => setProviders(r.data))
      .catch(() => {})
  }, [])

  const startRecon = async () => {
    if (!domain || !assetId || !domainId) { setError('Fill in Domain, Asset ID and Domain ID'); return }
    setLoading(true); setError('')
    try {
      const r = await axios.post(`${API}/api/v1/recon/start`,
        { domain, asset_id: assetId, domain_id: domainId, run_async: true },
        { headers: authHeader() }
      )
      setTaskId(r.data.task_id || '')
      setTab('status')
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to start recon')
    } finally { setLoading(false) }
  }

  const checkStatus = useCallback(async () => {
    if (!taskId) return
    try {
      const r = await axios.get(`${API}/api/v1/recon/status/${taskId}`, { headers: authHeader() })
      setTaskStatus(r.data)
    } catch {}
  }, [taskId])

  const loadSubdomains = async () => {
    if (!domainId) { setError('Enter Domain ID first'); return }
    setLoading(true)
    try {
      const r = await axios.get(`${API}/api/v1/recon/subdomains`, { params: { domain_id: domainId }, headers: authHeader() })
      setSubdomains(r.data.subdomains || [])
      setTab('subdomains')
    } catch (e: any) { setError(e.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const loadIPs = async () => {
    if (!domainId) { setError('Enter Domain ID first'); return }
    setLoading(true)
    try {
      const r = await axios.get(`${API}/api/v1/recon/ips`, { params: { domain_id: domainId }, headers: authHeader() })
      setIps(r.data.ips || [])
      setTab('ips')
    } catch (e: any) { setError(e.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const loadScreenshots = async () => {
    if (!domainId) { setError('Enter Domain ID first'); return }
    setLoading(true)
    try {
      const r = await axios.get(`${API}/api/v1/recon/screenshots`, { params: { domain_id: domainId }, headers: authHeader() })
      setScreenshots(r.data.screenshots || [])
      setTab('screenshots')
    } catch (e: any) { setError(e.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const loadVulns = async () => {
    setLoading(true)
    try {
      const r = await axios.get(`${API}/api/v1/recon/vulnerabilities`, { headers: authHeader() })
      setVulns(r.data.vulnerabilities || [])
      setTab('vulns')
    } catch (e: any) { setError(e.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const runEnrich = async () => {
    if (!enrichIp) return
    setLoading(true); setEnrichResult(null)
    try {
      const r = await axios.post(`${API}/api/v1/recon/enrich-ip`, { ip: enrichIp }, { headers: authHeader() })
      setEnrichResult(r.data)
      setTab('enrich')
    } catch (e: any) { setError(e.response?.data?.detail || 'Failed') }
    finally { setLoading(false) }
  }

  const TABS: { id: Tab; label: string; emoji: string }[] = [
    { id: 'start',      label: 'Start Recon',  emoji: '🚀' },
    { id: 'subdomains', label: 'Subdomains',   emoji: '🌐' },
    { id: 'ips',        label: 'IPs',          emoji: '📡' },
    { id: 'screenshots',label: 'Screenshots',  emoji: '📸' },
    { id: 'vulns',      label: 'Vulns',        emoji: '🐛' },
    { id: 'enrich',     label: 'Enrich IP',    emoji: '🔍' },
    { id: 'status',     label: 'Task Status',  emoji: '⏳' },
  ]

  const sevColor: Record<string, string> = {
    Critical: 'text-red-400 bg-red-500/10 border-red-500/20',
    High:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
    Medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    Low:      'text-blue-400 bg-blue-500/10 border-blue-500/20',
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto space-y-5">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-gray-100">🔭 Recon Engine</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              subfinder → dnsx → naabu → httpx → nuclei → gowitness
            </p>
          </div>
          {providers && (
            <div className="flex gap-2 flex-wrap">
              {[
                { label: 'Gemini',   ok: providers.ai_providers?.gemini?.configured },
                { label: 'VT',       ok: providers.threat_intelligence?.virustotal?.configured },
                { label: 'Shodan',   ok: providers.threat_intelligence?.shodan?.configured },
                { label: 'subfinder',ok: providers.projectdiscovery_tools?.subfinder?.available },
                { label: 'nuclei',   ok: providers.projectdiscovery_tools?.nuclei?.available },
              ].map(p => (
                <span key={p.label} className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${
                  p.ok ? 'text-green-400 bg-green-500/10 border-green-500/20'
                       : 'text-gray-600 bg-gray-800 border-gray-700'
                }`}>
                  {p.ok ? '✓' : '✗'} {p.label}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Config row */}
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Domain</label>
            <input className="w-full bg-[#161b22] border border-[#30363d] text-gray-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
              placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Asset ID</label>
            <input className="w-full bg-[#161b22] border border-[#30363d] text-gray-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
              placeholder="uuid" value={assetId} onChange={e => setAssetId(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Domain ID</label>
            <input className="w-full bg-[#161b22] border border-[#30363d] text-gray-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
              placeholder="uuid" value={domainId} onChange={e => setDomainId(e.target.value)} />
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">{error}</div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 flex-wrap border-b border-[#21262d] pb-2">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                tab === t.id ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200 hover:bg-[#21262d]'
              }`}>
              {t.emoji} {t.label}
            </button>
          ))}
        </div>

        {/* ── START TAB ─────────────────────────────────────────── */}
        {tab === 'start' && (
          <div className="space-y-4">
            <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
              <h2 className="text-sm font-semibold text-gray-200">Full Recon Pipeline</h2>
              <div className="grid grid-cols-3 gap-3 text-xs">
                {[
                  { step: '1', tool: 'subfinder', desc: 'Subdomain enumeration' },
                  { step: '2', tool: 'dnsx',      desc: 'DNS → exact IPs' },
                  { step: '3', tool: 'naabu',     desc: 'Port scanning' },
                  { step: '4', tool: 'httpx',     desc: 'HTTP probe + tech detect' },
                  { step: '5', tool: 'nuclei',    desc: 'Vulnerability scanning' },
                  { step: '6', tool: 'gowitness', desc: 'Screenshots' },
                ].map(s => (
                  <div key={s.step} className="flex items-start gap-2 p-3 bg-[#0d1117] border border-[#21262d] rounded-lg">
                    <span className="text-blue-400 font-bold shrink-0">{s.step}.</span>
                    <div>
                      <p className="font-mono text-gray-200">{s.tool}</p>
                      <p className="text-gray-500 mt-0.5">{s.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
              <button onClick={startRecon} disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition flex items-center gap-2">
                {loading ? '⏳ Starting...' : '🚀 Start Full Recon'}
              </button>
            </div>

            {/* Quick actions */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: '🌐 Load Subdomains', fn: loadSubdomains },
                { label: '📡 Load IPs',        fn: loadIPs },
                { label: '📸 Screenshots',     fn: loadScreenshots },
                { label: '🐛 Vulnerabilities', fn: loadVulns },
              ].map(a => (
                <button key={a.label} onClick={a.fn} disabled={loading}
                  className="bg-[#161b22] border border-[#30363d] hover:border-blue-500/50 text-gray-300 text-xs px-4 py-2.5 rounded-lg transition disabled:opacity-50">
                  {loading ? '...' : a.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ── SUBDOMAINS TAB ─────────────────────────────────────── */}
        {tab === 'subdomains' && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-[#21262d] flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-200">
                Subdomains <span className="text-blue-400 ml-2">{subdomains.length}</span>
              </span>
              <button onClick={loadSubdomains} className="text-xs text-blue-400 hover:text-blue-300">↻ Refresh</button>
            </div>
            {subdomains.length === 0 ? (
              <div className="py-16 text-center text-gray-500 text-sm">No subdomains yet — start a recon scan</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#21262d]">
                      {['Subdomain', 'IP Addresses', 'Ports', 'SSL', 'Responsive', 'Technologies'].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {subdomains.map((s, i) => (
                      <tr key={i} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                        <td className="px-4 py-3 font-mono text-blue-400">{s.subdomain}</td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-0.5">
                            {(s.ip_addresses || []).map((ip: string) => (
                              <span key={ip} className="font-mono text-gray-300">{ip}</span>
                            ))}
                            {(!s.ip_addresses || s.ip_addresses.length === 0) && <span className="text-gray-600">—</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(s.open_ports || []).map((p: number) => (
                              <span key={p} className="bg-[#0d1117] border border-[#30363d] px-1.5 py-0.5 rounded text-gray-300">{p}</span>
                            ))}
                            {(!s.open_ports || s.open_ports.length === 0) && <span className="text-gray-600">—</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={s.has_ssl ? 'text-green-400' : 'text-gray-600'}>{s.has_ssl ? '✓ Yes' : '✗ No'}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={s.is_responsive ? 'text-green-400' : 'text-gray-600'}>{s.is_responsive ? '● Live' : '○ Down'}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(s.technologies || []).map((t: string) => (
                              <span key={t} className="bg-blue-500/10 border border-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded">{t}</span>
                            ))}
                            {(!s.technologies || s.technologies.length === 0) && <span className="text-gray-600">—</span>}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── IPs TAB ─────────────────────────────────────────────── */}
        {tab === 'ips' && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-[#21262d] flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-200">
                Unique IPs <span className="text-blue-400 ml-2">{ips.length}</span>
              </span>
              <button onClick={loadIPs} className="text-xs text-blue-400 hover:text-blue-300">↻ Refresh</button>
            </div>
            {ips.length === 0 ? (
              <div className="py-16 text-center text-gray-500 text-sm">No IPs yet — run a recon scan</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#21262d]">
                      {['IP Address', 'Subdomains', 'Count'].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {ips.map((ip, i) => (
                      <tr key={i} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                        <td className="px-4 py-3">
                          <span className="font-mono text-green-400 text-sm">{ip.ip}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(ip.subdomains || []).map((s: string) => (
                              <span key={s} className="bg-[#0d1117] border border-[#30363d] px-1.5 py-0.5 rounded font-mono text-gray-300">{s}</span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-gray-400">{ip.subdomain_count}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── SCREENSHOTS TAB ─────────────────────────────────────── */}
        {tab === 'screenshots' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-200">
                Screenshots <span className="text-blue-400 ml-2">{screenshots.length}</span>
              </span>
              <button onClick={loadScreenshots} className="text-xs text-blue-400 hover:text-blue-300">↻ Refresh</button>
            </div>
            {screenshots.length === 0 ? (
              <div className="bg-[#161b22] border border-[#30363d] rounded-xl py-16 text-center text-gray-500 text-sm">
                No screenshots yet — gowitness captures them during recon
              </div>
            ) : (
              <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {screenshots.map((s, i) => (
                  <div key={i} className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
                    {s.file_path ? (
                      <img
                        src={`/screenshots/${s.file_path.split('/').pop()}`}
                        alt={s.url}
                        className="w-full h-36 object-cover bg-[#0d1117]"
                        onError={e => { (e.target as HTMLImageElement).style.display = 'none' }}
                      />
                    ) : (
                      <div className="w-full h-36 bg-[#0d1117] flex items-center justify-center text-gray-600 text-xs">
                        No preview
                      </div>
                    )}
                    <div className="p-3 space-y-1">
                      <p className="text-xs text-blue-400 truncate font-mono">{s.url}</p>
                      <p className="text-xs text-gray-500">{s.subdomain}</p>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${
                          s.status_code >= 200 && s.status_code < 300
                            ? 'text-green-400 bg-green-500/10 border-green-500/20'
                            : s.status_code >= 300 && s.status_code < 400
                            ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
                            : 'text-red-400 bg-red-500/10 border-red-500/20'
                        }`}>
                          {s.status_code || '?'}
                        </span>
                        {s.title && <span className="text-xs text-gray-500 truncate">{s.title}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── VULNS TAB ───────────────────────────────────────────── */}
        {tab === 'vulns' && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-[#21262d]">
              <span className="text-sm font-semibold text-gray-200">
                Vulnerabilities (nuclei) <span className="text-red-400 ml-2">{vulns.length}</span>
              </span>
            </div>
            {vulns.length === 0 ? (
              <div className="py-16 text-center text-gray-500 text-sm">No vulnerabilities found yet</div>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#21262d]">
                    {['CVE', 'Title', 'Severity', 'CVSS', 'Found'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {vulns.map((v, i) => (
                    <tr key={i} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                      <td className="px-4 py-3 font-mono text-blue-400">{v.cve_id || '—'}</td>
                      <td className="px-4 py-3 max-w-xs">
                        <p className="text-gray-200 truncate">{v.title}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded border text-xs font-medium ${sevColor[v.severity] || 'text-gray-400 bg-gray-500/10 border-gray-500/20'}`}>
                          {v.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-bold ${
                          (v.cvss_score || 0) >= 9 ? 'text-red-400' :
                          (v.cvss_score || 0) >= 7 ? 'text-orange-400' :
                          (v.cvss_score || 0) >= 4 ? 'text-yellow-400' : 'text-blue-400'
                        }`}>
                          {v.cvss_score?.toFixed(1) || '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {v.created_at ? new Date(v.created_at).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── ENRICH TAB ──────────────────────────────────────────── */}
        {tab === 'enrich' && (
          <div className="space-y-4">
            <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-gray-200 mb-4">IP Enrichment — VT + Shodan + AbuseIPDB + GreyNoise</h2>
              <div className="flex gap-3">
                <input
                  className="flex-1 bg-[#0d1117] border border-[#30363d] text-gray-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                  placeholder="e.g. 8.8.8.8"
                  value={enrichIp}
                  onChange={e => setEnrichIp(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runEnrich()}
                />
                <button onClick={runEnrich} disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium transition">
                  {loading ? '...' : '🔍 Enrich'}
                </button>
              </div>
            </div>

            {enrichResult && (
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { key: 'virustotal', label: '🦠 VirusTotal',  color: 'blue' },
                  { key: 'shodan',     label: '🌊 Shodan',      color: 'cyan' },
                  { key: 'abuseipdb', label: '⚠️ AbuseIPDB',  color: 'orange' },
                  { key: 'greynoise', label: '💨 GreyNoise',   color: 'gray' },
                ].map(p => {
                  const data = enrichResult[p.key] || {}
                  const isErr = data.status === 'key_not_configured' || data.status === 'error'
                  return (
                    <div key={p.key} className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 space-y-2">
                      <p className="text-xs font-semibold text-gray-300">{p.label}</p>
                      {isErr ? (
                        <p className="text-xs text-red-400">{data.status === 'key_not_configured' ? 'API key not set' : 'Error: ' + (data.error || '')}</p>
                      ) : (
                        <div className="space-y-1 text-xs">
                          {Object.entries(data).filter(([k]) => !['provider', 'ip'].includes(k)).slice(0, 6).map(([k, v]) => (
                            <div key={k} className="flex justify-between gap-2">
                              <span className="text-gray-500 capitalize">{k.replace(/_/g, ' ')}</span>
                              <span className={`text-right font-medium truncate max-w-[100px] ${
                                k === 'is_malicious' && v ? 'text-red-400' : 'text-gray-300'
                              }`}>
                                {typeof v === 'boolean' ? (v ? '⚠ Yes' : '✓ No') : String(v) || '—'}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* ── STATUS TAB ──────────────────────────────────────────── */}
        {tab === 'status' && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200">Scan Task Status</h2>
            <div className="flex gap-3">
              <input
                className="flex-1 bg-[#0d1117] border border-[#30363d] text-gray-100 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
                placeholder="task-id"
                value={taskId}
                onChange={e => setTaskId(e.target.value)}
              />
              <button onClick={checkStatus}
                className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg text-sm font-medium transition">
                Check
              </button>
            </div>

            {taskStatus && (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <span className={`w-2.5 h-2.5 rounded-full animate-pulse ${
                    taskStatus.status === 'SUCCESS' ? 'bg-green-400' :
                    taskStatus.status === 'FAILURE' ? 'bg-red-400' :
                    taskStatus.status === 'STARTED' ? 'bg-blue-400' : 'bg-yellow-400'
                  }`} />
                  <span className="text-sm font-medium text-gray-200">{taskStatus.status}</span>
                </div>

                {taskStatus.result && (
                  <div className="space-y-2">
                    {taskStatus.result.summary && (
                      <div className="grid grid-cols-3 gap-3">
                        {Object.entries(taskStatus.result.summary).map(([k, v]) => (
                          <div key={k} className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3">
                            <p className="text-lg font-bold text-blue-400">{String(v)}</p>
                            <p className="text-xs text-gray-500 capitalize mt-0.5">{k.replace(/_/g, ' ')}</p>
                          </div>
                        ))}
                      </div>
                    )}
                    <pre className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3 text-xs text-gray-400 overflow-auto max-h-64">
                      {JSON.stringify(taskStatus.result, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  )
}

export default function ReconPage(props: any) {
  return (
    <AuthProvider>
      <AppLayout>
        <ReconPageInner {...props} />
      </AppLayout>
    </AuthProvider>
  )
}
