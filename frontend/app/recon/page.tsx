'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import {
  Activity,
  AlertTriangle,
  Bug,
  Camera,
  Check,
  CheckCircle2,
  Clipboard,
  Globe2,
  KeyRound,
  Loader2,
  Network,
  Radio,
  RefreshCw,
  Rocket,
  Search,
  Server,
  ShieldCheck,
  XCircle,
  type LucideIcon,
} from 'lucide-react'

import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

function authHeader() {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : ''
  return { Authorization: `Bearer ${token}` }
}

function errorMessage(error: any, fallback: string) {
  return error?.response?.data?.detail || error?.message || fallback
}

type Tab = 'start' | 'subdomains' | 'ips' | 'screenshots' | 'vulns' | 'enrich' | 'status'

type TargetOption = {
  asset_id: string
  asset_name: string
  asset_type: string
  target: string
  domain_id: string | null
  domain: string
  scan_status: string
  active_scan_id?: string | null
}

type ScanStatus = {
  task_id: string
  scan_reference: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  asset_id: string
  domain_id: string | null
  domain: string
  summary: { discoveries: number; vulnerabilities: number }
  current_tool?: string | null
  progress?: number
  live_subdomains?: string[]
  error?: string | null
  started_at?: string | null
  completed_at?: string | null
}

const TABS: { id: Tab; label: string; icon: LucideIcon }[] = [
  { id: 'start', label: 'Start Recon', icon: Rocket },
  { id: 'subdomains', label: 'Subdomains', icon: Network },
  { id: 'ips', label: 'IPs', icon: Radio },
  { id: 'screenshots', label: 'Screenshots', icon: Camera },
  { id: 'vulns', label: 'Vulnerabilities', icon: Bug },
  { id: 'enrich', label: 'Enrich IP', icon: Search },
  { id: 'status', label: 'Task Status', icon: Activity },
]

const PIPELINE = [
  { tool: 'subfinder', description: 'Subdomain enumeration' },
  { tool: 'dnsx', description: 'DNS resolution to exact IPs' },
  { tool: 'naabu', description: 'Top-port TCP scanning' },
  { tool: 'nmap', description: 'Service and version detection on open ports' },
  { tool: 'httpx', description: 'HTTP status and technology detection' },
  { tool: 'nuclei', description: 'Template-based vulnerability scanning' },
  { tool: 'gowitness', description: 'Chromium screenshots' },
]

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  return (
    <button
      type="button"
      onClick={copy}
      className="shrink-0 text-gray-500 transition hover:text-blue-400"
      title="Copy ID"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Clipboard className="h-3.5 w-3.5" />}
    </button>
  )
}

function StatusMark({ status }: { status?: string }) {
  if (status === 'running' || status === 'pending') {
    return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
  }
  if (status === 'completed') {
    return <CheckCircle2 className="h-4 w-4 text-green-400" />
  }
  if (status === 'failed' || status === 'cancelled') {
    return <XCircle className="h-4 w-4 text-red-400" />
  }
  return <Activity className="h-4 w-4 text-gray-500" />
}

function ReconContent() {
  const [tab, setTab] = useState<Tab>('start')
  const [targets, setTargets] = useState<TargetOption[]>([])
  const [selectedKey, setSelectedKey] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [providers, setProviders] = useState<any>(null)
  const [taskId, setTaskId] = useState('')
  const [taskStatus, setTaskStatus] = useState<ScanStatus | null>(null)
  const [subdomains, setSubdomains] = useState<any[]>([])
  const [ips, setIps] = useState<any[]>([])
  const [screenshots, setScreenshots] = useState<any[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
  const [enrichIp, setEnrichIp] = useState('')
  const [enrichment, setEnrichment] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const targetKey = (target: TargetOption) => `${target.asset_id}:${target.domain_id || target.domain}`
  const selectedTarget = useMemo(
    () => targets.find(target => targetKey(target) === selectedKey) || null,
    [selectedKey, targets],
  )
  const domainId = taskStatus?.domain_id || selectedTarget?.domain_id || ''

  const loadConfiguration = useCallback(async () => {
    setError('')
    const [targetsResult, providersResult] = await Promise.allSettled([
      axios.get(`${API}/api/v1/recon/assets`, { headers: authHeader() }),
      axios.get(`${API}/api/v1/recon/providers/status`, { headers: authHeader() }),
    ])

    if (targetsResult.status === 'fulfilled') {
      const items: TargetOption[] = targetsResult.value.data.items || []
      setTargets(items)
      setSelectedKey(current => current || (items[0] ? targetKey(items[0]) : ''))
    } else {
      setError(errorMessage(targetsResult.reason, 'Could not load owned assets'))
    }

    if (providersResult.status === 'fulfilled') {
      setProviders(providersResult.value.data)
    } else {
      setError(current => current || errorMessage(providersResult.reason, 'Could not check scanner tools'))
    }
  }, [])

  useEffect(() => {
    void loadConfiguration()
  }, [loadConfiguration])

  useEffect(() => {
    if (!taskId && selectedTarget?.active_scan_id) {
      setTaskId(selectedTarget.active_scan_id)
    }
  }, [selectedTarget?.active_scan_id, taskId])

  const fetchStatus = useCallback(async () => {
    if (!taskId) return null
    const response = await axios.get<ScanStatus>(`${API}/api/v1/recon/status/${taskId}`, {
      headers: authHeader(),
    })
    setTaskStatus(response.data)
    return response.data
  }, [taskId])

  const fetchSubdomains = useCallback(async (resolvedDomainId: string, resolvedScanId?: string) => {
    if (!resolvedDomainId) return
    const response = await axios.get(`${API}/api/v1/recon/subdomains`, {
      params: {
        domain_id: resolvedDomainId,
        ...(resolvedScanId ? { scan_id: resolvedScanId } : {}),
      },
      headers: authHeader(),
    })
    setSubdomains(response.data.subdomains || [])
  }, [])

  const fetchResults = useCallback(async (resolvedDomainId: string, resolvedScanId?: string) => {
    if (!resolvedDomainId) return
    const config = { params: { domain_id: resolvedDomainId }, headers: authHeader() }
    const [subdomainResult, ipResult, screenshotResult, vulnerabilityResult] = await Promise.all([
      axios.get(`${API}/api/v1/recon/subdomains`, {
        params: {
          domain_id: resolvedDomainId,
          ...(resolvedScanId ? { scan_id: resolvedScanId } : {}),
        },
        headers: authHeader(),
      }),
      axios.get(`${API}/api/v1/recon/ips`, config),
      axios.get(`${API}/api/v1/recon/screenshots`, config),
      axios.get(`${API}/api/v1/recon/vulnerabilities`, config),
    ])
    setSubdomains(subdomainResult.data.subdomains || [])
    setIps(ipResult.data.ips || [])
    setScreenshots(screenshotResult.data.screenshots || [])
    setVulnerabilities(vulnerabilityResult.data.vulnerabilities || [])
  }, [])

  useEffect(() => {
    if (!taskId) return
    let cancelled = false

    const poll = async () => {
      try {
        const current = await fetchStatus()
        if (!current || cancelled) return
        if (current.domain_id && ['pending', 'running'].includes(current.status)) {
          await fetchSubdomains(current.domain_id, current.task_id)
        } else if (current.status === 'completed' && current.domain_id) {
          await fetchResults(current.domain_id, current.task_id)
        }
      } catch (pollError) {
        if (!cancelled) setError(errorMessage(pollError, 'Could not read scan status'))
      }
    }

    void poll()
    const interval = window.setInterval(async () => {
      const current = await fetchStatus().catch(() => null)
      if (!current || cancelled) return
      if (current.domain_id && ['pending', 'running'].includes(current.status)) {
        await fetchSubdomains(current.domain_id, current.task_id).catch(() => undefined)
      }
      if (['completed', 'failed', 'cancelled'].includes(current.status)) {
        window.clearInterval(interval)
        if (current.domain_id) {
          if (current.status === 'completed') {
            await fetchResults(current.domain_id, current.task_id).catch(() => undefined)
          } else {
            await fetchSubdomains(current.domain_id, current.task_id).catch(() => undefined)
          }
        }
      }
    }, 3000)

    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [fetchResults, fetchStatus, fetchSubdomains, taskId])

  const startRecon = async () => {
    if (!selectedTarget) {
      setError('Add or select a domain asset first')
      return
    }
    if (!authorized) {
      setError('Confirm that you own this target or have written permission to scan it')
      return
    }
    if (providers && !providers.ready) {
      setError('Scanner tools are not ready. Check the tool status shown above.')
      return
    }

    setLoading(true)
    setError('')
    setTaskStatus(null)
    setSubdomains([])
    try {
      const response = await axios.post(
        `${API}/api/v1/recon/start`,
        {
          asset_id: selectedTarget.asset_id,
          domain_id: selectedTarget.domain_id,
          confirmed_authorized: authorized,
        },
        { headers: authHeader() },
      )
      setTaskId(response.data.task_id)
      setTaskStatus({
        task_id: response.data.task_id,
        scan_reference: response.data.scan_reference,
        status: response.data.status,
        asset_id: response.data.asset_id,
        domain_id: response.data.domain_id,
        domain: response.data.domain,
        summary: { discoveries: 0, vulnerabilities: 0 },
      })
      setTab('subdomains')
      await loadConfiguration()
    } catch (startError) {
      setError(errorMessage(startError, 'Failed to start real recon'))
    } finally {
      setLoading(false)
    }
  }

  const openResults = async (nextTab: Tab) => {
    if (!domainId) {
      setError('Select an asset first. Its Domain ID will be resolved automatically.')
      return
    }
    setLoading(true)
    setError('')
    try {
      if (nextTab === 'subdomains') {
        await fetchSubdomains(domainId, taskId || undefined)
      } else {
        await fetchResults(domainId, taskId || undefined)
      }
      setTab(nextTab)
    } catch (resultError) {
      setError(errorMessage(resultError, 'Could not load scan results'))
    } finally {
      setLoading(false)
    }
  }

  const enrich = async () => {
    if (!enrichIp.trim()) return
    setLoading(true)
    setError('')
    try {
      const response = await axios.post(
        `${API}/api/v1/recon/enrich-ip`,
        { ip: enrichIp.trim() },
        { headers: authHeader() },
      )
      setEnrichment(response.data)
    } catch (enrichError) {
      setError(errorMessage(enrichError, 'Could not enrich IP'))
    } finally {
      setLoading(false)
    }
  }

  const toolStatuses = providers?.projectdiscovery_tools
    ? Object.entries(providers.projectdiscovery_tools) as [string, any][]
    : []

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="h-5 w-5 text-blue-400" />
            <h1 className="text-lg font-bold text-gray-100">Recon Engine</h1>
          </div>
          <p className="mt-1 text-xs text-gray-500">
            Real pipeline: subfinder → dnsx → naabu → nmap → httpx → nuclei → gowitness
          </p>
        </div>

        <div className="flex max-w-2xl flex-wrap justify-end gap-1.5">
          {toolStatuses.map(([name, state]) => (
            <span
              key={name}
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] ${
                state.available
                  ? 'border-green-500/20 bg-green-500/10 text-green-400'
                  : 'border-red-500/20 bg-red-500/10 text-red-400'
              }`}
            >
              {state.available ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
              {name}
            </span>
          ))}
          {providers && (
            <span
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] ${
                providers.browser?.chromium?.available
                  ? 'border-green-500/20 bg-green-500/10 text-green-400'
                  : 'border-red-500/20 bg-red-500/10 text-red-400'
              }`}
            >
              {providers.browser?.chromium?.available
                ? <CheckCircle2 className="h-3 w-3" />
                : <XCircle className="h-3 w-3" />}
              Chromium
            </span>
          )}
        </div>
      </div>

      <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-4">
        <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr_1fr]">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-400">Owned asset and domain</label>
            <select
              className="input"
              value={selectedKey}
              onChange={event => {
                setSelectedKey(event.target.value)
                setTaskId('')
                setTaskStatus(null)
                setSubdomains([])
                setIps([])
                setScreenshots([])
                setVulnerabilities([])
              }}
            >
              {targets.length === 0 && <option value="">No valid domain assets found</option>}
              {targets.map(target => (
                <option key={targetKey(target)} value={targetKey(target)}>
                  {target.asset_name} — {target.domain}
                </option>
              ))}
            </select>
            <p className="mt-1.5 text-[11px] text-gray-500">
              Add targets on the Assets page. Recon only lists assets owned by your account.
            </p>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-400">Asset ID</label>
            <div className="flex h-10 items-center gap-2 rounded-lg border border-[#30363d] bg-[#0d1117] px-3">
              <Server className="h-3.5 w-3.5 shrink-0 text-blue-400" />
              <code className="min-w-0 flex-1 truncate text-[11px] text-gray-300">
                {selectedTarget?.asset_id || 'Select an asset'}
              </code>
              {selectedTarget?.asset_id && <CopyValue value={selectedTarget.asset_id} />}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-400">Domain ID</label>
            <div className="flex h-10 items-center gap-2 rounded-lg border border-[#30363d] bg-[#0d1117] px-3">
              <KeyRound className="h-3.5 w-3.5 shrink-0 text-purple-400" />
              <code className="min-w-0 flex-1 truncate text-[11px] text-gray-300">
                {domainId || (selectedTarget ? 'Created automatically on first scan' : 'Select an asset')}
              </code>
              {domainId && <CopyValue value={domainId} />}
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-1 border-b border-[#21262d] pb-2">
        {TABS.map(item => {
          const Icon = item.icon
          return (
            <button
              type="button"
              key={item.id}
              onClick={() => setTab(item.id)}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                tab === item.id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:bg-[#21262d] hover:text-gray-200'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {item.label}
            </button>
          )
        })}
      </div>

      {tab === 'start' && (
        <div className="space-y-4">
          <section className="space-y-4 rounded-xl border border-[#30363d] bg-[#161b22] p-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-gray-200">Full Recon Pipeline</h2>
                <p className="mt-1 text-xs text-gray-500">
                  Results are saved only from tool output. A tool failure marks the scan failed.
                </p>
              </div>
              <ShieldCheck className="h-5 w-5 text-green-400" />
            </div>

            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {PIPELINE.map((step, index) => (
                <div key={step.tool} className="flex gap-3 rounded-lg border border-[#21262d] bg-[#0d1117] p-3">
                  <span className="text-xs font-bold text-blue-400">{index + 1}.</span>
                  <div>
                    <p className="font-mono text-xs text-gray-200">{step.tool}</p>
                    <p className="mt-1 text-[11px] text-gray-500">{step.description}</p>
                  </div>
                </div>
              ))}
            </div>

            <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-blue-500/20 bg-blue-500/5 p-3">
              <input
                type="checkbox"
                checked={authorized}
                onChange={event => setAuthorized(event.target.checked)}
                className="mt-0.5 h-4 w-4 accent-blue-600"
              />
              <span className="text-xs leading-5 text-gray-300">
                I own <strong className="text-gray-100">{selectedTarget?.domain || 'this target'}</strong> or have
                written authorization to run active reconnaissance and vulnerability checks.
              </span>
            </label>

            <button
              type="button"
              onClick={startRecon}
              disabled={loading || !selectedTarget || !authorized || (providers && !providers.ready)}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Rocket className="h-4 w-4" />}
              {loading ? 'Starting real scan…' : 'Start Full Recon'}
            </button>
          </section>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: 'Load subdomains', icon: Network, tab: 'subdomains' as Tab },
              { label: 'Load IPs', icon: Radio, tab: 'ips' as Tab },
              { label: 'Screenshots', icon: Camera, tab: 'screenshots' as Tab },
              { label: 'Vulnerabilities', icon: Bug, tab: 'vulns' as Tab },
            ].map(action => {
              const Icon = action.icon
              return (
                <button
                  type="button"
                  key={action.label}
                  onClick={() => void openResults(action.tab)}
                  disabled={loading || !domainId}
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-2.5 text-xs text-gray-300 transition hover:border-blue-500/50 disabled:opacity-40"
                >
                  <Icon className="h-4 w-4 text-blue-400" />
                  {action.label}
                </button>
              )
            })}
          </div>
        </div>
      )}

      {tab === 'status' && (
        <section className="rounded-xl border border-[#30363d] bg-[#161b22] p-5">
          {!taskStatus ? (
            <div className="py-12 text-center">
              <Activity className="mx-auto h-8 w-8 text-gray-600" />
              <p className="mt-3 text-sm text-gray-400">No scan started in this session</p>
              <p className="mt-1 text-xs text-gray-600">Start Recon to see live progress.</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                <div>
                  <div className="flex items-center gap-2">
                    <StatusMark status={taskStatus.status} />
                    <h2 className="text-sm font-semibold capitalize text-gray-200">{taskStatus.status}</h2>
                  </div>
                  <p className="mt-1 font-mono text-xs text-blue-400">{taskStatus.scan_reference}</p>
                  <p className="mt-1 text-xs text-gray-500">{taskStatus.domain}</p>
                </div>
                <button
                  type="button"
                  onClick={() => void fetchStatus()}
                  className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh
                </button>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-[#21262d] bg-[#0d1117] p-4">
                  <p className="text-xl font-bold text-blue-400">{taskStatus.summary.discoveries || 0}</p>
                  <p className="mt-1 text-xs text-gray-500">Real discovered hosts</p>
                </div>
                <div className="rounded-lg border border-[#21262d] bg-[#0d1117] p-4">
                  <p className="text-xl font-bold text-red-400">{taskStatus.summary.vulnerabilities || 0}</p>
                  <p className="mt-1 text-xs text-gray-500">Real nuclei findings</p>
                </div>
              </div>

              {taskStatus.status === 'running' && (
                <div className="flex items-center gap-2 rounded-lg border border-blue-500/20 bg-blue-500/10 p-3 text-xs text-blue-300">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>
                    {taskStatus.current_tool
                      ? `${taskStatus.current_tool} is running`
                      : 'Scanner pipeline is running'}
                    {' · '}
                    {taskStatus.progress ?? 0}% · refreshes every three seconds.
                  </span>
                </div>
              )}
              {taskStatus.status === 'completed' && (
                <div className="flex items-center gap-2 rounded-lg border border-green-500/20 bg-green-500/10 p-3 text-xs text-green-300">
                  <CheckCircle2 className="h-4 w-4" />
                  Scan completed. The result tabs now show persisted tool output.
                </div>
              )}
              {taskStatus.status === 'failed' && (
                <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-300">
                  <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{taskStatus.error || 'The scanner failed without producing results.'}</span>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {tab === 'subdomains' && (
        <div className="space-y-3">
          {taskStatus && ['pending', 'running'].includes(taskStatus.status) && (
            <div className="flex items-center justify-between gap-3 rounded-lg border border-blue-500/20 bg-blue-500/10 px-4 py-3 text-xs text-blue-300">
              <span className="inline-flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                {taskStatus.current_tool
                  ? `${taskStatus.current_tool} is running`
                  : 'Preparing the scanner pipeline'}
              </span>
              <span>{taskStatus.progress ?? 0}% · live refresh every 3s</span>
            </div>
          )}
          <ResultTable
          title="Discovered subdomains"
          icon={Network}
          count={subdomains.length}
          onRefresh={() => void openResults('subdomains')}
          empty={
            taskStatus && ['pending', 'running'].includes(taskStatus.status)
              ? 'Subfinder is running. New subdomains will appear here automatically.'
              : 'No persisted subdomains from a real scan.'
          }
          headers={['Subdomain', 'IP addresses', 'Open ports', 'Nmap services', 'HTTP', 'TLS', 'Technologies']}
          rows={subdomains.map(item => [
            <code key="host" className="text-blue-400">{item.subdomain}</code>,
            <span key="ips" className="font-mono text-gray-300">{(item.ip_addresses || []).join(', ') || '—'}</span>,
            <span key="ports">{(item.open_ports || []).join(', ') || '—'}</span>,
            <span key="services" className="text-gray-300">
              {(item.services || []).map((service: any) => (
                `${service.port}/${service.name}` +
                `${service.product ? ` ${service.product}` : ''}` +
                `${service.version ? ` ${service.version}` : ''}`
              )).join(', ') || '—'}
            </span>,
            <span key="http" className={item.is_responsive ? 'text-green-400' : 'text-gray-600'}>
              {item.is_responsive ? item.response_status_code || 'Live' : 'Awaiting httpx'}
            </span>,
            <span key="tls" className={item.has_ssl ? 'text-green-400' : 'text-gray-600'}>
              {item.has_ssl ? 'Yes' : 'No'}
            </span>,
            <span key="tech">{(item.technologies || []).join(', ') || '—'}</span>,
          ])}
          />
        </div>
      )}

      {tab === 'ips' && (
        <ResultTable
          title="Resolved IP addresses"
          icon={Radio}
          count={ips.length}
          onRefresh={() => void openResults('ips')}
          empty="No real IP resolutions are stored for this domain."
          headers={['IP address', 'Subdomains', 'Host count']}
          rows={ips.map(item => [
            <code key="ip" className="text-green-400">{item.ip}</code>,
            <span key="hosts">{(item.subdomains || []).join(', ')}</span>,
            <span key="count">{item.subdomain_count}</span>,
          ])}
        />
      )}

      {tab === 'vulns' && (
        <ResultTable
          title="Nuclei vulnerability findings"
          icon={Bug}
          count={vulnerabilities.length}
          onRefresh={() => void openResults('vulns')}
          empty="No real nuclei findings are stored for this domain."
          headers={['CVE', 'Finding', 'Target', 'Severity', 'CVSS']}
          rows={vulnerabilities.map(item => [
            <code key="cve" className="text-blue-400">{item.cve_id || '—'}</code>,
            <span key="title" className="text-gray-200">{item.title}</span>,
            <code key="target" className="text-gray-400">{item.subdomain}:{item.port}</code>,
            <span key="severity" className={
              item.severity === 'Critical' ? 'text-red-400'
                : item.severity === 'High' ? 'text-orange-400'
                  : item.severity === 'Medium' ? 'text-yellow-400' : 'text-blue-400'
            }>
              {item.severity}
            </span>,
            <span key="cvss">{item.cvss_score ?? '—'}</span>,
          ])}
        />
      )}

      {tab === 'screenshots' && (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Camera className="h-4 w-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-gray-200">Gowitness screenshots</h2>
              <span className="text-xs text-blue-400">{screenshots.length}</span>
            </div>
            <button
              type="button"
              onClick={() => void openResults('screenshots')}
              className="inline-flex items-center gap-1.5 text-xs text-blue-400"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
          {screenshots.length === 0 ? (
            <EmptyResult message="No real screenshot files are stored for this domain." icon={Camera} />
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {screenshots.map(item => (
                <article key={item.id} className="overflow-hidden rounded-xl border border-[#30363d] bg-[#161b22]">
                  <img
                    src={`${API}${item.file_url}`}
                    alt={item.title || item.url}
                    className="h-44 w-full bg-[#0d1117] object-cover"
                  />
                  <div className="space-y-1 p-3">
                    <p className="truncate text-xs font-medium text-gray-200">{item.title || item.subdomain}</p>
                    <p className="truncate font-mono text-[11px] text-blue-400">{item.url}</p>
                    <p className="text-[11px] text-gray-500">HTTP {item.status_code || 'unknown'}</p>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {tab === 'enrich' && (
        <section className="space-y-4">
          <div className="rounded-xl border border-[#30363d] bg-[#161b22] p-5">
            <div className="mb-4 flex items-center gap-2">
              <Search className="h-4 w-4 text-blue-400" />
              <div>
                <h2 className="text-sm font-semibold text-gray-200">Factual IP metadata</h2>
                <p className="mt-0.5 text-xs text-gray-500">
                  Local classification and reverse DNS; reputation is never fabricated.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <input
                className="input"
                value={enrichIp}
                onChange={event => setEnrichIp(event.target.value)}
                onKeyDown={event => event.key === 'Enter' && void enrich()}
                placeholder="IPv4 or IPv6 address"
              />
              <button type="button" onClick={() => void enrich()} disabled={loading} className="btn-blue">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {enrichment && (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-[#30363d] bg-[#161b22] p-4">
                <p className="font-mono text-sm text-green-400">{enrichment.ip}</p>
                <p className="mt-1 text-xs text-gray-500">Reverse DNS: {enrichment.reverse_dns || 'Not found'}</p>
              </div>
              <div className="rounded-xl border border-[#30363d] bg-[#161b22] p-4 text-xs">
                {Object.entries(enrichment.classification || {}).map(([key, value]) => (
                  <div key={key} className="flex justify-between border-b border-[#21262d] py-1.5 last:border-0">
                    <span className="text-gray-500">{key.replace(/_/g, ' ')}</span>
                    <span className="text-gray-300">{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

function EmptyResult({ message, icon: Icon }: { message: string; icon: LucideIcon }) {
  return (
    <div className="rounded-xl border border-[#30363d] bg-[#161b22] py-16 text-center">
      <Icon className="mx-auto h-7 w-7 text-gray-600" />
      <p className="mt-3 text-sm text-gray-500">{message}</p>
    </div>
  )
}

function ResultTable({
  title,
  icon: Icon,
  count,
  onRefresh,
  empty,
  headers,
  rows,
}: {
  title: string
  icon: LucideIcon
  count: number
  onRefresh: () => void
  empty: string
  headers: string[]
  rows: React.ReactNode[][]
}) {
  return (
    <section className="overflow-hidden rounded-xl border border-[#30363d] bg-[#161b22]">
      <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-3">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-blue-400" />
          <h2 className="text-sm font-semibold text-gray-200">{title}</h2>
          <span className="text-xs text-blue-400">{count}</span>
        </div>
        <button type="button" onClick={onRefresh} className="inline-flex items-center gap-1.5 text-xs text-blue-400">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>
      {rows.length === 0 ? (
        <div className="py-16 text-center text-sm text-gray-500">{empty}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#21262d]">
                {headers.map(header => (
                  <th key={header} className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500">
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={rowIndex} className="border-b border-[#21262d] transition hover:bg-[#1c2128]">
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="px-4 py-3 text-gray-400">{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default function ReconPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <ReconContent />
      </AppLayout>
    </AuthProvider>
  )
}
