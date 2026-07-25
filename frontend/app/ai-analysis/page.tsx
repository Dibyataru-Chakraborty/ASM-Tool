'use client'

import { useState, useEffect } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import api from '@/lib/api'
import { Spinner, ErrorState } from '@/components/ui'
import { Brain, Zap, FileText, List, CheckCircle, AlertCircle } from 'lucide-react'

const PROVIDERS = [
  { id: 'claude',  name: 'Claude',         icon: '🟣', desc: 'Anthropic — Best for detailed analysis' },
  { id: 'openai',  name: 'GPT-4',          icon: '🟢', desc: 'OpenAI — Fast and reliable' },
  { id: 'gemini',  name: 'Gemini Pro',     icon: '🔵', desc: 'Google — Excellent reasoning' },
  { id: 'all',     name: 'All Providers',  icon: '⚡', desc: 'Compare results from all AI providers' },
]

const TASKS = [
  { id: 'analyze',    icon: Brain,    label: 'Vulnerability Analysis',   desc: 'Deep analysis of a specific CVE' },
  { id: 'prioritize', icon: List,     label: 'Prioritize Vulns',         desc: 'AI-ranked remediation order' },
  { id: 'report',     icon: FileText, label: 'Executive Report',         desc: 'Business-ready risk summary' },
  { id: 'remediate',  icon: Zap,      label: 'Remediation Steps',        desc: 'Step-by-step fix instructions' },
]

function AIAnalysisContent() {
  const [providers, setProviders] = useState<any>(null)
  const [selectedProvider, setSelectedProvider] = useState('claude')
  const [selectedTask, setSelectedTask] = useState('analyze')
  const [vulnId, setVulnId] = useState('')
  const [assetId, setAssetId] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.getAIProviders().then(setProviders).catch(() => {})
  }, [])

  const handleRun = async () => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      let res: any
      if (selectedTask === 'analyze' && vulnId) {
        res = await api.analyzeVulnerability(vulnId, selectedProvider)
      } else if (selectedTask === 'prioritize' && assetId) {
        res = await api.prioritizeVulnerabilities(assetId)
      } else if (selectedTask === 'report' && assetId) {
        res = await api.generateAIReport(assetId)
      } else if (selectedTask === 'remediate' && vulnId) {
        res = await api.getRemediationSteps(vulnId)
      } else {
        setError('Please fill in the required field for the selected task.')
        setLoading(false)
        return
      }
      setResult(res)
    } catch (e: any) {
      setError(e.response?.data?.detail || 'AI analysis failed. Ensure your API key is configured in backend/.env')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-base font-semibold text-gray-100 flex items-center gap-2">
          <Brain className="w-5 h-5 text-blue-400" /> AI-Powered Analysis
        </h1>
        <p className="text-xs text-gray-500 mt-0.5">
          Use Claude, OpenAI, or Gemini to analyze vulnerabilities and generate insights
        </p>
      </div>

      {/* Provider Status */}
      {providers && (
        <div className="card p-4">
          <p className="text-xs font-medium text-gray-400 mb-3">Available AI Providers</p>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(providers.providers).map(([id, p]: [string, any]) => (
              <div key={id} className={`p-3 rounded-lg border text-xs ${p.available
                ? 'bg-green-500/5 border-green-500/20'
                : 'bg-[#0d1117] border-[#30363d]'}`}>
                <div className="flex items-center gap-2 mb-1">
                  {p.available
                    ? <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                    : <AlertCircle className="w-3.5 h-3.5 text-gray-500" />}
                  <span className={p.available ? 'text-gray-200' : 'text-gray-500'}>{p.name}</span>
                </div>
                <p className="text-gray-500 text-[10px]">{p.available ? 'API key configured' : 'No API key'}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Configuration Panel */}
        <div className="lg:col-span-1 space-y-4">
          {/* Task */}
          <div className="card p-4">
            <p className="text-xs font-medium text-gray-400 mb-3">1. Select Task</p>
            <div className="space-y-2">
              {TASKS.map(t => (
                <button key={t.id} onClick={() => setSelectedTask(t.id)}
                  className={`w-full flex items-start gap-3 p-3 rounded-lg border text-left transition ${
                    selectedTask === t.id
                      ? 'bg-blue-500/10 border-blue-500/30 text-blue-300'
                      : 'bg-[#0d1117] border-[#30363d] text-gray-400 hover:border-gray-500'
                  }`}>
                  <t.icon className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-medium">{t.label}</p>
                    <p className="text-[10px] opacity-70 mt-0.5">{t.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Provider */}
          <div className="card p-4">
            <p className="text-xs font-medium text-gray-400 mb-3">2. Select AI Provider</p>
            <div className="space-y-1.5">
              {PROVIDERS.map(p => (
                <button key={p.id} onClick={() => setSelectedProvider(p.id)}
                  className={`w-full flex items-center gap-2.5 p-2.5 rounded-lg border text-left transition ${
                    selectedProvider === p.id
                      ? 'bg-blue-500/10 border-blue-500/30'
                      : 'bg-[#0d1117] border-[#30363d] hover:border-gray-500'
                  }`}>
                  <span>{p.icon}</span>
                  <div>
                    <p className="text-xs font-medium text-gray-200">{p.name}</p>
                    <p className="text-[10px] text-gray-500">{p.desc}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Inputs */}
          <div className="card p-4 space-y-3">
            <p className="text-xs font-medium text-gray-400">3. Enter Details</p>
            {(selectedTask === 'analyze' || selectedTask === 'remediate') && (
              <div>
                <label className="block text-xs text-gray-500 mb-1">Vulnerability ID</label>
                <input className="input text-xs" placeholder="vuln-uuid-here"
                  value={vulnId} onChange={e => setVulnId(e.target.value)} />
              </div>
            )}
            {(selectedTask === 'prioritize' || selectedTask === 'report') && (
              <div>
                <label className="block text-xs text-gray-500 mb-1">Asset ID</label>
                <input className="input text-xs" placeholder="asset-uuid-here"
                  value={assetId} onChange={e => setAssetId(e.target.value)} />
              </div>
            )}
            <button
              onClick={handleRun}
              disabled={loading}
              className="btn-primary w-full text-sm flex items-center justify-center gap-2"
            >
              {loading ? <><Spinner size="sm" /> Analyzing...</> : <><Brain className="w-4 h-4" /> Run Analysis</>}
            </button>
          </div>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 card p-5">
          <p className="text-xs font-medium text-gray-400 mb-4">Analysis Result</p>

          {error && <ErrorState message={error} />}

          {!result && !error && !loading && (
            <div className="flex flex-col items-center justify-center py-20 text-center gap-3">
              <Brain className="w-10 h-10 text-gray-600" />
              <p className="text-sm text-gray-500">Configure and run an analysis to see AI insights here</p>
            </div>
          )}

          {loading && (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <Spinner size="lg" />
              <p className="text-sm text-gray-500">AI is analyzing... this may take a moment</p>
            </div>
          )}

          {result && !loading && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-xs text-green-400">
                <CheckCircle className="w-3.5 h-3.5" />
                Analysis complete · Provider: <span className="font-medium capitalize">{result.provider || selectedProvider}</span>
              </div>

              {/* Text analysis */}
              {result.analysis && (
                <div className="prose prose-invert max-w-none">
                  <div className="p-4 rounded-lg bg-[#0d1117] border border-[#30363d] text-xs text-gray-300 leading-relaxed whitespace-pre-wrap max-h-96 overflow-y-auto">
                    {result.analysis}
                  </div>
                </div>
              )}

              {/* Prioritization */}
              {result.prioritization && (
                <div className="p-4 rounded-lg bg-[#0d1117] border border-[#30363d] text-xs text-gray-300 leading-relaxed whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {result.prioritization}
                </div>
              )}

              {/* Report */}
              {result.report && (
                <div className="p-4 rounded-lg bg-[#0d1117] border border-[#30363d] text-xs text-gray-300 leading-relaxed whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {result.report}
                </div>
              )}

              {/* Remediation Steps */}
              {result.remediation_steps && (
                <ol className="space-y-2">
                  {result.remediation_steps.map((step: string, i: number) => (
                    <li key={i} className="flex gap-3 text-xs text-gray-300 p-3 rounded-lg bg-[#0d1117] border border-[#30363d]">
                      <span className="text-blue-400 font-bold shrink-0">{i + 1}.</span>
                      {step}
                    </li>
                  ))}
                </ol>
              )}

              {/* Multi-provider results */}
              {typeof result === 'object' && !result.analysis && !result.report && !result.remediation_steps && (
                <div className="space-y-3">
                  {Object.entries(result).map(([provider, data]: [string, any]) => (
                    <div key={provider} className="p-3 rounded-lg border border-[#30363d] bg-[#0d1117]">
                      <p className="text-xs font-medium text-blue-400 mb-2 capitalize">{provider}</p>
                      {data.error
                        ? <p className="text-xs text-red-400">{data.error}</p>
                        : <p className="text-xs text-gray-300 leading-relaxed">{data.analysis}</p>
                      }
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AIAnalysisPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <AIAnalysisContent />
      </AppLayout>
    </AuthProvider>
  )
}
