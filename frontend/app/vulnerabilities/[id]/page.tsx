'use client'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useState, useEffect, use } from 'react'
import Link from 'next/link'
import asm from '@/lib/api'

const SEV_CLS: Record<string,string> = {critical:'tag-crit',high:'tag-high',medium:'tag-med',low:'tag-low',info:'tag-info'}

function VulnDetailPageInner({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const [vuln, setVuln]     = useState<any>(null)
  const [aiAnalysis, setAi] = useState('')
  const [aiLoading, setAiL] = useState(false)

  useEffect(() => { asm.getVuln(id).then(setVuln).catch(()=>{}) }, [id])

  const runAI = async () => {
    if (!vuln) return
    setAiL(true); setAi('')
    try {
      const r = await import('@/lib/api').then(m => m.client.post('/api/v1/recon/ai/analyze-vulnerability', {
        cve_id: vuln.cve_id, title: vuln.title,
        description: vuln.description, severity: vuln.severity, cvss_score: vuln.cvss_score,
      }))
      setAi(r.data.analysis || 'No analysis returned')
    } catch(e:any) { setAi(e.response?.data?.detail || 'AI analysis failed') }
    setAiL(false)
  }

  if (!vuln) return <div className="flex items-center justify-center h-64"><div className="animate-spin text-4xl">🐛</div></div>

  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <Link href="/vulnerabilities" className="hover:text-gray-300">← Vulnerabilities</Link>
        <span>/</span>
        <span className="text-gray-400 truncate">{vuln.title}</span>
      </div>

      {/* Title card */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1">
            <h1 className="text-base font-bold text-gray-100 mb-2">{vuln.title}</h1>
            <div className="flex flex-wrap gap-2">
              <span className={SEV_CLS[vuln.severity]||'tag-info'}>{vuln.severity}</span>
              {vuln.cvss_score && <span className="tag-info">CVSS {vuln.cvss_score.toFixed(1)}</span>}
              {vuln.cve_id && <span className="text-xs font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">{vuln.cve_id}</span>}
              {vuln.cwe_id && <span className="text-xs font-mono text-gray-400 bg-gray-500/10 border border-gray-500/20 px-2 py-0.5 rounded">{vuln.cwe_id}</span>}
            </div>
          </div>
          {vuln.is_false_positive && <span className="text-xs text-orange-400 bg-orange-500/10 border border-orange-500/20 px-2 py-1 rounded">False Positive</span>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Left col */}
        <div className="space-y-4">
          {/* Location */}
          <div className="card p-4 space-y-2">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Location</p>
            {vuln.host && <div><p className="text-[10px] text-gray-500">Host</p><p className="text-xs font-mono text-gray-300">{vuln.host}</p></div>}
            {vuln.url  && <div><p className="text-[10px] text-gray-500">URL</p><p className="text-xs font-mono text-blue-400 break-all">{vuln.url}</p></div>}
            {vuln.port && <div><p className="text-[10px] text-gray-500">Port</p><p className="text-xs font-mono text-gray-300">{vuln.port}</p></div>}
            {vuln.parameter && <div><p className="text-[10px] text-gray-500">Parameter</p><p className="text-xs font-mono text-yellow-400">{vuln.parameter}</p></div>}
          </div>

          {/* Description */}
          {vuln.description && (
            <div className="card p-4">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Description</p>
              <p className="text-xs text-gray-300 leading-relaxed">{vuln.description}</p>
            </div>
          )}

          {/* References */}
          {vuln.references?.length > 0 && (
            <div className="card p-4">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">References</p>
              <div className="space-y-1">
                {vuln.references.slice(0,5).map((r:string,i:number)=>(
                  <a key={i} href={r} target="_blank" rel="noreferrer" className="block text-xs text-blue-400 hover:underline truncate">{r}</a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right col */}
        <div className="space-y-4">
          {/* HTTP Request */}
          {vuln.http_request && (
            <div className="card overflow-hidden">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide px-4 py-2.5 border-b border-[#21262d]">HTTP Request</p>
              <pre className="text-[10px] text-gray-300 font-mono p-3 overflow-auto max-h-40 leading-relaxed">{vuln.http_request}</pre>
            </div>
          )}

          {/* Proof of Concept */}
          {vuln.proof_of_concept && (
            <div className="card overflow-hidden">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide px-4 py-2.5 border-b border-[#21262d]">Proof of Concept</p>
              <pre className="text-[10px] text-green-400 font-mono p-3 overflow-auto max-h-32">{vuln.proof_of_concept}</pre>
            </div>
          )}

          {/* Raw evidence */}
          {vuln.raw_evidence && (
            <div className="card overflow-hidden">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide px-4 py-2.5 border-b border-[#21262d]">Evidence</p>
              <pre className="text-[10px] text-gray-400 font-mono p-3 overflow-auto max-h-32">{vuln.raw_evidence}</pre>
            </div>
          )}

          {/* Recommendation */}
          {vuln.recommendation && (
            <div className="card p-4 bg-green-500/5 border-green-500/20">
              <p className="text-xs font-semibold text-green-400 mb-2">🛠 Recommendation</p>
              <p className="text-xs text-gray-300 leading-relaxed">{vuln.recommendation}</p>
            </div>
          )}
        </div>
      </div>

      {/* AI Analysis */}
      <div className="card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">AI Analysis</p>
          <button onClick={runAI} disabled={aiLoading} className="btn-blue text-xs">
            {aiLoading ? '⏳ Analyzing…' : '🧠 Analyze with Gemini'}
          </button>
        </div>
        <div className="bg-[#0d1117] border border-[#30363d] rounded-lg p-3 min-h-[80px]">
          {aiLoading ? (
            <p className="text-xs text-gray-500 animate-pulse">Gemini is analyzing this vulnerability…</p>
          ) : aiAnalysis ? (
            <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{aiAnalysis}</p>
          ) : (
            <p className="text-xs text-gray-600">Click "Analyze with Gemini" to get AI-powered analysis and remediation steps</p>
          )}
        </div>
      </div>

      {/* Screenshots */}
      {vuln.screenshots?.length > 0 && (
        <div className="card p-4">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Screenshots</p>
          <div className="grid grid-cols-2 gap-3">
            {vuln.screenshots.map((s:any)=>(
              <div key={s.id} className="bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden">
                <img src={`/screenshots/${s.file_path?.split('/').pop()}`} alt={s.url} className="w-full h-32 object-cover" />
                <p className="text-[10px] text-gray-500 px-2 py-1 truncate">{s.url}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function VulnDetailPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <AuthProvider>
      <AppLayout>
        <VulnDetailPageInner params={params} />
      </AppLayout>
    </AuthProvider>
  )
}
