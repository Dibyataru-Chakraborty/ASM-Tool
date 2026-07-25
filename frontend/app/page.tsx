'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import Link from 'next/link'
import { Shield, Server, Bug, Brain, FileText, Radar } from 'lucide-react'

export default function Home() {
  const { isAuthenticated, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && isAuthenticated) router.push('/dashboard')
  }, [isAuthenticated, loading, router])

  const features = [
    { icon: Server,   label: 'Asset Discovery',         desc: 'Domains, subdomains, ports' },
    { icon: Bug,      label: 'Vulnerability Scanning',  desc: 'CVE database integration' },
    { icon: Brain,    label: 'AI-Powered Analysis',     desc: 'Claude, GPT-4, Gemini' },
    { icon: Radar,    label: 'Continuous Monitoring',   desc: 'Real-time alerts & scans' },
    { icon: FileText, label: 'Automated Reporting',     desc: 'PDF, Excel, Executive' },
    { icon: Shield,   label: 'Threat Intelligence',     desc: 'VirusTotal, Shodan, Censys' },
  ]

  return (
    <div className="min-h-screen bg-[#0d1117] flex flex-col items-center justify-center px-4 py-16">
      <div className="max-w-3xl w-full text-center space-y-10">
        {/* Hero */}
        <div className="space-y-4">
          <div className="inline-flex p-4 bg-blue-500/10 border border-blue-500/20 rounded-2xl mb-2">
            <Shield className="w-10 h-10 text-blue-400" />
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-300 bg-clip-text text-transparent">
            ASM Platform
          </h1>
          <p className="text-gray-400 text-lg max-w-xl mx-auto">
            Enterprise Attack Surface Management with AI-powered vulnerability analysis
          </p>
          <div className="flex gap-4 justify-center pt-2">
            <Link href="/login"    className="btn-primary px-8 py-2.5">Sign In</Link>
            <Link href="/register" className="btn-secondary px-8 py-2.5">Register</Link>
          </div>
        </div>

        {/* Features */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-left">
          {features.map(({ icon: Icon, label, desc }) => (
            <div key={label} className="card p-4 space-y-2">
              <div className="p-2 w-fit bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <Icon className="w-4 h-4 text-blue-400" />
              </div>
              <p className="text-sm font-medium text-gray-200">{label}</p>
              <p className="text-xs text-gray-500">{desc}</p>
            </div>
          ))}
        </div>

        {/* Stats */}
        <div className="flex justify-center gap-12 pt-2">
          {[['10', 'Phases'], ['50+', 'API Endpoints'], ['20', 'DB Tables'], ['4', 'AI Models']].map(([v, l]) => (
            <div key={l} className="text-center">
              <p className="text-2xl font-bold text-blue-400">{v}</p>
              <p className="text-xs text-gray-500">{l}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
