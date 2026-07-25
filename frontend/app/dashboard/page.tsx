'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import axios from 'axios'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const H = () => ({ Authorization: `Bearer ${typeof window !== 'undefined' ? localStorage.getItem('access_token') : ''}` })

const CARDS = [
  { label: 'Assets',           href: '/assets',         emoji: '🖥️',  color: 'from-blue-600/20 to-blue-800/10  border-blue-500/20' },
  { label: 'Recon Engine',     href: '/recon',          emoji: '🔭',  color: 'from-purple-600/20 to-purple-800/10 border-purple-500/20' },
  { label: 'AI Pentest',       href: '/shannon',        emoji: '🤖',  color: 'from-orange-600/20 to-orange-800/10 border-orange-500/20' },
  { label: 'Vulnerabilities',  href: '/vulnerabilities', emoji: '🐛', color: 'from-red-600/20 to-red-800/10 border-red-500/20' },
  { label: 'Alerts',           href: '/alerts',         emoji: '🔔',  color: 'from-yellow-600/20 to-yellow-800/10 border-yellow-500/20' },
  { label: 'AI Analysis',      href: '/ai-analysis',    emoji: '🧠',  color: 'from-cyan-600/20 to-cyan-800/10 border-cyan-500/20' },
  { label: 'Reports',          href: '/reports',        emoji: '📄',  color: 'from-green-600/20 to-green-800/10 border-green-500/20' },
  { label: 'Settings',         href: '/settings',       emoji: '⚙️',  color: 'from-gray-600/20 to-gray-800/10 border-gray-500/20' },
]

export default function DashboardPage() {
  const [stats, setStats] = useState({ assets: 0, vulns: 0, alerts: 0, scans: 0 })
  const [health, setHealth] = useState<'ok' | 'down' | 'loading'>('loading')

  useEffect(() => {
    axios.get(`${API}/health`).then(() => setHealth('ok')).catch(() => setHealth('down'))
    axios.get(`${API}/api/v1/assets`, { headers: H() })
      .then(r => setStats(s => ({ ...s, assets: r.data.total || 0 }))).catch(() => {})
    axios.get(`${API}/api/v1/vulnerabilities`, { headers: H() })
      .then(r => setStats(s => ({ ...s, vulns: r.data.total || 0 }))).catch(() => {})
    axios.get(`${API}/api/v1/alerts`, { headers: H() })
      .then(r => setStats(s => ({ ...s, alerts: r.data.total || 0 }))).catch(() => {})
    axios.get(`${API}/api/v1/dashboard/scan-statistics`, { headers: H() })
      .then(r => setStats(s => ({ ...s, scans: r.data.total || 0 }))).catch(() => {})
  }, [])

  return (
    <div className="space-y-6">
      {/* Welcome */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">Attack Surface Management Platform</p>
        </div>
        <div className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border ${
          health === 'ok'      ? 'text-green-400 bg-green-500/10 border-green-500/20' :
          health === 'down'    ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                                 'text-gray-500 bg-gray-500/10 border-gray-500/20'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full ${health === 'ok' ? 'bg-green-400' : health === 'down' ? 'bg-red-400' : 'bg-gray-500'}`} />
          {health === 'ok' ? 'API Online' : health === 'down' ? 'API Offline' : 'Checking...'}
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Assets',          value: stats.assets, emoji: '🖥️' },
          { label: 'Vulnerabilities', value: stats.vulns,  emoji: '🐛' },
          { label: 'Active Alerts',   value: stats.alerts, emoji: '🔔' },
          { label: 'Total Scans',     value: stats.scans,  emoji: '🔭' },
        ].map(s => (
          <div key={s.label} className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
            <div className="text-2xl mb-1">{s.emoji}</div>
            <div className="text-2xl font-bold text-gray-100">{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Navigation cards */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 mb-3">Quick Access</h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {CARDS.map(c => (
            <Link key={c.href} href={c.href}
              className={`bg-gradient-to-br ${c.color} border rounded-xl p-4 hover:scale-[1.02] transition-all duration-200 block`}>
              <div className="text-2xl mb-2">{c.emoji}</div>
              <div className="text-sm font-semibold text-gray-200">{c.label}</div>
            </Link>
          ))}
        </div>
      </div>

      {/* Quick start */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-200 mb-3">🚀 Quick Start</h2>
        <div className="space-y-2 text-sm text-gray-400">
          <div className="flex items-start gap-2">
            <span className="text-blue-400 font-bold shrink-0">1.</span>
            <span>Go to <Link href="/assets" className="text-blue-400 hover:underline">Assets</Link> → Add your domain (e.g. example.com)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-blue-400 font-bold shrink-0">2.</span>
            <span>Go to <Link href="/recon" className="text-blue-400 hover:underline">Recon Engine</Link> → Enter domain ID → Start Full Recon</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-blue-400 font-bold shrink-0">3.</span>
            <span>Go to <Link href="/shannon" className="text-blue-400 hover:underline">AI Pentest</Link> → Enter target URL → Start Shannon scan</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-blue-400 font-bold shrink-0">4.</span>
            <span>Check <Link href="/vulnerabilities" className="text-blue-400 hover:underline">Vulnerabilities</Link> and use AI Analysis for remediation</span>
          </div>
        </div>
      </div>
    </div>
  )
}
