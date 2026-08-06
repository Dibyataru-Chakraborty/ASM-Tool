'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  Eye,
  Network,
  Radar,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from 'lucide-react'

import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider, useAuth } from '@/lib/auth'
import asm from '@/lib/api'

const SEV_CLS: Record<string,string> = {
  critical:'text-red-400', high:'text-orange-400', medium:'text-yellow-400', low:'text-blue-400', info:'text-gray-400',
}

function DashboardContent() {
  const { user } = useAuth()
  const [overview, setOverview] = useState<any>(null)
  const [jobs, setJobs] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    const [asmState, legacy] = await Promise.allSettled([
      asm.getAttackSurfaceOverview(),
      asm.getDashboard(),
    ])
    if (asmState.status === 'fulfilled') setOverview(asmState.value)
    if (legacy.status === 'fulfilled') setJobs(legacy.value)
    setLoading(false)
  }

  useEffect(() => {
    load()
    const timer = window.setInterval(load, 8000)
    return () => window.clearInterval(timer)
  }, [])

  if (loading) {
    return <div className="flex h-64 items-center justify-center"><Radar className="h-8 w-8 animate-pulse text-blue-400" /></div>
  }

  const running = jobs?.running_scans || []
  const inventoryByType = overview?.inventory_by_type || {}
  const exposureBySeverity = overview?.exposures_by_severity || {}
  const recentChanges = overview?.recent_changes || []
  const topRisk = overview?.top_risk_assets || []

  const cards = [
    { label:'Attack Surface Assets', value:overview?.total_assets || 0, hint:user?.organization_name || 'Current organization', icon:Boxes, href:'/attack-surface' },
    { label:'New Assets', value:overview?.new_assets || 0, hint:'Discovered since prior observation', icon:Sparkles, href:'/attack-surface?status=new' },
    { label:'Unknown / Review', value:overview?.unknown_assets || 0, hint:'Ownership requires investigation', icon:Eye, href:'/attack-surface?ownership_status=requires_investigation' },
    { label:'Exposed Assets', value:overview?.exposed_assets || 0, hint:`${overview?.critical_exposures || 0} critical exposures`, icon:ShieldAlert, href:'/exposures' },
    { label:'Changes (24h)', value:overview?.changes_24h || 0, hint:'New, changed, removed or resolved', icon:Activity, href:'/changes' },
    { label:'30d Surface Growth', value:`${overview?.attack_surface_growth_30d || 0}%`, hint:'Based on first-seen inventory', icon:TrendingUp, href:'/attack-surface' },
  ]

  return (
    <AppLayout>
      <div className="space-y-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-lg font-bold text-gray-100">Attack Surface Overview</h1>
            <p className="mt-1 text-xs text-gray-500">Persistent external asset inventory, exposure context and change monitoring.</p>
          </div>
          <div className="flex gap-2">
            <Link href="/assets" className="btn-gray text-xs">Company Domains & Seeds</Link>
            <Link href="/recon" className="btn-blue text-xs">Run Discovery</Link>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
          {cards.map(({label,value,hint,icon:Icon,href}) => (
            <Link key={label} href={href} className="card p-4 transition hover:border-blue-500/40">
              <div className="mb-3 flex items-center justify-between">
                <Icon className="h-5 w-5 text-blue-400" />
                <ArrowUpRight className="h-3.5 w-3.5 text-gray-600" />
              </div>
              <p className="text-2xl font-bold text-gray-100">{value}</p>
              <p className="mt-1 text-xs font-medium text-gray-400">{label}</p>
              <p className="mt-1 text-[10px] leading-4 text-gray-600">{hint}</p>
            </Link>
          ))}
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <div className="card p-4">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-200">Asset Distribution</p>
                <p className="text-xs text-gray-600">Current active attack surface by type</p>
              </div>
              <Network className="h-5 w-5 text-cyan-400" />
            </div>
            {Object.keys(inventoryByType).length === 0 ? (
              <div className="py-10 text-center text-xs text-gray-600">Run discovery to build the persistent inventory.</div>
            ) : (
              <div className="space-y-3">
                {Object.entries(inventoryByType).sort((a:any,b:any)=>b[1]-a[1]).map(([type,count]:any) => {
                  const max = Math.max(...Object.values(inventoryByType).map((v:any)=>Number(v)), 1)
                  return (
                    <div key={type}>
                      <div className="mb-1 flex items-center justify-between text-xs">
                        <span className="capitalize text-gray-400">{type.replaceAll('_',' ')}</span>
                        <span className="font-mono text-gray-300">{count}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-[#21262d]">
                        <div className="h-full rounded-full bg-blue-500" style={{width:`${Math.max(4,(Number(count)/max)*100)}%`}} />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          <div className="card p-4">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-200">Exposure Priorities</p>
                <p className="text-xs text-gray-600">Open exposures, prioritized beyond CVSS alone</p>
              </div>
              <AlertTriangle className="h-5 w-5 text-orange-400" />
            </div>
            <div className="grid grid-cols-5 gap-2">
              {['critical','high','medium','low','info'].map(sev => (
                <Link href={`/exposures?severity=${sev}`} key={sev} className="rounded-lg border border-[#30363d] p-3 text-center hover:border-blue-500/40">
                  <p className={`text-xl font-bold ${SEV_CLS[sev]}`}>{exposureBySeverity[sev] || 0}</p>
                  <p className="mt-1 text-[10px] capitalize text-gray-600">{sev}</p>
                </Link>
              ))}
            </div>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#21262d] px-4 py-3">
              <div>
                <p className="text-sm font-semibold text-gray-200">Recent Attack Surface Changes</p>
                <p className="text-[10px] text-gray-600">What changed between monitoring cycles</p>
              </div>
              <Link href="/changes" className="text-xs text-blue-400">View all</Link>
            </div>
            {recentChanges.length === 0 ? (
              <div className="py-10 text-center text-xs text-gray-600">No attack-surface changes recorded yet.</div>
            ) : (
              <div className="divide-y divide-[#21262d]">
                {recentChanges.map((change:any) => (
                  <div key={change.id} className="flex items-start gap-3 px-4 py-3">
                    <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${change.severity==='critical'?'bg-red-400':change.severity==='high'?'bg-orange-400':change.severity==='medium'?'bg-yellow-400':'bg-blue-400'}`} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium text-gray-300">{change.title}</p>
                      <p className="mt-1 text-[10px] text-gray-600">{change.organization_name} · {new Date(change.detected_at).toLocaleString()}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#21262d] px-4 py-3">
              <div>
                <p className="text-sm font-semibold text-gray-200">Top Risk Assets</p>
                <p className="text-[10px] text-gray-600">Internet exposure + severity + business criticality</p>
              </div>
              <Link href="/attack-surface" className="text-xs text-blue-400">Inventory</Link>
            </div>
            {topRisk.length === 0 ? (
              <div className="py-10 text-center text-xs text-gray-600">No prioritized assets yet.</div>
            ) : (
              <div className="divide-y divide-[#21262d]">
                {topRisk.map((asset:any) => (
                  <Link href={`/attack-surface/${asset.id}`} key={asset.id} className="flex items-center gap-3 px-4 py-3 hover:bg-[#1c2128]">
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-xs text-gray-300">{asset.display_name || asset.value}</p>
                      <p className="mt-1 text-[10px] capitalize text-gray-600">{asset.asset_type.replaceAll('_',' ')} · {asset.organization_name}</p>
                    </div>
                    <div className="text-right">
                      <p className={`${asset.risk_score >= 80 ? 'text-red-400' : asset.risk_score >= 60 ? 'text-orange-400' : asset.risk_score >= 40 ? 'text-yellow-400' : 'text-blue-400'} text-sm font-bold`}>{asset.risk_score}</p>
                      <p className="text-[9px] text-gray-600">ASM risk</p>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {running.length > 0 && (
          <div className="card overflow-hidden">
            <div className="border-b border-[#21262d] px-4 py-3">
              <p className="text-sm font-semibold text-gray-200">Active Discovery Cycles</p>
            </div>
            <div className="divide-y divide-[#21262d]">
              {running.map((job:any) => (
                <div key={job.id} className="px-4 py-3">
                  <div className="mb-2 flex items-center justify-between text-xs">
                    <span className="font-mono text-gray-300">{job.asset_target}</span>
                    <span className="text-blue-400">{job.progress || 0}%</span>
                  </div>
                  <div className="h-1 overflow-hidden rounded-full bg-[#21262d]"><div className="h-full bg-blue-500" style={{width:`${job.progress || 0}%`}} /></div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  )
}

export default function Dashboard() {
  return <AuthProvider><DashboardContent /></AuthProvider>
}
