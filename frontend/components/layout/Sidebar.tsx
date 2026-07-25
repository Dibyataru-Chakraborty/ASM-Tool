'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import {
  Shield, LayoutDashboard, Server, Radar, Bug, AlertTriangle,
  FileText, Settings, LogOut, ChevronRight, Brain, Globe, Zap} from 'lucide-react'

const navItems = [
  { href: '/dashboard',         icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/assets',            icon: Server,          label: 'Assets' },
  { href: '/scans',             icon: Radar,           label: 'Scans' },
  { href: '/vulnerabilities',   icon: Bug,             label: 'Vulnerabilities' },
  { href: '/alerts',            icon: AlertTriangle,   label: 'Alerts' },
  { href: '/recon',             icon: Globe,           label: 'Recon Engine' },
  { href: '/shannon',           icon: Zap,             label: 'AI Pentest' },
  { href: '/ai-analysis',       icon: Brain,           label: 'AI Analysis' },
  { href: '/reports',           icon: FileText,        label: 'Reports' },
  { href: '/settings',          icon: Settings,        label: 'Settings' },
]

export default function Sidebar() {
  const pathname = usePathname()
  const { user, logout } = useAuth()

  return (
    <aside className="fixed left-0 top-0 h-screen w-56 bg-[#0d1117] border-r border-[#21262d] flex flex-col z-50">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-[#21262d]">
        <Link href="/dashboard" className="flex items-center gap-2.5">
          <div className="p-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <div className="text-sm font-bold text-gray-100">ASM Platform</div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Enterprise</div>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 overflow-y-auto space-y-0.5">
        {navItems.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link key={href} href={href} className={active ? 'sidebar-item-active' : 'sidebar-item'}>
              <Icon className="w-4 h-4 shrink-0" />
              <span className="text-sm font-medium">{label}</span>
              {active && <ChevronRight className="w-3.5 h-3.5 ml-auto opacity-60" />}
            </Link>
          )
        })}
      </nav>

      {/* User section */}
      <div className="px-3 pb-4 border-t border-[#21262d] pt-3">
        <div className="flex items-center gap-2.5 px-3 py-2 mb-1">
          <div className="w-7 h-7 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-xs font-bold text-blue-400 shrink-0">
            {user?.full_name?.[0]?.toUpperCase() || 'U'}
          </div>
          <div className="min-w-0">
            <div className="text-xs font-medium text-gray-200 truncate">{user?.full_name}</div>
            <div className="text-[10px] text-gray-500 capitalize">{user?.role}</div>
          </div>
        </div>
        <button
          onClick={logout}
          className="sidebar-item w-full text-red-400 hover:text-red-300 hover:bg-red-500/10"
        >
          <LogOut className="w-4 h-4" />
          <span className="text-sm font-medium">Logout</span>
        </button>
      </div>
    </aside>
  )
}
