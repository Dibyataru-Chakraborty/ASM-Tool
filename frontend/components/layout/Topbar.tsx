'use client'

import { usePathname } from 'next/navigation'
import { Bell, Search, RefreshCw } from 'lucide-react'
import { useAuth } from '@/lib/auth'

const pageTitles: Record<string, string> = {
  '/dashboard':       'Dashboard',
  '/assets':          'Asset Inventory',
  '/scans':           'Scan Management',
  '/vulnerabilities': 'Vulnerabilities',
  '/alerts':          'Alerts',
  '/ai-analysis':     'AI Analysis',
  '/reports':         'Reports',
  '/settings':        'Settings',
}

export default function Topbar() {
  const pathname = usePathname()
  const { user } = useAuth()

  const title = Object.entries(pageTitles).find(([k]) => pathname.startsWith(k))?.[1] || 'ASM Platform'

  return (
    <header className="h-14 border-b border-[#21262d] bg-[#0d1117] flex items-center px-6 gap-4">
      <h1 className="text-sm font-semibold text-gray-200 flex-1">{title}</h1>

      {/* Search */}
      <div className="relative hidden md:block">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
        <input
          placeholder="Search assets, CVEs..."
          className="input pl-8 py-1.5 text-xs w-56 h-8"
        />
      </div>

      {/* Refresh */}
      <button
        onClick={() => window.location.reload()}
        className="p-1.5 text-gray-500 hover:text-gray-300 hover:bg-[#21262d] rounded-lg transition"
        title="Refresh"
      >
        <RefreshCw className="w-4 h-4" />
      </button>

      {/* Notifications */}
      <button className="relative p-1.5 text-gray-500 hover:text-gray-300 hover:bg-[#21262d] rounded-lg transition">
        <Bell className="w-4 h-4" />
        <span className="absolute top-0.5 right-0.5 w-2 h-2 bg-red-500 rounded-full" />
      </button>

      {/* Avatar */}
      <div className="w-7 h-7 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-xs font-bold text-blue-400">
        {user?.full_name?.[0]?.toUpperCase() || 'U'}
      </div>
    </header>
  )
}
