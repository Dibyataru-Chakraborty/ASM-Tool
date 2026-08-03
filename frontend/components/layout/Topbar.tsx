'use client'
import { usePathname } from 'next/navigation'
import {
  Bot,
  Bug,
  CalendarClock,
  FileText,
  Globe2,
  History,
  LayoutDashboard,
  Moon,
  Server,
  Settings,
  Shield,
  Sun,
  type LucideIcon,
} from 'lucide-react'
import { useTheme } from '@/lib/theme'

const TITLES: Record<string, { label: string; icon: LucideIcon }> = {
  '/dashboard':       { label: 'Dashboard',            icon: LayoutDashboard },
  '/assets':          { label: 'Assets',               icon: Server },
  '/scheduler':       { label: 'Scan Scheduler',       icon: CalendarClock },
  '/scans':           { label: 'Scan History',         icon: History },
  '/recon':           { label: 'Recon Engine',         icon: Globe2 },
  '/shannon':         { label: 'AI Pentest (Shannon)', icon: Bot },
  '/vulnerabilities': { label: 'Vulnerabilities',      icon: Bug },
  '/reports':         { label: 'Reports',              icon: FileText },
  '/settings':        { label: 'Settings',             icon: Settings },
}

export default function Topbar() {
  const path = usePathname()
  const { theme, toggleTheme } = useTheme()
  const title = Object.entries(TITLES).find(([k]) => path === k || path.startsWith(k + '/'))?.[1]
    || { label: 'ASM Platform', icon: Shield }
  const Icon = title.icon

  return (
    <header className="h-12 border-b border-[#21262d] bg-[#010409] flex items-center px-5 gap-3">
      <h1 className="flex flex-1 items-center gap-2 text-sm font-semibold text-gray-300">
        <Icon className="h-4 w-4 text-blue-400" aria-hidden="true" />
        <span>{title.label}</span>
      </h1>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={toggleTheme}
          className="theme-toggle"
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark'
            ? <Sun className="h-4 w-4" aria-hidden="true" />
            : <Moon className="h-4 w-4" aria-hidden="true" />}
        </button>
        <span className="text-[10px] text-gray-600">AI</span>
        <span className="text-[10px] font-semibold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">Gemini 1.5 Pro</span>
      </div>
    </header>
  )
}
