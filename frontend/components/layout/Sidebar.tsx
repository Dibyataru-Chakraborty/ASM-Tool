'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import {
  Bot,
  Bug,
  CalendarClock,
  FileText,
  Globe2,
  History,
  LayoutDashboard,
  LogOut,
  Server,
  Settings,
  Shield,
} from 'lucide-react'

const NAV = [
  { href: '/dashboard',       icon: LayoutDashboard, iconClass: 'text-sky-400',     label: 'Dashboard'       },
  { href: '/assets',          icon: Server,          iconClass: 'text-indigo-400',  label: 'Assets'          },
  { href: '/scheduler',       icon: CalendarClock,   iconClass: 'text-amber-400',   label: 'Scheduler'       },
  { href: '/scans',           icon: History,         iconClass: 'text-purple-400',  label: 'Scan History'    },
  { href: '/recon',           icon: Globe2,          iconClass: 'text-cyan-400',    label: 'Recon Engine'    },
  { href: '/shannon',         icon: Bot,             iconClass: 'text-pink-400',    label: 'AI Pentest'      },
  { href: '/vulnerabilities', icon: Bug,             iconClass: 'text-red-400',     label: 'Vulnerabilities' },
  { href: '/reports',         icon: FileText,        iconClass: 'text-emerald-400', label: 'Reports'         },
  { href: '/settings',        icon: Settings,        iconClass: 'text-slate-400',   label: 'Settings'        },
]

export default function Sidebar() {
  const path = usePathname()
  const { user, logout } = useAuth()

  return (
    <aside className="fixed left-0 top-0 h-screen w-52 bg-[#010409] border-r border-[#21262d] flex flex-col z-50">
      <div className="px-4 py-4 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-blue-400" aria-hidden="true" />
          <div>
            <p className="text-sm font-bold text-gray-100 leading-none">ASM Platform</p>
            <p className="text-[10px] text-gray-600 mt-0.5">Attack Surface Mgmt</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {NAV.map(n => {
          const active = path === n.href || (n.href !== '/dashboard' && path.startsWith(n.href + '/')) || path === n.href
          const Icon = n.icon
          return (
            <Link key={n.href} href={n.href} className={active ? 'nav-active' : 'nav-item'}>
              <Icon className={`h-4 w-4 shrink-0 ${n.iconClass}`} aria-hidden="true" />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>

      <div className="px-2 pb-3 border-t border-[#21262d] pt-2">
        <div className="px-3 py-2 mb-1">
          <p className="text-xs font-medium text-gray-300 truncate">{user?.full_name}</p>
          <p className="text-[10px] text-gray-600 capitalize">{user?.role}</p>
        </div>
        <button onClick={logout} className="nav-item w-full text-red-400 hover:text-red-300 hover:bg-red-500/10">
          <LogOut className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  )
}
