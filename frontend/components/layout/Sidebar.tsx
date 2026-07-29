'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'

const NAV = [
  { href: '/dashboard',       icon: '🏠', label: 'Dashboard'       },
  { href: '/assets',          icon: '🖥️', label: 'Assets'          },
  { href: '/scheduler',       icon: '🕐', label: 'Scheduler'       },
  { href: '/scans',           icon: '🔭', label: 'Scan History'    },
  { href: '/recon',           icon: '🌐', label: 'Recon Engine'    },
  { href: '/shannon',         icon: '🤖', label: 'AI Pentest'      },
  { href: '/vulnerabilities', icon: '🐛', label: 'Vulnerabilities' },
  { href: '/reports',         icon: '📄', label: 'Reports'         },
  { href: '/settings',        icon: '⚙️', label: 'Settings'        },
]

export default function Sidebar() {
  const path = usePathname()
  const { user, logout } = useAuth()

  return (
    <aside className="fixed left-0 top-0 h-screen w-52 bg-[#010409] border-r border-[#21262d] flex flex-col z-50">
      <div className="px-4 py-4 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          <span className="text-xl">🛡️</span>
          <div>
            <p className="text-sm font-bold text-gray-100 leading-none">ASM Platform</p>
            <p className="text-[10px] text-gray-600 mt-0.5">Attack Surface Mgmt</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {NAV.map(n => {
          const active = path === n.href || (n.href !== '/dashboard' && path.startsWith(n.href + '/')) || path === n.href
          return (
            <Link key={n.href} href={n.href} className={active ? 'nav-active' : 'nav-item'}>
              <span className="text-base leading-none">{n.icon}</span>
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
          <span>🚪</span><span>Logout</span>
        </button>
      </div>
    </aside>
  )
}
