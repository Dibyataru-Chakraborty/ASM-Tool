'use client'
import { usePathname } from 'next/navigation'

const TITLES: Record<string,string> = {
  '/dashboard': '🏠 Dashboard', '/assets': '🖥️ Assets',
  '/scheduler': '🕐 Scan Scheduler', '/scans': '🔭 Scan History',
  '/recon': '🌐 Recon Engine', '/shannon': '🤖 AI Pentest (Shannon)',
  '/vulnerabilities': '🐛 Vulnerabilities', '/reports': '📄 Reports',
  '/settings': '⚙️ Settings',
}

export default function Topbar() {
  const path = usePathname()
  const title = Object.entries(TITLES).find(([k]) => path === k || path.startsWith(k + '/'))?.[1] || 'ASM Platform'
  return (
    <header className="h-12 border-b border-[#21262d] bg-[#010409] flex items-center px-5 gap-3">
      <h1 className="text-sm font-semibold text-gray-300 flex-1">{title}</h1>
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-gray-600">AI</span>
        <span className="text-[10px] font-semibold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">Gemini 1.5 Pro</span>
      </div>
    </header>
  )
}
