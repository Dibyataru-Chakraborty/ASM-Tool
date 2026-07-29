'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import Sidebar from './Sidebar'
import Topbar from './Topbar'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && !isAuthenticated) router.push('/login')
  }, [isAuthenticated, loading, router])

  if (loading) return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="text-4xl animate-spin">🛡️</div>
        <p className="text-sm text-gray-500">Loading…</p>
      </div>
    </div>
  )

  if (!isAuthenticated) return null

  return (
    <div className="min-h-screen bg-[#0d1117]">
      <Sidebar />
      <div className="ml-52 flex flex-col min-h-screen">
        <Topbar />
        <main className="flex-1 p-5 max-w-7xl">
          {children}
        </main>
      </div>
    </div>
  )
}
