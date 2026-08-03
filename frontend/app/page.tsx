'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (token) router.replace('/dashboard')
  }, [router])

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center px-4">
      <div className="max-w-2xl text-center space-y-8">
        <div>
          <div className="text-6xl mb-4">🛡️</div>
          <h1 className="text-3xl font-bold text-gray-100">ASM Platform</h1>
          <p className="text-gray-500 mt-2 text-sm">Enterprise Attack Surface Management</p>
        </div>

        <div className="grid grid-cols-3 gap-4 text-sm">
          {[
            { e:'🔭', t:'Real Scanning',    d:'Multi-stage asset, service, and vulnerability analysis' },
            { e:'🤖', t:'AI Analysis',      d:'Gemini 1.5 Pro powers every report' },
            { e:'📄', t:'Auto Reports',     d:'Executive + Technical after every scan' },
          ].map(f => (
            <div key={f.t} className="card p-4">
              <div className="text-2xl mb-2">{f.e}</div>
              <p className="text-gray-200 font-medium text-xs mb-1">{f.t}</p>
              <p className="text-gray-600 text-[10px]">{f.d}</p>
            </div>
          ))}
        </div>

        <div className="flex gap-3 justify-center">
          <Link href="/login"    className="btn-blue px-8 text-sm">Sign In</Link>
          <Link href="/register" className="btn-gray px-8 text-sm">Register</Link>
        </div>
      </div>
    </div>
  )
}
