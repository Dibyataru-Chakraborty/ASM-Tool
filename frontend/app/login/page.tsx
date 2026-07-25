'use client'
import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import axios from 'axios'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export default function LoginPage() {
  const router = useRouter()
  const [form, setForm]     = useState({ email: '', password: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const r = await axios.post(`${API}/api/v1/auth/login`, form)
      localStorage.setItem('access_token', r.data.access_token)
      router.push('/dashboard')
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Invalid credentials')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-5">
        <div className="text-center">
          <div className="text-4xl mb-3">🛡️</div>
          <h1 className="text-xl font-bold text-gray-100">ASM Platform</h1>
          <p className="text-sm text-gray-500 mt-1">Sign in to your account</p>
        </div>

        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-xs text-red-400">
              {error}
            </div>
          )}
          <form onSubmit={submit} className="space-y-3">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Email</label>
              <input type="email" required className="w-full bg-[#0d1117] border border-[#30363d] text-gray-100 placeholder-gray-600 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue-500"
                placeholder="admin@example.com" value={form.email}
                onChange={e => setForm(f => ({...f, email: e.target.value}))} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password</label>
              <input type="password" required className="w-full bg-[#0d1117] border border-[#30363d] text-gray-100 placeholder-gray-600 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue-500"
                placeholder="••••••••••••" value={form.password}
                onChange={e => setForm(f => ({...f, password: e.target.value}))} />
            </div>
            <button type="submit" disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white py-2.5 rounded-lg text-sm font-semibold transition">
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        </div>

        <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3 text-xs text-gray-500 space-y-1">
          <p className="text-gray-400 font-medium">Demo credentials</p>
          <p>Email: <span className="text-gray-300 font-mono">admin@asm.io</span></p>
          <p>Password: <span className="text-gray-300 font-mono">Admin@123456!</span></p>
        </div>

        <p className="text-center text-xs text-gray-600">
          No account? <Link href="/register" className="text-blue-400 hover:underline">Register</Link>
        </p>
      </div>
    </div>
  )
}
