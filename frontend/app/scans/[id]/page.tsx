'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Loader2,
  Radar,
  Search,
  ShieldAlert,
  XCircle,
} from 'lucide-react'

import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

type ScanJob = {
  id: string
  reference_id?: string | null
  asset_id: string
  scan_type: string
  status: string
  target_domain?: string | null
  retry_count?: number
  started_at?: string | null
  completed_at?: string | null
  discovered_count?: number
  vulnerable_count?: number
  error_message?: string | null
  created_at: string
  updated_at: string
}

const ACTIVE_STATUSES = new Set(['pending', 'queued', 'running'])

function asDate(value?: string | null) {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function formatDate(value?: string | null) {
  const date = asDate(value)
  return date ? date.toLocaleString() : '—'
}

function formatDuration(start?: string | null, end?: string | null) {
  const startedAt = asDate(start)
  if (!startedAt) return '—'

  const endedAt = asDate(end)
  if (!endedAt) return 'In progress'

  const seconds = Math.max(0, Math.round((endedAt.getTime() - startedAt.getTime()) / 1000))
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  return minutes ? `${minutes}m ${remainingSeconds}s` : `${remainingSeconds}s`
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
  if (status === 'completed') return <CheckCircle2 className="h-4 w-4 text-green-400" />
  if (status === 'failed') return <XCircle className="h-4 w-4 text-red-400" />
  if (status === 'cancelled') return <XCircle className="h-4 w-4 text-gray-500" />
  return <Clock3 className="h-4 w-4 text-yellow-400" />
}

function statusClasses(status: string) {
  if (status === 'running') return 'border-blue-500/30 bg-blue-500/10 text-blue-400'
  if (status === 'completed') return 'border-green-500/30 bg-green-500/10 text-green-400'
  if (status === 'failed') return 'border-red-500/30 bg-red-500/10 text-red-400'
  if (status === 'cancelled') return 'border-gray-500/30 bg-gray-500/10 text-gray-400'
  return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
}

function ScanDetailPageInner({ params }: { params: { id: string } }) {
  const { id } = params
  const [scan, setScan] = useState<ScanJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadScan = useCallback(async () => {
    try {
      const response = await asm.getScan(id)
      setScan(response)
      setError('')
    } catch (requestError: any) {
      const detail = requestError?.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Unable to load this scan.')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    loadScan()
  }, [loadScan])

  useEffect(() => {
    if (!scan || !ACTIVE_STATUSES.has(String(scan.status).toLowerCase())) return
    const timer = window.setInterval(loadScan, 3000)
    return () => window.clearInterval(timer)
  }, [scan?.status, loadScan])

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-9 w-9 animate-spin text-blue-400" aria-label="Loading scan" />
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="card mx-auto mt-16 max-w-lg p-8 text-center">
        <AlertCircle className="mx-auto mb-3 h-10 w-10 text-red-400" />
        <h1 className="text-base font-semibold text-gray-100">Scan details unavailable</h1>
        <p className="mt-2 text-sm text-gray-500">{error || 'This scan could not be found.'}</p>
        <Link href="/scans" className="btn-blue mt-5 inline-flex items-center gap-2 text-xs">
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Scan History
        </Link>
      </div>
    )
  }

  const status = String(scan.status || 'pending').toLowerCase()
  const isActive = ACTIVE_STATUSES.has(status)
  const title = scan.target_domain || scan.reference_id || scan.id

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link href="/scans" className="mb-2 inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-blue-400">
            <ArrowLeft className="h-3.5 w-3.5" />
            Scan History
          </Link>
          <h1 className="break-all text-xl font-bold text-gray-100">{title}</h1>
          <p className="mt-1 font-mono text-xs text-blue-400">
            {scan.reference_id || scan.id}
          </p>
        </div>

        <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold capitalize ${statusClasses(status)}`}>
          <StatusIcon status={status} />
          {status === 'pending' ? 'queued' : status}
        </span>
      </div>

      {scan.error_message && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
          <div>
            <p className="text-xs font-semibold text-red-300">Scan failed</p>
            <p className="mt-1 whitespace-pre-wrap text-xs text-red-200/80">{scan.error_message}</p>
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">Scan type</p>
            <Radar className="h-4 w-4 text-blue-400" />
          </div>
          <p className="text-lg font-bold capitalize text-gray-100">
            {(scan.scan_type || 'scan').replace(/_/g, ' ')}
          </p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">Discoveries</p>
            <Search className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-gray-100">{scan.discovered_count ?? 0}</p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">Findings</p>
            <ShieldAlert className="h-4 w-4 text-orange-400" />
          </div>
          <p className="text-2xl font-bold text-gray-100">{scan.vulnerable_count ?? 0}</p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">Duration</p>
            <Clock3 className="h-4 w-4 text-purple-400" />
          </div>
          <p className="text-lg font-bold text-gray-100">
            {formatDuration(scan.started_at, scan.completed_at)}
          </p>
        </div>
      </div>

      <div className="card p-5">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">Execution status</h2>
            <p className="mt-1 text-xs text-gray-500">
              {isActive
                ? 'This page refreshes every 3 seconds while the real scan is active.'
                : `The scan is ${status}.`}
            </p>
          </div>
          <StatusIcon status={status} />
        </div>

        <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#21262d]">
          {status === 'running' ? (
            <div className="h-full w-1/3 animate-pulse rounded-full bg-blue-500" />
          ) : (
            <div
              className={`h-full rounded-full ${
                status === 'completed'
                  ? 'w-full bg-green-500'
                  : status === 'failed'
                    ? 'w-full bg-red-500'
                    : status === 'cancelled'
                      ? 'w-full bg-gray-600'
                      : 'w-1/12 bg-yellow-500'
              }`}
            />
          )}
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="border-b border-[#21262d] px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-100">Scan record</h2>
          <p className="mt-1 text-xs text-gray-500">Values below come directly from the saved scan record.</p>
        </div>

        <dl className="grid sm:grid-cols-2">
          {[
            ['Scan ID', scan.id],
            ['Reference', scan.reference_id || '—'],
            ['Asset ID', scan.asset_id],
            ['Target', scan.target_domain || '—'],
            ['Created', formatDate(scan.created_at)],
            ['Started', formatDate(scan.started_at)],
            ['Completed', formatDate(scan.completed_at)],
            ['Last updated', formatDate(scan.updated_at)],
          ].map(([label, value]) => (
            <div key={label} className="border-b border-[#21262d] px-5 py-4 even:sm:border-l">
              <dt className="text-[10px] uppercase tracking-wide text-gray-600">{label}</dt>
              <dd className="mt-1 break-all font-mono text-xs text-gray-300">{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  )
}

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  return (
    <AuthProvider>
      <AppLayout>
        <ScanDetailPageInner params={params} />
      </AppLayout>
    </AuthProvider>
  )
}
