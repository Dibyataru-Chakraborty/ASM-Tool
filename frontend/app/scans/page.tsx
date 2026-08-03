'use client'
import { useState, useEffect } from 'react'
import Link from 'next/link'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Search,
  Trash2,
  X,
} from 'lucide-react'

const STATUS_CLS: Record<string,string> = {
  running:'text-blue-400',pending:'text-yellow-400',queued:'text-yellow-400',completed:'text-green-400',
  failed:'text-red-400',cancelled:'text-gray-500',paused:'text-orange-400'
}
const STATUS_DOT: Record<string,string> = {
  running:'bg-blue-400 animate-pulse',pending:'bg-yellow-400',queued:'bg-yellow-400',completed:'bg-green-400',
  failed:'bg-red-400',cancelled:'bg-gray-600',paused:'bg-orange-400'
}

export default function ScansPage() {
  const [scans, setScans]   = useState<any[]>([])
  const [assets, setAssets] = useState<any[]>([])
  const [filter, setFilter] = useState('')
  const [assetFilter, setAssetFilter] = useState('')
  const [search, setSearch] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState(true)

  const [deleteTarget, setDeleteTarget] = useState<any | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const load = async () => {
    const p: any = {}
    if (assetFilter) p.asset_id = assetFilter
    if (searchQuery) {
      p.search = searchQuery
      p.limit = 100
    }
    const [s, a] = await Promise.all([asm.getScans(p), asm.getAssets()])
    const assetRows = a.assets || []
    const assetById = new Map(assetRows.map((asset: any) => [asset.id, asset]))
    const scanRows = (s.items || s.scans || []).map((scan: any) => {
      const asset: any = assetById.get(scan.asset_id)
      const status = scan.status === 'pending' ? 'queued' : scan.status
      const startedAt = scan.started_at ? new Date(scan.started_at).getTime() : 0
      const completedAt = scan.completed_at ? new Date(scan.completed_at).getTime() : 0

      return {
        ...scan,
        status,
        asset_target: scan.asset_target || asset?.target || asset?.name || scan.asset_id,
        triggered_by: scan.triggered_by || 'manual',
        progress: typeof scan.progress === 'number'
          ? scan.progress
          : status === 'completed' ? 100 : 0,
        duration_seconds: scan.duration_seconds || (
          startedAt && completedAt ? Math.max(0, Math.round((completedAt - startedAt) / 1000)) : null
        ),
      }
    })

    const statusRows = filter
      ? scanRows.filter((scan: any) => scan.status === filter)
      : scanRows
    // This local check also keeps search responsive while an older backend
    // container is being replaced.
    const normalizedSearch = searchQuery.toLowerCase()
    setScans(normalizedSearch
      ? statusRows.filter((scan: any) =>
          String(scan.reference_id || '').toLowerCase().includes(normalizedSearch)
          || String(scan.id || '').toLowerCase().includes(normalizedSearch)
        )
      : statusRows
    )
    setAssets(assetRows)
    setLoading(false)
  }

  useEffect(() => {
    const timer = window.setTimeout(() => setSearchQuery(search.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [search])

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t) }, [filter, assetFilter, searchQuery])

  const cancel = async (id: string) => { await asm.cancelScan(id); load() }
  const openDeleteModal = (scan: any) => {
  setDeleteError('')
  setDeleteTarget(scan)
}

const closeDeleteModal = () => {
  if (deleting) return

  setDeleteError('')
  setDeleteTarget(null)
}

const confirmDelete = async () => {
  if (!deleteTarget) return

  try {
    setDeleting(true)
    setDeleteError('')

    await asm.deleteScan(deleteTarget.id)

    setDeleteTarget(null)

    // Remove instantly from UI.
    setScans(current =>
      current.filter(scan => scan.id !== deleteTarget.id)
    )

    // Then synchronize with backend.
    await load()
  } catch (error: any) {
    const message =
      error?.response?.data?.detail ||
      error?.message ||
      'Failed to delete scan'

    setDeleteError(message)
  } finally {
    setDeleting(false)
  }
}
  return (
    <AuthProvider><AppLayout>
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Scan History</h1>
          <p className="text-xs text-gray-500">{scans.length} scans · Auto-refreshes every 5s</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
            <input
              type="search"
              value={search}
              onChange={event => setSearch(event.target.value)}
              className="input py-1.5 pl-9 pr-8 text-xs"
              placeholder="Search scan ID or reference"
              aria-label="Search scans by ID or reference"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 transition hover:text-gray-300"
                aria-label="Clear scan search"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <select className="input py-1.5 text-xs w-40" value={assetFilter} onChange={e=>setAssetFilter(e.target.value)}>
            <option value="">All Assets</option>
            {assets.map((a:any)=><option key={a.id} value={a.id}>{a.target}</option>)}
          </select>
          <select className="input py-1.5 text-xs w-36" value={filter} onChange={e=>setFilter(e.target.value)}>
            <option value="">All Status</option>
            {['queued','running','completed','failed','cancelled'].map(s=><option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="card overflow-x-auto">
        {loading ? (
          <div className="py-12 text-center animate-pulse text-gray-600 text-sm">Loading scans…</div>
        ) : scans.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-2xl mb-2">🔭</p>
            <p className="text-sm text-gray-500">No scans found</p>
            <Link href="/assets" className="btn-blue text-xs mt-3 inline-block">Go to Assets → Trigger Scan</Link>
          </div>
        ) : (
          <table className="w-full min-w-[1100px] table-fixed text-xs">
            <colgroup>
              <col className="w-[22%]" />
              <col className="w-[13%]" />
              <col className="w-[13%]" />
              <col className="w-[12%]" />
              <col className="w-[13%]" />
              <col className="w-[12%]" />
              <col className="w-[15%]" />
            </colgroup>
            <thead><tr className="border-b border-[#21262d]">
              {['Target','Status','Progress','Triggered','Started','Duration','Actions'].map(h=>(
                <th
                  key={h}
                  className={`px-4 py-3 font-medium uppercase tracking-wide text-gray-500 ${h === 'Actions' ? 'text-right' : 'text-left'}`}
                >
                  {h}
                </th>
              ))}
            </tr></thead>
            <tbody>
              {scans.map((j:any)=>(
                <tr key={j.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                  <td className="px-4 py-3">
                    <p className="font-mono text-gray-200">{j.asset_target}</p>
                    <p className="font-mono text-blue-400 text-[10px]" title={j.id}>
                      {j.reference_id || j.id}
                    </p>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {j.status === 'running' ? (
                        <Loader2 className="h-4 w-4 animate-spin text-blue-400" aria-label="Scan running" />
                      ) : j.status === 'completed' ? (
                        <CheckCircle2 className="h-4 w-4 text-green-400" aria-label="Scan completed" />
                      ) : (
                        <span className={`h-2 w-2 rounded-full ${STATUS_DOT[j.status]||'bg-gray-600'}`} />
                      )}
                      <span className={STATUS_CLS[j.status]||'text-gray-400'}>{j.status}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 w-32">
                    <div className="h-1.5 bg-[#21262d] rounded-full overflow-hidden">
                      {j.status === 'running' ? (
                        <div
                          className="h-full animate-pulse rounded-full bg-blue-500 transition-all duration-500"
                          style={{ width: `${Math.max(4, Math.min(100, j.progress || 0))}%` }}
                        />
                      ) : (
                        <div className="h-full bg-blue-500 transition-all duration-500 rounded-full" style={{width:`${j.progress||0}%`}} />
                      )}
                    </div>
                    <p className="text-gray-600 mt-0.5">
                      {j.status === 'running' ? `${j.progress || 0}%` : j.status === 'queued' ? 'Waiting' : `${j.progress||0}%`}
                    </p>
                  </td>
                  <td className="px-4 py-3 text-gray-500 capitalize">{j.triggered_by}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {j.started_at ? new Date(j.started_at).toLocaleTimeString() : '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {j.duration_seconds ? `${Math.round(j.duration_seconds/60)}m ${j.duration_seconds%60}s` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2 whitespace-nowrap">

                      {/* View */}
                      <Link
                        href={`/scans/${j.id}`}
                        className="text-xs text-blue-400 transition hover:text-blue-300"
                      >
                       View
                     </Link>

                     {/* Cancel active scan */}
                     {['running', 'queued'].includes(j.status) && (
                       <>
                         <span className="text-gray-700">|</span>

                         <button
                           type="button"
                           onClick={() => cancel(j.id)}
                           className="text-xs text-red-400 transition hover:text-red-300"
                         >
                           Cancel
                         </button>
                      </>
                    )}

                    <span className="text-gray-700">|</span>

                    {/* Delete */}
                    <button
                      type="button"
                      onClick={() => openDeleteModal(j)}
                      className="group rounded-md p-1.5 text-gray-500 transition
                                 hover:bg-red-500/10 hover:text-red-400"
                      title="Delete scan"
                      aria-label={`Delete scan ${j.reference_id || j.id}`}
                    >
                      <Trash2
                        className="h-4 w-4 transition group-hover:scale-110"
                        strokeWidth={1.8}
                      />
                    </button>

                   </div>
                 </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>

    {/* Delete scan confirmation modal */}
    {deleteTarget && (
      <div
        className="fixed inset-0 z-[100] flex items-center justify-center
                   bg-black/70 px-4 backdrop-blur-sm"
        onMouseDown={event => {
          if (event.target === event.currentTarget) {
            closeDeleteModal()
          }
        }}
      >
        <div
          className="w-full max-w-md overflow-hidden rounded-xl
                     border border-[#30363d] bg-[#161b22]
                     shadow-2xl"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-scan-title"
        >

          {/* Header */}
          <div className="flex items-start gap-3 border-b border-[#30363d] px-5 py-4">

            <div
              className="flex h-10 w-10 shrink-0 items-center justify-center
                           rounded-full bg-red-500/10"
              >
                <AlertTriangle className="h-5 w-5 text-red-400" />
              </div>

              <div className="min-w-0 flex-1">
                <h2
                  id="delete-scan-title"
                  className="text-sm font-semibold text-gray-100"
                >
                  Delete scan?
                </h2>

                <p className="mt-1 text-xs leading-5 text-gray-500">
                  This action permanently deletes this scan and its
                  associated scan history.
                </p>
              </div>

              <button
                type="button"
                onClick={closeDeleteModal}
                disabled={deleting}
                className="rounded-md p-1 text-gray-500 transition
                           hover:bg-[#21262d] hover:text-gray-300
                           disabled:cursor-not-allowed disabled:opacity-50"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>

            </div>

            {/* Scan information */}
            <div className="px-5 py-4">

              <div
                className="rounded-lg border border-[#30363d]
                           bg-[#0d1117] px-4 py-3"
              >
                <p className="text-[10px] uppercase tracking-wider text-gray-600">
                  Target
                </p>

                <p className="mt-1 font-mono text-sm text-gray-200">
                  {deleteTarget.asset_target}
                </p>

                <p className="mt-2 text-[10px] uppercase tracking-wider text-gray-600">
                  Scan ID
                </p>

                <p className="mt-1 break-all font-mono text-xs text-blue-400">
                  {deleteTarget.reference_id || deleteTarget.id}
                </p>
              </div>


              {/* Running scan warning */}
              {['running', 'queued'].includes(deleteTarget.status) && (
                <div
                  className="mt-3 rounded-lg border border-orange-500/20
                             bg-orange-500/5 px-3 py-2.5"
                >
                  <p className="text-xs leading-5 text-orange-300">
                    This scan is currently {deleteTarget.status}.
                    Cancel the scan first before deleting it.
                  </p>
                </div>
              )}


              {/* API error */}
              {deleteError && (
                <div
                  className="mt-3 rounded-lg border border-red-500/20
                             bg-red-500/5 px-3 py-2.5"
                >
                  <p className="text-xs leading-5 text-red-400">
                    {deleteError}
                  </p>
                </div>
              )}

            </div>


            {/* Buttons */}
            <div
              className="flex justify-end gap-2 border-t border-[#30363d]
                         bg-[#0d1117]/40 px-5 py-4"
            >

              <button
                type="button"
                onClick={closeDeleteModal}
                disabled={deleting}
                className="rounded-md border border-[#30363d]
                           bg-[#21262d] px-4 py-2 text-xs font-medium
                           text-gray-300 transition
                           hover:bg-[#30363d]
                           disabled:cursor-not-allowed disabled:opacity-50"
              >
                Cancel
              </button>


              <button
                type="button"
                onClick={confirmDelete}
                disabled={
                  deleting ||
                  ['running', 'queued'].includes(deleteTarget.status)
                }
                className="flex items-center gap-2 rounded-md
                           bg-red-600 px-4 py-2 text-xs font-semibold
                           text-white transition
                           hover:bg-red-500
                           disabled:cursor-not-allowed
                           disabled:bg-red-900/50
                           disabled:text-red-300/50"
              >
                {deleting ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  <>
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </>
                )}
              </button>

            </div>
          </div>
        </div>
      )}

    
    </AppLayout>
  </AuthProvider>
  )
}
