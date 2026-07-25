'use client'

import { useState, useEffect } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useAssets } from '@/hooks/useAssets'
import api from '@/lib/api'
import {
  StatCard, LoadingState, ErrorState, StatusBadge, Modal,
  ConfirmDialog, Table, Pagination, EmptyState
} from '@/components/ui'
import { RiskGauge } from '@/components/charts/RiskChart'
import { Plus, Server, Archive, Trash2, Eye, RefreshCw, Globe } from 'lucide-react'
import type { Asset } from '@/types'

const ASSET_TYPES = ['domain', 'ip_range', 'web_application', 'mobile_app', 'cloud_service'] as const

type AssetType = (typeof ASSET_TYPES)[number]

function AssetDetailsModal({ assetId, onClose }: { assetId: string; onClose: () => void }) {
  const [assetDetails, setAssetDetails] = useState<any>(null)
  const [subdomains, setSubdomains] = useState<any[]>([])
  const [screenshots, setScreenshots] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'subdomains' | 'screenshots'>('overview')

  useEffect(() => {
    if (!assetId) return
    setLoading(true)
    Promise.all([
      api.getAsset(assetId),
      api.getAssetSubdomains(assetId).catch(() => ({ subdomains: [], total: 0 })),
      api.getAssetScreenshots(assetId).catch(() => ({ screenshots: [], total: 0 }))
    ])
      .then(([assetRes, subRes, screenRes]) => {
        setAssetDetails(assetRes)
        setSubdomains(subRes.subdomains || [])
        setScreenshots(screenRes.screenshots || [])
      })
      .catch(err => setError(err.response?.data?.detail || 'Failed to load details'))
      .finally(() => setLoading(false))
  }, [assetId])

  if (loading) return <div className="py-8 text-center text-xs text-gray-400">Loading details...</div>
  if (error) return <div className="py-8 text-center text-xs text-red-400">{error}</div>
  if (!assetDetails) return null

  return (
    <div className="space-y-4">
      {/* Tabs */}
      <div className="flex border-b border-[#21262d] gap-2 mb-2">
        {(['overview', 'subdomains', 'screenshots'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-3 py-1.5 text-xs font-semibold border-b-2 capitalize transition ${
              activeTab === tab
                ? 'border-blue-500 text-gray-100'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3">
              <p className="text-[10px] uppercase font-bold tracking-wider text-gray-500 mb-0.5">Asset Type</p>
              <p className="text-sm font-semibold text-gray-200 capitalize">{assetDetails.asset_type.replace('_', ' ')}</p>
            </div>
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3">
              <p className="text-[10px] uppercase font-bold tracking-wider text-gray-500 mb-0.5">Status</p>
              <div className="mt-0.5"><StatusBadge status={assetDetails.status} /></div>
            </div>
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3">
              <p className="text-[10px] uppercase font-bold tracking-wider text-gray-500 mb-0.5">Risk Score</p>
              <div className="mt-1"><RiskGauge score={assetDetails.risk_score} /></div>
            </div>
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3">
              <p className="text-[10px] uppercase font-bold tracking-wider text-gray-500 mb-0.5">Registered On</p>
              <p className="text-sm font-medium text-gray-200 mt-0.5">{new Date(assetDetails.created_at).toLocaleString()}</p>
            </div>
          </div>

          {assetDetails.description && (
            <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3">
              <p className="text-[10px] uppercase font-bold tracking-wider text-gray-500 mb-1">Description</p>
              <p className="text-xs text-gray-300 whitespace-pre-wrap">{assetDetails.description}</p>
            </div>
          )}

          <div className="border-t border-[#21262d] pt-3">
            <p className="text-xs font-semibold text-gray-200 mb-2">Discovery & Scan Statistics</p>
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-blue-400">{assetDetails.total_domains || 0}</p>
                <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Domains</p>
              </div>
              <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-purple-400">{assetDetails.total_subdomains || 0}</p>
                <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Subdomains</p>
              </div>
              <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-3 text-center">
                <p className="text-lg font-bold text-red-400">{assetDetails.vulnerable_domains || 0}</p>
                <p className="text-[10px] font-medium text-gray-500 uppercase tracking-wider">Vulnerable</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'subdomains' && (
        <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
          {subdomains.length === 0 ? (
            <p className="text-xs text-gray-500 text-center py-8">No subdomains discovered yet. Run a scan to discover subdomains.</p>
          ) : (
            subdomains.map(sub => (
              <div key={sub.id} className="bg-[#161b22] border border-[#21262d] rounded-lg p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-200 font-mono">{sub.subdomain}</span>
                  <StatusBadge status={sub.is_responsive ? 'active' : 'inactive'} />
                </div>
                <div className="flex flex-wrap gap-1.5 items-center text-[10px] text-gray-400">
                  <span>IP: {sub.ip_addresses?.join(', ') || 'N/A'}</span>
                  {sub.response_status_code && (
                    <span className="bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">
                      HTTP {sub.response_status_code}
                    </span>
                  )}
                  {sub.ports && sub.ports.length > 0 && (
                    <div className="flex gap-1 items-center ml-auto">
                      <span className="text-[9px] uppercase tracking-wider text-gray-500">Ports:</span>
                      {sub.ports.map((p: number) => (
                        <span key={p} className="bg-blue-500/10 text-blue-400 border border-blue-500/25 px-1 py-0.2 rounded font-mono">
                          {p}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'screenshots' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[300px] overflow-y-auto pr-1">
          {screenshots.length === 0 ? (
            <div className="col-span-full py-8 text-center text-xs text-gray-500">
              No page screenshots captured. Scans must find open HTTP/HTTPS services.
            </div>
          ) : (
            screenshots.map(screen => (
              <div key={screen.id} className="bg-[#161b22] border border-[#21262d] rounded-lg overflow-hidden flex flex-col">
                {/* Simulated Browser Frame Header */}
                <div className="bg-[#21262d] px-2.5 py-1.5 flex items-center gap-1.5 border-b border-[#30363d]">
                  <div className="flex gap-1">
                    <span className="w-1 h-1 rounded-full bg-red-500" />
                    <span className="w-1 h-1 rounded-full bg-yellow-500" />
                    <span className="w-1 h-1 rounded-full bg-green-500" />
                  </div>
                  <div className="bg-[#0d1117] text-[8px] text-gray-400 px-2 py-0.5 rounded flex-1 truncate font-mono text-center">
                    {screen.url}
                  </div>
                </div>
                {/* Simulated Screenshot Thumbnail */}
                <div className="aspect-video bg-gradient-to-br from-blue-900/30 to-purple-900/30 flex flex-col items-center justify-center p-3 text-center border-b border-[#30363d] relative">
                  <div className="absolute top-2 right-2 bg-black/60 px-1.5 py-0.5 rounded text-[8px] font-mono text-green-400 font-bold border border-green-500/20">
                    HTTP {screen.status_code}
                  </div>
                  <p className="text-[10px] font-semibold text-gray-200 line-clamp-1 mb-1">{screen.title || 'Landing Page'}</p>
                  <p className="text-[8px] text-gray-500 uppercase tracking-widest font-mono">Port {screen.port}</p>
                </div>
                {/* Footer details */}
                <div className="p-2.5 space-y-1.5 flex-1 flex flex-col justify-between">
                  <div className="flex flex-wrap gap-1">
                    {screen.technologies?.map((tech: string) => (
                      <span key={tech} className="bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded text-[9px] font-medium">
                        {tech}
                      </span>
                    ))}
                  </div>
                  <a
                    href={screen.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[9px] text-blue-400 hover:text-blue-300 font-medium inline-block text-right self-end mt-1"
                  >
                    Open Target ↗
                  </a>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      <div className="flex pt-2">
        <button type="button" className="btn-secondary text-sm flex-1" onClick={onClose}>Close</button>
      </div>
    </div>
  )
}

function AssetForm({ onClose, onSave }: { onClose: () => void; onSave: () => void }) {
  const [form, setForm] = useState<{ name: string; description: string; asset_type: AssetType }>({ name: '', description: '', asset_type: 'domain' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.createAsset(form)
      onSave()
      onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create asset')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Asset Name *</label>
        <input className="input" placeholder="example.com" required
          value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Type *</label>
        <select className="input" value={form.asset_type}
          onChange={e => setForm(f => ({ ...f, asset_type: e.target.value as AssetType }))}>
          {ASSET_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
        </select>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Description</label>
        <textarea className="input resize-none" rows={3} placeholder="Optional description..."
          value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
      </div>
      <div className="flex gap-3 pt-2">
        <button type="button" className="btn-secondary text-sm flex-1" onClick={onClose}>Cancel</button>
        <button type="submit" disabled={loading} className="btn-primary text-sm flex-1">
          {loading ? 'Creating...' : 'Create Asset'}
        </button>
      </div>
    </form>
  )
}

function AssetsContent() {
  const [page, setPage] = useState(0)
  const { data, loading, error, refetch } = useAssets(page, 10)
  const [createOpen, setCreateOpen] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [archiveId, setArchiveId] = useState<string | null>(null)
  const [viewId, setViewId] = useState<string | null>(null)

  const handleDelete = async () => {
    if (!deleteId) return
    await api.deleteAsset(deleteId)
    refetch()
  }

  const handleArchive = async () => {
    if (!archiveId) return
    await api.archiveAsset(archiveId)
    refetch()
  }

  if (loading) return <LoadingState text="Loading assets..." />
  if (error) return <ErrorState message={error} />

  const assets = data?.items || []
  const total = data?.total || 0

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-gray-100">Asset Inventory</h1>
          <p className="text-xs text-gray-500 mt-0.5">{total} assets registered</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary text-sm flex items-center gap-2" onClick={refetch}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <button className="btn-primary text-sm flex items-center gap-2" onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" /> Add Asset
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total"    value={total}                                               icon={Server} color="blue" />
        <StatCard label="Active"   value={assets.filter(a => a.status === 'active').length}    icon={Globe}  color="green" />
        <StatCard label="Archived" value={assets.filter(a => a.status === 'archived').length}  color="yellow" />
        <StatCard label="Avg Risk" value={`${(assets.reduce((s, a) => s + a.risk_score, 0) / (assets.length || 1)).toFixed(0)}/100`} color="red" />
      </div>

      {/* Table */}
      <div className="card">
        {assets.length === 0 ? (
          <EmptyState
            title="No assets found"
            description="Add your first asset to start monitoring"
            action={
              <button className="btn-primary text-sm" onClick={() => setCreateOpen(true)}>
                <Plus className="w-4 h-4 mr-1 inline" /> Add Asset
              </button>
            }
          />
        ) : (
          <>
            <Table headers={['Asset', 'Type', 'Status', 'Risk Score', 'Created', 'Actions']}>
              {assets.map((a: Asset) => (
                <tr key={a.id} className="table-row">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
                        <Server className="w-3.5 h-3.5 text-blue-400" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-200">{a.name}</p>
                        {a.description && <p className="text-xs text-gray-500 truncate max-w-[200px]">{a.description}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-gray-400 capitalize">{a.asset_type.replace('_', ' ')}</span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-3 w-36">
                    <RiskGauge score={a.risk_score} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-gray-500">
                      {new Date(a.created_at).toLocaleDateString()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setViewId(a.id)}
                        className="p-1.5 text-gray-500 hover:text-blue-400 hover:bg-blue-500/10 rounded transition"
                        title="View Details">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setArchiveId(a.id)}
                        className="p-1.5 text-gray-500 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition"
                        title="Archive">
                        <Archive className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setDeleteId(a.id)}
                        className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded transition"
                        title="Delete">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </Table>
            <Pagination page={page} total={total} limit={10} onChange={setPage} />
          </>
        )}
      </div>

      {/* Modals */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Add New Asset">
        <AssetForm onClose={() => setCreateOpen(false)} onSave={refetch} />
      </Modal>

      <Modal open={!!viewId} onClose={() => setViewId(null)} title="Asset Details">
        {viewId && <AssetDetailsModal assetId={viewId} onClose={() => setViewId(null)} />}
      </Modal>

      <ConfirmDialog
        open={!!deleteId} onClose={() => setDeleteId(null)} onConfirm={handleDelete}
        title="Delete Asset" danger
        message="Are you sure you want to delete this asset? This action cannot be undone and will delete all associated data."
      />
      <ConfirmDialog
        open={!!archiveId} onClose={() => setArchiveId(null)} onConfirm={handleArchive}
        title="Archive Asset"
        message="Are you sure you want to archive this asset? It will be hidden from active monitoring."
      />
    </div>
  )
}

export default function AssetsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <AssetsContent />
      </AppLayout>
    </AuthProvider>
  )
}
