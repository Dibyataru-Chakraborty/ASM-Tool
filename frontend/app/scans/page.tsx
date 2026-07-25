'use client'

import { useState, useEffect, useCallback } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import api from '@/lib/api'
import { StatCard, LoadingState, StatusBadge, Modal, Table, EmptyState } from '@/components/ui'
import { Radar, Play, XCircle, Plus, RefreshCw } from 'lucide-react'
import type { Scan, Asset } from '@/types'

const SCAN_TYPES = ['full', 'quick', 'port_scan', 'vuln_scan', 'ssl_check'] as const

function NewScanForm({ assets, selectedAssetId, onClose, onSave }: { assets: Asset[]; selectedAssetId: string; onClose: () => void; onSave: () => void }) {
  const [form, setForm] = useState({ asset_id: selectedAssetId || (assets[0]?.id || ''), scan_type: 'full', target_domain: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.asset_id) {
      setError('Please select an asset')
      return
    }
    setLoading(true)
    try {
      await api.initiateScan(form.asset_id, form.scan_type, form.target_domain || undefined)
      onSave()
      onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to initiate scan')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Select Asset *</label>
        <select className="input" required value={form.asset_id}
          onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))}>
          <option value="" disabled>Choose an asset...</option>
          {assets.map(a => <option key={a.id} value={a.id}>{a.name} ({a.asset_type.replace('_', ' ')})</option>)}
        </select>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Scan Type *</label>
        <select className="input" value={form.scan_type}
          onChange={e => setForm(f => ({ ...f, scan_type: e.target.value }))}>
          {SCAN_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
        </select>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Target Domain (optional)</label>
        <input className="input" placeholder="example.com"
          value={form.target_domain} onChange={e => setForm(f => ({ ...f, target_domain: e.target.value }))} />
      </div>
      <div className="flex gap-3 pt-2">
        <button type="button" className="btn-secondary text-sm flex-1" onClick={onClose}>Cancel</button>
        <button type="submit" disabled={loading} className="btn-primary text-sm flex-1">
          {loading ? 'Starting...' : 'Start Scan'}
        </button>
      </div>
    </form>
  )
}

function ScansContent() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)

  const fetchAssets = useCallback(async () => {
    try {
      const res = await api.getAssets(0, 100)
      const items = res.items || []
      setAssets(items)
      if (items.length > 0 && !selectedAssetId) {
        setSelectedAssetId(items[0].id)
      }
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to fetch assets')
    }
  }, [selectedAssetId])

  const fetchScans = useCallback(async () => {
    if (!selectedAssetId) {
      setLoading(false)
      return
    }
    try {
      setLoading(true)
      const res = await api.getScans(selectedAssetId)
      setScans(res.items || [])
      setError(null)
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to fetch scans')
    } finally {
      setLoading(false)
    }
  }, [selectedAssetId])

  useEffect(() => {
    fetchAssets()
  }, [fetchAssets])

  useEffect(() => {
    fetchScans()
  }, [fetchScans])

  const handleCancelScan = async (scanId: string) => {
    try {
      await api.cancelScan(scanId)
      fetchScans()
    } catch (e) {
      console.error(e)
    }
  }

  if (loading && assets.length === 0) return <LoadingState text="Loading scans..." />

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-gray-100">Scan Management</h1>
          <p className="text-xs text-gray-500 mt-0.5">{scans.length} scans total for selected asset</p>
        </div>
        <div className="flex items-center gap-2">
          {assets.length > 0 && (
            <div className="flex items-center gap-2 mr-2">
              <label className="text-xs text-gray-400 font-medium whitespace-nowrap">Asset:</label>
              <select className="input text-xs py-1.5 px-2 bg-[#161b22] border-[#21262d] max-w-[200px]"
                value={selectedAssetId} onChange={e => setSelectedAssetId(e.target.value)}>
                {assets.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
              </select>
            </div>
          )}
          <button className="btn-secondary text-sm flex items-center gap-2" onClick={fetchScans}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <button className="btn-primary text-sm flex items-center gap-2" onClick={() => setCreateOpen(true)} disabled={assets.length === 0}>
            <Plus className="w-4 h-4" /> New Scan
          </button>
        </div>
      </div>

      {error && <div className="text-sm text-red-400 font-medium">{error}</div>}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={scans.length}                                            icon={Radar}   color="blue" />
        <StatCard label="Running"     value={scans.filter(s => s.status === 'running').length}        color="blue" />
        <StatCard label="Completed"   value={scans.filter(s => s.status === 'completed').length}      color="green" />
        <StatCard label="Failed"      value={scans.filter(s => s.status === 'failed').length}         color="red" />
      </div>

      <div className="card">
        {assets.length === 0 ? (
          <EmptyState title="No assets registered" description="Please register an asset first to manage scans." />
        ) : scans.length === 0 ? (
          <EmptyState title="No scans found" description="Start a new scan to begin reconnaissance"
            action={
              <button className="btn-primary text-sm" onClick={() => setCreateOpen(true)}>
                <Plus className="w-4 h-4 mr-1 inline" /> Start Scan
              </button>
            }
          />
        ) : (
          <Table headers={['Scan ID', 'Type', 'Status', 'Started', 'Actions']}>
            {scans.map((s: Scan) => (
              <tr key={s.id} className="table-row">
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-gray-400">{s.id.slice(0, 8)}...</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-400 capitalize">{s.scan_type.replace('_', ' ')}</span>
                </td>
                <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-500">{new Date(s.created_at).toLocaleString()}</span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1">
                    {s.status === 'running' && (
                      <button className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded transition"
                        onClick={() => handleCancelScan(s.id)} title="Cancel">
                        <XCircle className="w-3.5 h-3.5" />
                      </button>
                    )}
                    {(s.status === 'failed' || s.status === 'completed') && (
                      <button className="p-1.5 text-gray-500 hover:text-green-400 hover:bg-green-500/10 rounded transition"
                        onClick={async () => {
                          try {
                            await api.initiateScan(s.asset_id, s.scan_type, s.target_domain || undefined)
                            fetchScans()
                          } catch (e) {
                            console.error(e)
                          }
                        }} title="Re-run">
                        <Play className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Start New Scan">
        <NewScanForm assets={assets} selectedAssetId={selectedAssetId} onClose={() => setCreateOpen(false)} onSave={fetchScans} />
      </Modal>
    </div>
  )
}

export default function ScansPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <ScansContent />
      </AppLayout>
    </AuthProvider>
  )
}
