'use client'
import { useState, useEffect, useCallback } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const TYPES = ['domain','subdomain','ip','url','cidr']

type Asset = { id:string;name:string;target:string;asset_type:string;description?:string;tags:string[];last_scanned_at?:string;scan_count:number;is_active:boolean }

function AssetModal({asset,onClose,onSave}:{asset?:Asset;onClose:()=>void;onSave:()=>void}) {
  const [form, setForm] = useState({ name:asset?.name||'', target:asset?.target||'', asset_type:asset?.asset_type||'domain', description:asset?.description||'', tags:asset?.tags?.join(', ')||'' })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setSaving(true); setErr('')
    try {
      const body = { ...form, tags: form.tags.split(',').map(t=>t.trim()).filter(Boolean) }
      if (asset) await asm.updateAsset(asset.id, body)
      else await asm.createAsset(body)
      onSave(); onClose()
    } catch(e:any) { setErr(e.response?.data?.detail || 'Failed to save') }
    setSaving(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative card w-full max-w-md p-5 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-200">{asset ? 'Edit Asset' : 'Add Asset'}</h2>
          <button onClick={onClose} className="text-gray-600 hover:text-gray-300">✕</button>
        </div>
        {err && <p className="text-xs text-red-400 bg-red-500/10 rounded-lg p-2 mb-3">{err}</p>}
        <form onSubmit={save} className="space-y-3">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Display Name *</label>
            <input required className="input" placeholder="My Company" value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Target *</label>
            <input required className="input font-mono" placeholder="example.com or 192.168.1.0/24" value={form.target} onChange={e=>setForm(f=>({...f,target:e.target.value}))} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Type</label>
            <select className="input" value={form.asset_type} onChange={e=>setForm(f=>({...f,asset_type:e.target.value}))}>
              {TYPES.map(t=><option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Description</label>
            <textarea className="input resize-none h-16" placeholder="Optional description" value={form.description} onChange={e=>setForm(f=>({...f,description:e.target.value}))} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Tags (comma separated)</label>
            <input className="input" placeholder="production, critical, external" value={form.tags} onChange={e=>setForm(f=>({...f,tags:e.target.value}))} />
          </div>
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="btn-gray flex-1 text-sm">Cancel</button>
            <button type="submit" disabled={saving} className="btn-blue flex-1 text-sm">{saving?'Saving…':'Save Asset'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [total, setTotal]   = useState(0)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [modal, setModal]   = useState<Asset|null|'new'>(null)
  const [scanning, setScanning] = useState<string|null>(null)
  const [msg, setMsg]       = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    const d = await asm.getAssets(search ? {search} : {})
    setAssets(d.assets || [])
    setTotal(d.total || 0)
    setLoading(false)
  }, [search])

  useEffect(() => { load() }, [load])

  const del = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This removes all scan history.`)) return
    await asm.deleteAsset(id)
    load()
  }

  const scan = async (id: string) => {
    setScanning(id)
    try {
      const r = await asm.triggerScan(id)
      setMsg(`✅ Scan queued: ${r.scan_job_id}`)
      setTimeout(()=>setMsg(''),4000)
    } catch(e:any) { setMsg(`❌ ${e.response?.data?.detail||'Failed'}`) }
    setScanning(null)
  }

  const TYPE_CLS: Record<string,string> = {
    domain:'text-blue-400',subdomain:'text-cyan-400',ip:'text-green-400',url:'text-purple-400',cidr:'text-orange-400'
  }

  return (
    <AuthProvider><AppLayout>
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Assets</h1>
          <p className="text-xs text-gray-500">{total} assets · Domains, IPs, URLs, CIDRs</p>
        </div>
        <button onClick={()=>setModal('new')} className="btn-blue text-sm">+ Add Asset</button>
      </div>

      {msg && <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-2 text-sm text-gray-300">{msg}</div>}

      {/* Search */}
      <div className="flex gap-2">
        <input className="input flex-1" placeholder="🔍 Search by name or target…" value={search} onChange={e=>setSearch(e.target.value)} />
        <button onClick={load} className="btn-gray text-sm">Search</button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="py-16 text-center"><div className="animate-spin text-3xl">🔭</div></div>
        ) : assets.length === 0 ? (
          <div className="py-16 text-center">
            <p className="text-3xl mb-2">🖥️</p>
            <p className="text-sm text-gray-400 mb-3">No assets yet</p>
            <button onClick={()=>setModal('new')} className="btn-blue text-sm">Add your first asset</button>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead><tr className="border-b border-[#21262d]">
              {['Target','Type','Last Scanned','Scans','Tags','Actions'].map(h=>(
                <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {assets.map(a=>(
                <tr key={a.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                  <td className="px-4 py-3">
                    <p className="font-mono text-gray-200 font-medium">{a.target}</p>
                    {a.description && <p className="text-gray-600 mt-0.5 truncate max-w-xs">{a.description}</p>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-semibold uppercase text-[10px] ${TYPE_CLS[a.asset_type]||'text-gray-400'}`}>{a.asset_type}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {a.last_scanned_at ? new Date(a.last_scanned_at).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{a.scan_count}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(a.tags||[]).map((t:string)=>(
                        <span key={t} className="bg-[#0d1117] border border-[#30363d] text-gray-400 px-1.5 py-0.5 rounded text-[10px]">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <button onClick={()=>scan(a.id)} disabled={scanning===a.id}
                        className="text-xs text-green-400 hover:text-green-300 disabled:opacity-40 transition">
                        {scanning===a.id?'⏳':'▶ Scan'}
                      </button>
                      <span className="text-gray-700">|</span>
                      <button onClick={()=>setModal(a)} className="text-xs text-blue-400 hover:text-blue-300">Edit</button>
                      <span className="text-gray-700">|</span>
                      <button onClick={()=>del(a.id,a.name)} className="text-xs text-red-400 hover:text-red-300">Del</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <AssetModal
          asset={modal === 'new' ? undefined : modal as Asset}
          onClose={()=>setModal(null)}
          onSave={load}
        />
      )}
    </div>
    </AppLayout></AuthProvider>
  )
}
