'use client'
import { useState, useEffect } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const CRON_PRESETS = [
  {label:'Every day at 2:00 AM', value:'0 2 * * *'},
  {label:'Every day at midnight',value:'0 0 * * *'},
  {label:'Every 6 hours',        value:'0 */6 * * *'},
  {label:'Every 12 hours',       value:'0 */12 * * *'},
  {label:'Every Monday 9 AM',    value:'0 9 * * 1'},
  {label:'Custom…',              value:'custom'},
]

export default function SchedulerPage() {
  const [schedules, setSchedules] = useState<any[]>([])
  const [assets, setAssets]       = useState<any[]>([])
  const [loading, setLoading]     = useState(true)
  const [showAdd, setShowAdd]     = useState(false)
  const [form, setForm]           = useState({ asset_id:'', cron_expression:'0 2 * * *', is_enabled:true, notify_on_completion:false, notify_email:'' })
  const [cronPreset, setCronPreset] = useState('0 2 * * *')
  const [saving, setSaving]       = useState(false)
  const [err, setErr]             = useState('')

  const load = async () => {
    setLoading(true)
    const [s, a] = await Promise.all([asm.getSchedules(), asm.getAssets()])
    setSchedules(s.schedules || [])
    setAssets(a.assets || [])
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setSaving(true); setErr('')
    try {
      await asm.createSchedule({ ...form, cron_expression: form.cron_expression || cronPreset })
      setShowAdd(false); load()
    } catch(e:any) { setErr(e.response?.data?.detail || 'Failed') }
    setSaving(false)
  }

  const toggle   = async (id: string) => { await asm.toggleSchedule(id); load() }
  const pause    = async (id: string) => { await asm.pauseSchedule(id); load() }
  const del      = async (id: string) => { if (confirm('Delete this schedule?')) { await asm.deleteSchedule(id); load() } }

  const assetName = (id: string) => assets.find(a=>a.id===id)?.target || id

  return (
    <AuthProvider><AppLayout>
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-gray-100">Scan Scheduler</h1>
          <p className="text-xs text-gray-500">Cron-based automatic scanning</p>
        </div>
        <button onClick={()=>setShowAdd(!showAdd)} className="btn-blue text-sm">+ New Schedule</button>
      </div>

      {/* Add form */}
      {showAdd && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-200 mb-4">Create Schedule</h2>
          {err && <p className="text-xs text-red-400 bg-red-500/10 rounded-lg p-2 mb-3">{err}</p>}
          <form onSubmit={save} className="space-y-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Asset *</label>
              <select required className="input" value={form.asset_id} onChange={e=>setForm(f=>({...f,asset_id:e.target.value}))}>
                <option value="">— Select asset —</option>
                {assets.map(a=><option key={a.id} value={a.id}>{a.name} ({a.target})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Schedule</label>
              <select className="input mb-2" value={cronPreset}
                onChange={e=>{setCronPreset(e.target.value);if(e.target.value!=='custom')setForm(f=>({...f,cron_expression:e.target.value}))}}>
                {CRON_PRESETS.map(p=><option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
              {cronPreset === 'custom' && (
                <input className="input font-mono" placeholder="0 2 * * *" value={form.cron_expression}
                  onChange={e=>setForm(f=>({...f,cron_expression:e.target.value}))} />
              )}
              <p className="text-[10px] text-gray-600 mt-1">Cron format: minute hour day month weekday</p>
            </div>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
                <input type="checkbox" checked={form.is_enabled} onChange={e=>setForm(f=>({...f,is_enabled:e.target.checked}))} />
                Enable immediately
              </label>
              <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
                <input type="checkbox" checked={form.notify_on_completion} onChange={e=>setForm(f=>({...f,notify_on_completion:e.target.checked}))} />
                Email notification
              </label>
            </div>
            {form.notify_on_completion && (
              <input className="input" type="email" placeholder="alerts@company.com" value={form.notify_email}
                onChange={e=>setForm(f=>({...f,notify_email:e.target.value}))} />
            )}
            <div className="flex gap-2">
              <button type="button" onClick={()=>setShowAdd(false)} className="btn-gray flex-1 text-sm">Cancel</button>
              <button type="submit" disabled={saving} className="btn-blue flex-1 text-sm">{saving?'Saving…':'Create Schedule'}</button>
            </div>
          </form>
        </div>
      )}

      {/* List */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="py-12 text-center animate-pulse text-gray-600">Loading schedules…</div>
        ) : schedules.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-2xl mb-2">🕐</p>
            <p className="text-sm text-gray-500 mb-2">No schedules yet</p>
            <button onClick={()=>setShowAdd(true)} className="btn-blue text-xs">Create first schedule</button>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead><tr className="border-b border-[#21262d]">
              {['Asset','Cron','Status','Next Run','Last Run','Stats','Actions'].map(h=>(
                <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wide">{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {schedules.map((s:any)=>(
                <tr key={s.id} className="border-b border-[#21262d] hover:bg-[#1c2128] transition">
                  <td className="px-4 py-3 font-mono text-gray-200">{assetName(s.asset_id)}</td>
                  <td className="px-4 py-3">
                    <code className="bg-[#0d1117] border border-[#30363d] px-2 py-0.5 rounded text-gray-300">{s.cron_expression}</code>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-col gap-1">
                      <span className={`text-[10px] font-bold ${s.is_enabled?'text-green-400':'text-gray-600'}`}>
                        {s.is_enabled ? '● Enabled' : '○ Disabled'}
                      </span>
                      {s.is_paused && <span className="text-[10px] text-yellow-400">⏸ Paused</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div>
                      <p className="text-gray-400">{s.last_run_at ? new Date(s.last_run_at).toLocaleDateString() : '—'}</p>
                      {s.last_run_status && (
                        <p className={`text-[10px] ${s.last_run_status==='completed'?'text-green-400':'text-red-400'}`}>{s.last_run_status}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    <p>✅ {s.run_count} runs</p>
                    {s.fail_count > 0 && <p className="text-red-400">❌ {s.fail_count} fails</p>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button onClick={()=>toggle(s.id)} className={`text-xs ${s.is_enabled?'text-red-400 hover:text-red-300':'text-green-400 hover:text-green-300'} transition`}>
                        {s.is_enabled?'Disable':'Enable'}
                      </button>
                      <span className="text-gray-700">|</span>
                      <button onClick={()=>pause(s.id)} className="text-xs text-yellow-400 hover:text-yellow-300 transition">
                        {s.is_paused?'Resume':'Pause'}
                      </button>
                      <span className="text-gray-700">|</span>
                      <button onClick={()=>del(s.id)} className="text-xs text-red-400 hover:text-red-300 transition">Del</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
    </AppLayout></AuthProvider>
  )
}
