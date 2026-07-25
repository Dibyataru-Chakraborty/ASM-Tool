'use client'

import { useState } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import api from '@/lib/api'
import { StatCard, StatusBadge, Modal, Table } from '@/components/ui'
import { FileText, Download, Plus, RefreshCw } from 'lucide-react'
import type { Report } from '@/types'

const REPORT_TYPES = ['executive', 'technical', 'compliance', 'vulnerability']
const FORMATS = ['pdf', 'excel', 'html']

function NewReportForm({ onClose, onSave }: { onClose: () => void; onSave: () => void }) {
  const [form, setForm] = useState({ asset_id: '', report_type: 'executive', format: 'pdf' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.generateReport(form.asset_id, form.report_type, form.format)
      onSave(); onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to generate report')
    } finally { setLoading(false) }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Asset ID *</label>
        <input className="input" placeholder="asset-uuid" required
          value={form.asset_id} onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))} />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Report Type</label>
        <select className="input" value={form.report_type}
          onChange={e => setForm(f => ({ ...f, report_type: e.target.value }))}>
          {REPORT_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
        </select>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-400 mb-1.5">Format</label>
        <div className="flex gap-2">
          {FORMATS.map(f => (
            <button key={f} type="button"
              onClick={() => setForm(fm => ({ ...fm, format: f }))}
              className={`flex-1 py-2 rounded-lg border text-xs font-medium transition ${
                form.format === f
                  ? 'bg-blue-600 border-blue-600 text-white'
                  : 'bg-[#0d1117] border-[#30363d] text-gray-400 hover:border-gray-500'
              }`}>
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
      <div className="flex gap-3 pt-2">
        <button type="button" className="btn-secondary text-sm flex-1" onClick={onClose}>Cancel</button>
        <button type="submit" disabled={loading} className="btn-primary text-sm flex-1">
          {loading ? 'Generating...' : 'Generate Report'}
        </button>
      </div>
    </form>
  )
}

function ReportsContent() {
  const [createOpen, setCreateOpen] = useState(false)

  const mockReports: Report[] = [
    { id: '1', asset_id: 'a1', report_type: 'executive',      format: 'pdf',   title: 'Executive Risk Summary - Q1 2024',          status: 'generated', created_at: new Date().toISOString() },
    { id: '2', asset_id: 'a1', report_type: 'technical',      format: 'pdf',   title: 'Technical Vulnerability Report - example.com', status: 'generated', created_at: new Date().toISOString() },
    { id: '3', asset_id: 'a2', report_type: 'compliance',     format: 'excel', title: 'SOC2 Compliance Assessment',                   status: 'generated', created_at: new Date().toISOString() },
    { id: '4', asset_id: 'a3', report_type: 'vulnerability',  format: 'html',  title: 'Full Vulnerability Scan - api.example.com',    status: 'generating', created_at: new Date().toISOString() },
  ]

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-gray-100">Reports</h1>
          <p className="text-xs text-gray-500 mt-0.5">{mockReports.length} reports generated</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary text-sm flex items-center gap-2"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          <button className="btn-primary text-sm flex items-center gap-2" onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" /> Generate Report
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Reports"  value={mockReports.length}                                           icon={FileText} color="blue" />
        <StatCard label="Generated"      value={mockReports.filter(r => r.status === 'generated').length}    color="green" />
        <StatCard label="Generating"     value={mockReports.filter(r => r.status === 'generating').length}   color="yellow" />
        <StatCard label="PDF Reports"    value={mockReports.filter(r => r.format === 'pdf').length}          color="purple" />
      </div>

      <div className="card">
        <Table headers={['Title', 'Type', 'Format', 'Status', 'Generated', 'Actions']}>
          {mockReports.map((r: Report) => (
            <tr key={r.id} className="table-row">
              <td className="px-4 py-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-500/20">
                    <FileText className="w-3.5 h-3.5 text-purple-400" />
                  </div>
                  <span className="text-xs text-gray-200 font-medium">{r.title}</span>
                </div>
              </td>
              <td className="px-4 py-3">
                <span className="text-xs text-gray-400 capitalize">{r.report_type}</span>
              </td>
              <td className="px-4 py-3">
                <span className="text-xs font-mono uppercase text-blue-400">{r.format}</span>
              </td>
              <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
              <td className="px-4 py-3">
                <span className="text-xs text-gray-500">{new Date(r.created_at).toLocaleDateString()}</span>
              </td>
              <td className="px-4 py-3">
                {r.status === 'generated' && (
                  <button className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition">
                    <Download className="w-3.5 h-3.5" /> Download
                  </button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </div>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Generate New Report">
        <NewReportForm onClose={() => setCreateOpen(false)} onSave={() => {}} />
      </Modal>
    </div>
  )
}

export default function ReportsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <ReportsContent />
      </AppLayout>
    </AuthProvider>
  )
}
