'use client'

import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useAlerts } from '@/hooks/useVulnerabilities'
import { StatCard, LoadingState, SeverityBadge, EmptyState, Table } from '@/components/ui'
import { AlertTriangle, CheckCircle, Bell } from 'lucide-react'
import type { Alert } from '@/types'

function AlertsContent() {
  const { alerts, loading, resolve } = useAlerts()

  const displayAlerts = alerts.length > 0 ? alerts : []
  if (loading) return <LoadingState text="Loading alerts..." />

  const open     = displayAlerts.filter(a => !a.is_resolved).length
  const resolved = displayAlerts.filter(a => a.is_resolved).length
  const critical = displayAlerts.filter(a => a.severity === 'Critical' && !a.is_resolved).length

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-base font-semibold text-gray-100">Alerts</h1>
        <p className="text-xs text-gray-500 mt-0.5">{open} open alerts requiring attention</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard label="Open Alerts"     value={open}     icon={Bell}          color="red" />
        <StatCard label="Critical"        value={critical}  icon={AlertTriangle} color="red" />
        <StatCard label="Resolved"        value={resolved}  icon={CheckCircle}   color="green" />
      </div>

      <div className="card">
        {displayAlerts.length === 0 ? (
          <EmptyState title="No alerts" description="All clear! No active alerts at this time." />
        ) : (
          <Table headers={['Type', 'Severity', 'Message', 'Status', 'Time', 'Action']}>
            {displayAlerts.map((a: Alert) => (
              <tr key={a.id} className="table-row">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${a.is_resolved ? 'text-gray-500' : 'text-orange-400'}`} />
                    <span className="text-xs text-gray-300 whitespace-nowrap">{a.alert_type}</span>
                  </div>
                </td>
                <td className="px-4 py-3"><SeverityBadge severity={a.severity} /></td>
                <td className="px-4 py-3 max-w-xs">
                  <p className={`text-xs line-clamp-2 ${a.is_resolved ? 'text-gray-500 line-through' : 'text-gray-300'}`}>
                    {a.message}
                  </p>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium ${a.is_resolved ? 'text-green-400' : 'text-orange-400'}`}>
                    {a.is_resolved ? '✓ Resolved' : '● Open'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-500">{new Date(a.created_at).toLocaleString()}</span>
                </td>
                <td className="px-4 py-3">
                  {!a.is_resolved && (
                    <button onClick={() => resolve(a.id)}
                      className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300 transition">
                      <CheckCircle className="w-3.5 h-3.5" /> Resolve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </div>
  )
}

export default function AlertsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <AlertsContent />
      </AppLayout>
    </AuthProvider>
  )
}
