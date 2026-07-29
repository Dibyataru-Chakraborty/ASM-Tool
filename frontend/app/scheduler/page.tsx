'use client'

import { FormEvent, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  CalendarClock,
  CheckCircle2,
  Clock3,
  Loader2,
  Mail,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Send,
  Trash2,
  XCircle,
} from 'lucide-react'

import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import asm from '@/lib/api'

const CRON_PRESETS = [
  { label: 'Every day at 2:00 PM', value: '0 14 * * *' },
  { label: 'Every day at 2:00 AM', value: '0 2 * * *' },
  { label: 'Every day at midnight', value: '0 0 * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Every 12 hours', value: '0 */12 * * *' },
  { label: 'Every Monday at 9:00 AM', value: '0 9 * * 1' },
  { label: 'Custom…', value: 'custom' },
]

const COMMON_TIMEZONES = [
  'UTC',
  'Asia/Calcutta',
  'Asia/Dhaka',
  'Asia/Singapore',
  'Europe/London',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
]

type AssetOption = {
  id: string
  name: string
  target?: string | null
  asset_type: string
}

type MailStatus = {
  configured: boolean
  host?: string | null
  port: number
  transport: string
  from_address?: string | null
  missing: string[]
}

type SchedulePreview = {
  next_run_at: string
  next_run_local: string
  timezone: string
}

const initialForm = {
  asset_id: '',
  cron_expression: '0 14 * * *',
  timezone: 'UTC',
  is_enabled: true,
  notify_on_completion: false,
  notify_email: '',
  confirmed_authorized: false,
}

function formatScheduleTime(value: string | null, timezone: string) {
  if (!value) return '—'
  try {
    return new Date(value).toLocaleString(undefined, {
      timeZone: timezone,
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return new Date(value).toLocaleString()
  }
}

function SchedulerContent() {
  const [schedules, setSchedules] = useState<any[]>([])
  const [assets, setAssets] = useState<AssetOption[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState(initialForm)
  const [cronPreset, setCronPreset] = useState('0 14 * * *')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [mailStatus, setMailStatus] = useState<MailStatus | null>(null)
  const [mailMessage, setMailMessage] = useState('')
  const [testingMail, setTestingMail] = useState(false)
  const [preview, setPreview] = useState<SchedulePreview | null>(null)
  const [previewError, setPreviewError] = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    const [scheduleResult, assetResult, mailResult, userResult] = await Promise.allSettled([
      asm.getSchedules(),
      asm.getAssets({ limit: 100 }),
      asm.getScheduleMailStatus(),
      asm.getMe(),
    ])

    if (scheduleResult.status === 'fulfilled') {
      setSchedules(scheduleResult.value.schedules || [])
    } else {
      setError(
        scheduleResult.reason?.response?.data?.detail || 'Failed to load schedules',
      )
    }

    if (assetResult.status === 'fulfilled') {
      const availableAssets = assetResult.value.items || assetResult.value.assets || []
      setAssets(availableAssets)
      setForm(current => ({
        ...current,
        asset_id: current.asset_id || availableAssets[0]?.id || '',
      }))
    } else {
      setError(current => current || (
        assetResult.reason?.response?.data?.detail || 'Failed to load assets'
      ))
    }

    if (mailResult.status === 'fulfilled') {
      setMailStatus(mailResult.value)
    }
    if (userResult.status === 'fulfilled') {
      setForm(current => ({
        ...current,
        notify_email: current.notify_email || userResult.value.email || '',
      }))
    }
    setLoading(false)
  }

  useEffect(() => {
    const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
    setForm(current => ({ ...current, timezone: browserTimezone }))
    void load()
  }, [])

  useEffect(() => {
    if (!form.cron_expression || !form.timezone) return
    const timeout = window.setTimeout(async () => {
      try {
        const value = await asm.previewSchedule({
          cron_expression: form.cron_expression,
          timezone: form.timezone,
        })
        setPreview(value)
        setPreviewError('')
      } catch (previewFailure: any) {
        setPreview(null)
        setPreviewError(
          previewFailure.response?.data?.detail || 'Invalid schedule or timezone',
        )
      }
    }, 350)
    return () => window.clearTimeout(timeout)
  }, [form.cron_expression, form.timezone])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setSaving(true)
    setError('')
    try {
      await asm.createSchedule(form)
      setShowAdd(false)
      setForm(current => ({
        ...initialForm,
        timezone: current.timezone,
        notify_email: current.notify_email,
      }))
      setCronPreset('0 14 * * *')
      await load()
    } catch (saveError: any) {
      setError(saveError.response?.data?.detail || 'Failed to create schedule')
    } finally {
      setSaving(false)
    }
  }

  const toggle = async (id: string) => {
    await asm.toggleSchedule(id)
    await load()
  }

  const pause = async (id: string) => {
    await asm.pauseSchedule(id)
    await load()
  }

  const remove = async (id: string) => {
    if (!window.confirm('Delete this schedule?')) return
    await asm.deleteSchedule(id)
    await load()
  }

  const sendTestEmail = async () => {
    setTestingMail(true)
    setMailMessage('')
    try {
      const result = await asm.sendScheduleTestEmail(form.notify_email || undefined)
      setMailMessage(result.message)
    } catch (mailError: any) {
      setMailMessage(mailError.response?.data?.detail || 'Test email failed')
    } finally {
      setTestingMail(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <CalendarClock className="h-5 w-5 text-blue-400" />
            <h1 className="text-base font-bold text-gray-100">Scan Scheduler</h1>
          </div>
          <p className="mt-1 text-xs text-gray-500">
            Persistent timezone-aware automatic scans
          </p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => void load()} className="btn-gray inline-flex items-center gap-2 text-sm">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button type="button" onClick={() => setShowAdd(!showAdd)} className="btn-blue inline-flex items-center gap-2 text-sm">
            <Plus className="h-4 w-4" />
            New Schedule
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-300">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {showAdd && (
        <div className="card p-5">
          <h2 className="mb-4 text-sm font-semibold text-gray-200">Create Schedule</h2>
          <form onSubmit={save} className="space-y-4">
            <div>
              <label className="mb-1 block text-xs text-gray-500">Asset *</label>
              <select
                required
                className="input"
                value={form.asset_id}
                onChange={event => setForm(current => ({
                  ...current,
                  asset_id: event.target.value,
                }))}
              >
                <option value="">— Select asset —</option>
                {assets.map(asset => (
                  <option key={asset.id} value={asset.id}>
                    {asset.name} ({asset.target || asset.asset_type})
                  </option>
                ))}
              </select>
              {assets.length === 0 && !loading && (
                <p className="mt-1.5 text-xs text-yellow-400">
                  No active assets found. <Link href="/assets" className="underline">Create an asset</Link> first.
                </p>
              )}
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-gray-500">Schedule</label>
                <select
                  className="input"
                  value={cronPreset}
                  onChange={event => {
                    const value = event.target.value
                    setCronPreset(value)
                    if (value !== 'custom') {
                      setForm(current => ({ ...current, cron_expression: value }))
                    }
                  }}
                >
                  {CRON_PRESETS.map(preset => (
                    <option key={preset.value} value={preset.value}>{preset.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">Timezone</label>
                <input
                  className="input"
                  list="scheduler-timezones"
                  value={form.timezone}
                  onChange={event => setForm(current => ({
                    ...current,
                    timezone: event.target.value,
                  }))}
                  placeholder="Asia/Calcutta"
                  required
                />
                <datalist id="scheduler-timezones">
                  {COMMON_TIMEZONES.map(timezone => (
                    <option key={timezone} value={timezone} />
                  ))}
                </datalist>
              </div>
            </div>

            {cronPreset === 'custom' && (
              <div>
                <label className="mb-1 block text-xs text-gray-500">Cron expression</label>
                <input
                  className="input font-mono"
                  placeholder="0 14 * * *"
                  value={form.cron_expression}
                  onChange={event => setForm(current => ({
                    ...current,
                    cron_expression: event.target.value,
                  }))}
                  required
                />
                <p className="mt-1 text-[10px] text-gray-600">
                  Format: minute hour day month weekday
                </p>
              </div>
            )}

            <div className={`rounded-lg border p-3 text-xs ${
              previewError
                ? 'border-red-500/20 bg-red-500/10 text-red-300'
                : 'border-blue-500/20 bg-blue-500/10 text-blue-300'
            }`}>
              <div className="flex items-center gap-2">
                <Clock3 className="h-4 w-4" />
                {previewError
                  ? previewError
                  : preview
                    ? `Next run: ${formatScheduleTime(preview.next_run_at, preview.timezone)} (${preview.timezone})`
                    : 'Calculating next run…'}
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <label className="flex cursor-pointer items-center gap-2 text-xs text-gray-400">
                <input
                  type="checkbox"
                  checked={form.is_enabled}
                  onChange={event => setForm(current => ({
                    ...current,
                    is_enabled: event.target.checked,
                  }))}
                />
                Enable immediately
              </label>
              <label className="flex cursor-pointer items-center gap-2 text-xs text-gray-400">
                <input
                  type="checkbox"
                  checked={form.notify_on_completion}
                  onChange={event => setForm(current => ({
                    ...current,
                    notify_on_completion: event.target.checked,
                  }))}
                />
                Email after completion or failure
              </label>
              <label className="flex cursor-pointer items-center gap-2 text-xs text-gray-400">
                <input
                  type="checkbox"
                  required
                  checked={form.confirmed_authorized}
                  onChange={event => setForm(current => ({
                    ...current,
                    confirmed_authorized: event.target.checked,
                  }))}
                />
                I own this target or have written permission
              </label>
            </div>

            {form.notify_on_completion && (
              <div className="rounded-lg border border-[#30363d] bg-[#0d1117] p-3">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-gray-300">Completion email</span>
                  </div>
                  <span className={`text-[10px] ${mailStatus?.configured ? 'text-green-400' : 'text-yellow-400'}`}>
                    {mailStatus?.configured ? 'SMTP ready' : 'SMTP not configured'}
                  </span>
                </div>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    className="input"
                    type="email"
                    required
                    placeholder="alerts@company.com"
                    value={form.notify_email}
                    onChange={event => setForm(current => ({
                      ...current,
                      notify_email: event.target.value,
                    }))}
                  />
                  <button
                    type="button"
                    onClick={() => void sendTestEmail()}
                    disabled={!mailStatus?.configured || testingMail || !form.notify_email}
                    className="btn-gray inline-flex shrink-0 items-center justify-center gap-2 text-xs"
                  >
                    {testingMail ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                    Send test
                  </button>
                </div>
                {!mailStatus?.configured && (
                  <p className="mt-2 text-[10px] text-yellow-400">
                    Add {mailStatus?.missing?.join(', ') || 'SMTP settings'} to backend/.env.
                  </p>
                )}
                {mailMessage && <p className="mt-2 text-[10px] text-gray-400">{mailMessage}</p>}
              </div>
            )}

            <div className="flex gap-2">
              <button type="button" onClick={() => setShowAdd(false)} className="btn-gray flex-1 text-sm">
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving || assets.length === 0 || Boolean(previewError)}
                className="btn-blue flex flex-1 items-center justify-center gap-2 text-sm"
              >
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                {saving ? 'Saving…' : 'Create Schedule'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-gray-600">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm">Loading schedules…</span>
          </div>
        ) : schedules.length === 0 ? (
          <div className="py-12 text-center">
            <CalendarClock className="mx-auto h-8 w-8 text-gray-600" />
            <p className="mb-2 mt-3 text-sm text-gray-500">No schedules yet</p>
            <button onClick={() => setShowAdd(true)} className="btn-blue text-xs">
              Create first schedule
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1040px] text-xs">
              <thead>
                <tr className="border-b border-[#21262d]">
                  {['Asset', 'Schedule', 'Status', 'Next Run', 'Last Run', 'Email', 'Stats', 'Actions'].map(header => (
                    <th key={header} className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500">
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {schedules.map(schedule => (
                  <tr key={schedule.id} className="border-b border-[#21262d] transition hover:bg-[#1c2128]">
                    <td className="px-4 py-3">
                      <p className="font-medium text-gray-200">{schedule.asset_name}</p>
                      <p className="max-w-52 truncate font-mono text-[10px] text-gray-500">{schedule.target}</p>
                    </td>
                    <td className="px-4 py-3">
                      <code className="rounded border border-[#30363d] bg-[#0d1117] px-2 py-0.5 text-gray-300">
                        {schedule.cron_expression}
                      </code>
                      <p className="mt-1 text-[10px] text-gray-500">{schedule.timezone}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {schedule.is_enabled && !schedule.is_paused
                          ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                          : <Pause className="h-3.5 w-3.5 text-yellow-400" />}
                        <span className={schedule.is_enabled && !schedule.is_paused ? 'text-green-400' : 'text-gray-500'}>
                          {!schedule.is_enabled ? 'Disabled' : schedule.is_paused ? 'Paused' : 'Enabled'}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      {formatScheduleTime(schedule.next_run_at, schedule.timezone)}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-gray-400">{formatScheduleTime(schedule.last_run_at, schedule.timezone)}</p>
                      {schedule.last_run_status && (
                        <p className={`mt-1 text-[10px] ${
                          schedule.last_run_status === 'completed' ? 'text-green-400'
                            : schedule.last_run_status === 'running' ? 'text-blue-400'
                              : schedule.last_run_status === 'queued' ? 'text-blue-400'
                                : 'text-red-400'
                        }`}>
                          {schedule.last_run_status}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {schedule.notify_on_completion ? (
                        <>
                          <p className="max-w-40 truncate text-gray-400">{schedule.notify_email}</p>
                          <p className={`mt-1 text-[10px] ${
                            schedule.notification_status === 'sent' ? 'text-green-400'
                              : schedule.notification_status?.startsWith('failed') ? 'text-red-400'
                                : 'text-gray-600'
                          }`}>
                            {schedule.notification_status || 'ready'}
                          </p>
                        </>
                      ) : <span className="text-gray-600">Off</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-500">
                      <p>{schedule.run_count} runs</p>
                      {schedule.fail_count > 0 && <p className="text-red-400">{schedule.fail_count} failures</p>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => void toggle(schedule.id)}
                          title={schedule.is_enabled ? 'Disable' : 'Enable'}
                          className={schedule.is_enabled ? 'text-red-400' : 'text-green-400'}
                        >
                          {schedule.is_enabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                        </button>
                        <button
                          type="button"
                          onClick={() => void pause(schedule.id)}
                          title={schedule.is_paused ? 'Resume' : 'Pause'}
                          className="text-yellow-400"
                        >
                          {schedule.is_paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
                        </button>
                        <button
                          type="button"
                          onClick={() => void remove(schedule.id)}
                          title="Delete"
                          className="text-red-400"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

export default function SchedulerPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <SchedulerContent />
      </AppLayout>
    </AuthProvider>
  )
}
