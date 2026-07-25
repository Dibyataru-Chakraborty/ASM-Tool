'use client'

import { useState } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { useAuth } from '@/lib/auth'
import api from '@/lib/api'
import { CheckCircle, AlertCircle, Eye, EyeOff, Key, Bell, Shield, Database } from 'lucide-react'

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="card p-6 space-y-5">
      <div className="flex items-center gap-2.5 pb-3 border-b border-[#21262d]">
        <div className="p-1.5 bg-blue-500/10 border border-blue-500/20 rounded-lg">
          <Icon className="w-4 h-4 text-blue-400" />
        </div>
        <h2 className="text-sm font-semibold text-gray-200">{title}</h2>
      </div>
      {children}
    </div>
  )
}

function ApiKeyField({ label, envKey, placeholder }: { label: string; envKey: string; placeholder: string }) {
  const [show, setShow] = useState(false)
  const [value, setValue] = useState('')
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <label className="text-xs font-medium text-gray-400">{label}</label>
        <span className="text-[10px] text-gray-600 font-mono">{envKey}</span>
      </div>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <input
            type={show ? 'text' : 'password'}
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder={placeholder}
            className="input pr-10 text-xs"
          />
          <button type="button" onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
        <button onClick={handleSave} className={`px-3 py-2 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${saved ? 'bg-green-600 text-white' : 'btn-secondary'}`}>
          {saved ? <><CheckCircle className="w-3.5 h-3.5" /> Saved</> : 'Save'}
        </button>
      </div>
    </div>
  )
}

function SettingsContent() {
  const { user } = useAuth()
  const [profile, setProfile] = useState({ full_name: user?.full_name || '', email: user?.email || '' })
  const [passwords, setPasswords] = useState({ old: '', new: '', confirm: '' })
  const [pwError, setPwError] = useState('')
  const [pwSuccess, setPwSuccess] = useState(false)
  const [notifications, setNotifications] = useState({
    email: true, slack: false, critical_only: false, weekly_report: true
  })

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setPwError('')
    if (passwords.new !== passwords.confirm) { setPwError('Passwords do not match'); return }
    try {
      await api.changePassword(passwords.old, passwords.new)
      setPwSuccess(true)
      setPasswords({ old: '', new: '', confirm: '' })
      setTimeout(() => setPwSuccess(false), 3000)
    } catch (err: any) {
      setPwError(err.response?.data?.detail || 'Failed to change password')
    }
  }

  return (
    <div className="space-y-5 max-w-2xl">
      <div>
        <h1 className="text-base font-semibold text-gray-100">Settings</h1>
        <p className="text-xs text-gray-500 mt-0.5">Manage your account and API integrations</p>
      </div>

      {/* Profile */}
      <Section title="Profile" icon={Shield}>
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Full Name</label>
            <input className="input" value={profile.full_name}
              onChange={e => setProfile(p => ({ ...p, full_name: e.target.value }))} />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Email</label>
            <input className="input opacity-60 cursor-not-allowed" type="email" value={profile.email} disabled />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Role</label>
            <div className="input bg-[#0d1117] opacity-60 cursor-not-allowed capitalize">{user?.role}</div>
          </div>
          <button className="btn-primary text-sm">Save Profile</button>
        </div>
      </Section>

      {/* Password */}
      <Section title="Change Password" icon={Key}>
        <form onSubmit={handlePasswordChange} className="space-y-3">
          {pwError && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20">
              <AlertCircle className="w-3.5 h-3.5 text-red-400" />
              <p className="text-xs text-red-400">{pwError}</p>
            </div>
          )}
          {pwSuccess && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-green-500/10 border border-green-500/20">
              <CheckCircle className="w-3.5 h-3.5 text-green-400" />
              <p className="text-xs text-green-400">Password changed successfully</p>
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Current Password</label>
            <input className="input" type="password" placeholder="••••••••••••" required
              value={passwords.old} onChange={e => setPasswords(p => ({ ...p, old: e.target.value }))} />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">New Password</label>
            <input className="input" type="password" placeholder="••••••••••••" required
              value={passwords.new} onChange={e => setPasswords(p => ({ ...p, new: e.target.value }))} />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Confirm New Password</label>
            <input className="input" type="password" placeholder="••••••••••••" required
              value={passwords.confirm} onChange={e => setPasswords(p => ({ ...p, confirm: e.target.value }))} />
          </div>
          <button type="submit" className="btn-primary text-sm">Update Password</button>
        </form>
      </Section>

      {/* AI API Keys */}
      <Section title="AI Provider API Keys" icon={Database}>
        <p className="text-xs text-gray-500 -mt-2">
          Configure API keys in <span className="font-mono text-blue-400">backend/.env</span> file. Keys shown here are for reference only.
        </p>
        <div className="space-y-4">
          <ApiKeyField label="Anthropic Claude"  envKey="CLAUDE_API_KEY"       placeholder="sk-ant-api03-..." />
          <ApiKeyField label="OpenAI GPT-4"      envKey="OPENAI_API_KEY"       placeholder="sk-proj-..." />
          <ApiKeyField label="Google Gemini"     envKey="GEMINI_API_KEY"       placeholder="AIzaSy..." />
          <ApiKeyField label="Cohere"            envKey="COHERE_API_KEY"       placeholder="..." />
        </div>
      </Section>

      {/* Threat Intelligence Keys */}
      <Section title="Threat Intelligence API Keys" icon={Shield}>
        <div className="space-y-4">
          <ApiKeyField label="VirusTotal"   envKey="VIRUSTOTAL_API_KEY"   placeholder="64-char hex key" />
          <ApiKeyField label="Shodan"       envKey="SHODAN_API_KEY"       placeholder="shodan api key" />
          <ApiKeyField label="AbuseIPDB"    envKey="ABUSEIPDB_API_KEY"   placeholder="abuseipdb key" />
          <ApiKeyField label="GreyNoise"    envKey="GREYNOISE_API_KEY"   placeholder="greynoise key" />
          <ApiKeyField label="GitHub Token" envKey="GITHUB_TOKEN"         placeholder="ghp_..." />
        </div>
      </Section>

      {/* Notifications */}
      <Section title="Notifications" icon={Bell}>
        <div className="space-y-3">
          {[
            { key: 'email',         label: 'Email Notifications',        desc: 'Receive alerts via email' },
            { key: 'slack',         label: 'Slack Notifications',        desc: 'Send alerts to Slack channel' },
            { key: 'critical_only', label: 'Critical Alerts Only',       desc: 'Only notify on Critical severity' },
            { key: 'weekly_report', label: 'Weekly Summary Report',      desc: 'Receive weekly digest every Monday' },
          ].map(({ key, label, desc }) => (
            <div key={key} className="flex items-center justify-between py-2">
              <div>
                <p className="text-xs font-medium text-gray-300">{label}</p>
                <p className="text-[10px] text-gray-500 mt-0.5">{desc}</p>
              </div>
              <button
                onClick={() => setNotifications(n => ({ ...n, [key]: !n[key as keyof typeof n] }))}
                className={`relative w-9 h-5 rounded-full transition-colors duration-200 ${
                  notifications[key as keyof typeof notifications] ? 'bg-blue-600' : 'bg-[#30363d]'
                }`}
              >
                <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${
                  notifications[key as keyof typeof notifications] ? 'translate-x-4' : 'translate-x-0'
                }`} />
              </button>
            </div>
          ))}
        </div>
        <div className="pt-2">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Slack Webhook URL</label>
            <input className="input text-xs" placeholder="https://hooks.slack.com/services/..." />
          </div>
        </div>
      </Section>
    </div>
  )
}

export default function SettingsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <SettingsContent />
      </AppLayout>
    </AuthProvider>
  )
}
