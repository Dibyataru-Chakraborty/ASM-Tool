'use client'
import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth'
import { client } from '@/lib/api'
import AppLayout from '@/components/layout/AppLayout'
import { AuthProvider } from '@/lib/auth'

const SECTIONS = [
  {
    title: '🤖 AI Providers',
    keys: [
      { key: 'GEMINI_API_KEY',  label: 'Google Gemini', hint: 'aistudio.google.com', primary: true },
      { key: 'CLAUDE_API_KEY',  label: 'Anthropic Claude', hint: 'console.anthropic.com' },
      { key: 'OPENAI_API_KEY',  label: 'OpenAI GPT-4', hint: 'platform.openai.com' },
    ]
  },
  {
    title: '🔍 Threat Intelligence',
    keys: [
      { key: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal', hint: 'virustotal.com', primary: true },
      { key: 'SHODAN_API_KEY',     label: 'Shodan', hint: 'shodan.io', primary: true },
      { key: 'ABUSEIPDB_API_KEY',  label: 'AbuseIPDB', hint: 'abuseipdb.com' },
      { key: 'GREYNOISE_API_KEY',  label: 'GreyNoise', hint: 'greynoise.io' },
      { key: 'CENSYS_API_ID',      label: 'Censys ID', hint: 'search.censys.io' },
      { key: 'CENSYS_API_SECRET',  label: 'Censys Secret', hint: 'search.censys.io' },
    ]
  },
  {
    title: '🔔 Notifications',
    keys: [
      { key: 'SLACK_WEBHOOK_URL', label: 'Slack Webhook', hint: 'hooks.slack.com/...' },
      { key: 'GITHUB_TOKEN',      label: 'GitHub Token', hint: 'For secret scanning' },
    ]
  },
]

function SettingsContent() {
  const { user } = useAuth()
  const [providers, setProviders] = useState<any>(null)
  const [pwForm, setPwForm] = useState({ old: '', new_pw: '', confirm: '' })
  const [pwMsg, setPwMsg]   = useState('')

  useEffect(() => {
    client.get('/api/v1/recon/providers/status').then(r => setProviders(r.data)).catch(() => {})
  }, [])

  const changePw = async (e: React.FormEvent) => {
    e.preventDefault()
    if (pwForm.new_pw !== pwForm.confirm) { setPwMsg('❌ Passwords do not match'); return }
    try {
      await client.post('/api/v1/auth/change-password', { old_password: pwForm.old, new_password: pwForm.new_pw })
      setPwMsg('✅ Password changed')
      setPwForm({ old: '', new_pw: '', confirm: '' })
    } catch(e: any) { setPwMsg('❌ ' + (e.response?.data?.detail || 'Failed')) }
    setTimeout(() => setPwMsg(''), 4000)
  }

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-base font-bold text-gray-100">Settings</h1>

      {/* Profile */}
      <div className="card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-200">👤 Profile</h2>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div><p className="text-gray-500 mb-0.5">Name</p><p className="text-gray-200">{user?.full_name}</p></div>
          <div><p className="text-gray-500 mb-0.5">Email</p><p className="text-gray-200">{user?.email}</p></div>
          <div><p className="text-gray-500 mb-0.5">Role</p><p className="text-gray-200 capitalize">{user?.role}</p></div>
        </div>
      </div>

      {/* Change password */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-gray-200 mb-3">🔑 Change Password</h2>
        {pwMsg && <p className="text-xs mb-3">{pwMsg}</p>}
        <form onSubmit={changePw} className="space-y-3">
          <div><label className="block text-xs text-gray-500 mb-1">Current Password</label>
            <input type="password" className="input" required value={pwForm.old} onChange={e => setPwForm(f => ({...f, old: e.target.value}))} />
          </div>
          <div><label className="block text-xs text-gray-500 mb-1">New Password</label>
            <input type="password" className="input" required value={pwForm.new_pw} onChange={e => setPwForm(f => ({...f, new_pw: e.target.value}))} />
          </div>
          <div><label className="block text-xs text-gray-500 mb-1">Confirm New Password</label>
            <input type="password" className="input" required value={pwForm.confirm} onChange={e => setPwForm(f => ({...f, confirm: e.target.value}))} />
          </div>
          <button type="submit" className="btn-blue text-sm">Update Password</button>
        </form>
      </div>

      {/* Provider status */}
      {providers && (
        <>
          {SECTIONS.map(section => (
            <div key={section.title} className="card p-5">
              <h2 className="text-sm font-semibold text-gray-200 mb-3">{section.title}</h2>
              <div className="space-y-2">
                {section.keys.map(k => {
                  const allProviders = {
                    ...providers.ai_providers,
                    ...providers.threat_intelligence,
                    ...providers.notifications,
                  }
                  const configured = allProviders[k.key.toLowerCase().replace(/_api_key|_api_id|_api_secret/g, '')] ||
                    Object.entries(allProviders).find(([key]) => key.includes(k.key.toLowerCase().split('_')[0]))?.[1] as any
                  const isConfigured = configured?.configured ?? false

                  return (
                    <div key={k.key} className="flex items-center justify-between py-2 border-b border-[#21262d] last:border-0">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${isConfigured ? 'bg-green-400' : 'bg-gray-600'}`} />
                          <p className="text-xs text-gray-300">{k.label}</p>
                          {k.primary && <span className="text-[10px] text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1 rounded">Primary</span>}
                        </div>
                        <p className="text-[10px] text-gray-600 ml-3.5 mt-0.5 font-mono">{k.key}</p>
                      </div>
                      <div className="text-right">
                        {isConfigured ? (
                          <span className="text-xs text-green-400">✓ Configured</span>
                        ) : (
                          <a href={`https://${k.hint}`} target="_blank" rel="noreferrer"
                            className="text-xs text-blue-400 hover:text-blue-300">Get key →</a>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
              <p className="text-[10px] text-gray-600 mt-3">
                Set keys in <code className="text-blue-400">backend/.env</code> and restart the server
              </p>
            </div>
          ))}

          {/* PD Tools */}
          <div className="card p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-3">🛠 Security Tools</h2>
            <div className="space-y-2">
              {Object.entries(providers.projectdiscovery_tools || {}).map(([name, info]: any) => (
                <div key={name} className="flex items-center justify-between py-1.5 border-b border-[#21262d] last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${info.available ? 'bg-green-400' : 'bg-red-400'}`} />
                    <span className="text-xs font-mono text-gray-300">{name}</span>
                  </div>
                  {info.available ? (
                    <span className="text-xs text-green-400">✓ Installed</span>
                  ) : (
                    <a href="https://docs.projectdiscovery.io/opensource" target="_blank" rel="noreferrer"
                      className="text-xs text-red-400 hover:text-red-300">Not found — Install</a>
                  )}
                </div>
              ))}
            </div>
            <p className="text-[10px] text-gray-600 mt-3">
              Tools are installed via <code className="text-blue-400">scripts/install_pd_tools.sh</code>
            </p>
          </div>
        </>
      )}
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
