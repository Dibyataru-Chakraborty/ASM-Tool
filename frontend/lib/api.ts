import axios from 'axios'

export const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const client = axios.create({ baseURL: API, timeout: 30000 })

client.interceptors.request.use(cfg => {
  const t = typeof window !== 'undefined' ? localStorage.getItem('access_token') : ''
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

client.interceptors.response.use(r => r, err => {
  if (err.response?.status === 401) {
    localStorage.removeItem('access_token')
    window.location.href = '/login'
  }
  return Promise.reject(err)
})

// ASM endpoints
export const asm = {
  // Assets
  getAssets:    (p?: any)  => client.get('/api/v1/assets', { params: p }).then(r => r.data),
  getAsset:     (id: string) => client.get(`/api/v1/assets/${id}`).then(r => r.data),
  createAsset:  (b: any)   => client.post('/api/v1/assets', b).then(r => r.data),
  updateAsset:  (id: string, b: any) => client.put(`/api/v1/assets/${id}`, b).then(r => r.data),
  deleteAsset:  (id: string) => client.delete(`/api/v1/assets/${id}`),

  // Schedules
  getSchedules:    (p?: any)   => client.get('/api/v1/schedules', { params: p }).then(r => r.data),
  createSchedule:  (b: any)    => client.post('/api/v1/schedules', b).then(r => r.data),
  toggleSchedule:  (id: string) => client.put(`/api/v1/schedules/${id}/toggle`).then(r => r.data),
  pauseSchedule:   (id: string) => client.put(`/api/v1/schedules/${id}/pause`).then(r => r.data),
  deleteSchedule:  (id: string) => client.delete(`/api/v1/schedules/${id}`),
  previewSchedule: (b: any) => client.post('/api/v1/schedules/preview', b).then(r => r.data),
  getScheduleMailStatus: () => client.get('/api/v1/schedules/mail/status').then(r => r.data),
  sendScheduleTestEmail: (recipient?: string) => client.post(
    '/api/v1/schedules/mail/test',
    recipient ? { recipient } : {},
  ).then(r => r.data),

  // Scan jobs
  triggerScan:  (asset_id: string) => client.post('/api/v1/scans/trigger', { asset_id }).then(r => r.data),
  getScans:     (p?: any) => client.get('/api/v1/scans', { params: p }).then(r => r.data),
  getScan:      (id: string) => client.get(`/api/v1/scans/${id}`).then(r => r.data),
  getScanTools: (id: string) => client.get(`/api/v1/scans/${id}/tools`).then(r => r.data),
  getScanLogs:  (id: string, since?: string) => client.get(`/api/v1/scans/${id}/logs`, { params: since ? { since_id: since } : {} }).then(r => r.data),
  cancelScan:   (id: string) => client.post(`/api/v1/scans/${id}/cancel`).then(r => r.data),
  deleteScan:   (id: string) => client.delete(`/api/v1/scans/${id}`).then(r => r.data),
  
  // Real Recon results
  getReconStatus: (scanId: string) => client.get(`/api/v1/recon/status/${scanId}`).then(r => r.data),
  getReconSubdomains: (domainId: string, scanId?: string) => client.get(
    '/api/v1/recon/subdomains',
    { params: { domain_id: domainId, ...(scanId ? { scan_id: scanId } : {}) } },
  ).then(r => r.data),
  getReconIPs: (domainId: string) => client.get(
    '/api/v1/recon/ips',
    { params: { domain_id: domainId } },
  ).then(r => r.data),
  getReconVulnerabilities: (domainId: string) => client.get(
    '/api/v1/recon/vulnerabilities',
    { params: { domain_id: domainId } },
  ).then(r => r.data),
  getReconAIServiceAssessments: (scanId: string) => client.get(
    '/api/v1/recon/ai-service-assessments',
    { params: { scan_id: scanId } },
  ).then(r => r.data),
  getReconScreenshots: (domainId: string) => client.get(
    '/api/v1/recon/screenshots',
    { params: { domain_id: domainId } },
  ).then(r => r.data),

  // Vulnerabilities
  getVulns:     (p?: any) => client.get('/api/v1/vulnerabilities', { params: p }).then(r => r.data),
  getVulnerabilities: (severity?: string) => client.get('/api/v1/vulnerabilities', { params: severity ? { severity } : {} }).then(r => r.data),
  getVuln:      (id: string) => client.get(`/api/v1/vulnerabilities/${id}`).then(r => r.data),
  markFP:       (id: string) => client.post(`/api/v1/vulnerabilities/${id}/false-positive`).then(r => r.data),

  // Reports
  getReports:   (p?: any) => client.get('/api/v1/reports', { params: p }).then(r => r.data),
  getReport:    (id: string) => client.get(`/api/v1/reports/${id}`).then(r => r.data),
  exportReport: (id: string, fmt: string) => `${API}/api/v1/reports/${id}/export/${fmt}`,

  // Dashboard
  getDashboard: () => client.get('/api/v1/dashboard/full').then(r => r.data),
  getRiskSummary: () => client.get('/api/v1/dashboard/risk-summary').then(r => r.data),
  getTimeline: (days = 30) => client.get('/api/v1/dashboard/timeline', { params: { days } }).then(r => r.data),

  // AI Analysis (Phase 7)
  getAIProviders: () => client.get('/api/v1/ai/providers').then(r => r.data),
  analyzeVulnerability: (id: string, provider: string) => client.post(`/api/v1/ai/analyze/vulnerability/${id}`, null, { params: { provider } }).then(r => r.data),
  prioritizeVulnerabilities: (assetId: string) => client.post('/api/v1/ai/prioritize', null, { params: { asset_id: assetId } }).then(r => r.data),
  generateAIReport: (assetId: string) => client.post(`/api/v1/ai/report/executive/${assetId}`).then(r => r.data),
  getRemediationSteps: (id: string) => client.post(`/api/v1/ai/remediate/${id}`).then(r => r.data),

  // Alerts
  getAlerts: (assetId?: string) => client.get('/api/v1/alerts', { params: assetId ? { asset_id: assetId } : {} }).then(r => r.data),
  resolveAlert: (id: string) => client.post(`/api/v1/alerts/${id}/resolve`).then(r => r.data),

  // Auth
  register: (b: any) => client.post('/api/v1/auth/register', b).then(r => r.data),
  login: (b: any) => client.post('/api/v1/auth/login', b).then(r => r.data),
  logout: () => client.post('/api/v1/auth/logout').then(r => r.data),
  getMe: () => client.get('/api/v1/auth/me').then(r => r.data),
}

export default asm
