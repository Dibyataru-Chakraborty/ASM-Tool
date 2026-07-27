import axios, { AxiosInstance, AxiosError } from 'axios'
import type {
  AuthResponse, LoginRequest, RegisterRequest, User,
  Asset, AssetStats, PaginatedResponse,
  Scan, Port, Vulnerability, Alert, Report,
  ThreatIntelligence, RiskSummary, DashboardFull,
  AIAnalysis, AIProviders
} from '@/types'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

class ApiClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: BASE_URL,
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000,
    })

    // Request interceptor — attach token
    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('access_token')
      if (token) config.headers.Authorization = `Bearer ${token}`
      return config
    })

    // Response interceptor — handle 401
    this.client.interceptors.response.use(
      (res) => res,
      async (err: AxiosError) => {
        if (err.response?.status === 401) {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
        return Promise.reject(err)
      }
    )
  }

  // ─── Auth ─────────────────────────────────────────────────────────────────
  async login(data: LoginRequest): Promise<AuthResponse> {
    const res = await this.client.post('/api/v1/auth/login', data)
    const auth: AuthResponse = res.data
    localStorage.setItem('access_token', auth.access_token)
    localStorage.setItem('refresh_token', auth.refresh_token)
    return auth
  }

  async register(data: RegisterRequest): Promise<AuthResponse> {
    const res = await this.client.post('/api/v1/auth/register', data)
    return res.data
  }

  async getMe(): Promise<User> {
    const res = await this.client.get('/api/v1/auth/me')
    return res.data
  }

  async logout(): Promise<void> {
    await this.client.post('/api/v1/auth/logout')
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
  }

  async changePassword(old_password: string, new_password: string): Promise<void> {
    await this.client.post('/api/v1/auth/change-password', { old_password, new_password })
  }

  // ─── Assets ───────────────────────────────────────────────────────────────
  async getAssets(skip = 0, limit = 10): Promise<PaginatedResponse<Asset>> {
    const res = await this.client.get('/api/v1/assets', { params: { skip, limit } })
    return res.data
  }

  async getAsset(id: string): Promise<Asset> {
    const res = await this.client.get(`/api/v1/assets/${id}`)
    return res.data
  }

  async createAsset(data: Partial<Asset>): Promise<Asset> {
    const res = await this.client.post('/api/v1/assets', data)
    return res.data
  }

  async updateAsset(id: string, data: Partial<Asset>): Promise<Asset> {
    const res = await this.client.put(`/api/v1/assets/${id}`, data)
    return res.data
  }

  async deleteAsset(id: string): Promise<void> {
    await this.client.delete(`/api/v1/assets/${id}`)
  }

  async archiveAsset(id: string): Promise<Asset> {
    const res = await this.client.post(`/api/v1/assets/${id}/archive`)
    return res.data
  }

  async getAssetStats(id: string): Promise<AssetStats> {
    const res = await this.client.get(`/api/v1/assets/${id}/stats`)
    return res.data
  }

  async getAssetDomains(asset_id: string): Promise<any[]> {
    const res = await this.client.get(`/api/v1/assets/${asset_id}/domains`)
    return res.data
  }

  async getAssetSubdomains(asset_id: string): Promise<{ subdomains: any[]; total: number }> {
    const res = await this.client.get(`/api/v1/assets/${asset_id}/subdomains`)
    return res.data
  }

  async getAssetScreenshots(asset_id: string): Promise<{ screenshots: any[]; total: number }> {
    const res = await this.client.get(`/api/v1/assets/${asset_id}/screenshots`)
    return res.data
  }

  // ─── Scans ────────────────────────────────────────────────────────────────
  async getScans(asset_id: string): Promise<PaginatedResponse<Scan>> {
    const res = await this.client.get('/api/v1/scans', { params: { asset_id } })
    return res.data
  }

  async initiateScan(asset_id: string, scan_type: string, target_domain?: string): Promise<Scan> {
    const res = await this.client.post('/api/v1/scans', { asset_id, scan_type, target_domain })
    return res.data
  }

  async getScan(id: string): Promise<Scan> {
    const res = await this.client.get(`/api/v1/scans/${id}`)
    return res.data
  }

  async cancelScan(id: string): Promise<void> {
    await this.client.get(`/api/v1/scans/${id}/cancel`)
  }

  async discoverDomain(asset_id: string, domain: string): Promise<any> {
    const res = await this.client.post('/api/v1/scans/discover', { asset_id, domain })
    return res.data
  }

  // ─── Ports ────────────────────────────────────────────────────────────────
  async getPorts(subdomain_id: string): Promise<{ ports: Port[]; total: number }> {
    const res = await this.client.get('/api/v1/ports', { params: { subdomain_id } })
    return res.data
  }

  // ─── Vulnerabilities ──────────────────────────────────────────────────────
  async getVulnerabilities(severity?: string): Promise<{ vulnerabilities: Vulnerability[]; total: number }> {
    const res = await this.client.get('/api/v1/vulnerabilities', {
      params: severity ? { severity } : {}
    })
    return res.data
  }

  async getCriticalVulnerabilities(): Promise<{ vulnerabilities: Vulnerability[]; total: number }> {
    const res = await this.client.get('/api/v1/vulnerabilities/critical')
    return res.data
  }

  // ─── Alerts ───────────────────────────────────────────────────────────────
  async getAlerts(asset_id?: string, resolved = false): Promise<{ alerts: Alert[]; total: number }> {
    const res = await this.client.get('/api/v1/alerts', {
      params: { ...(asset_id && { asset_id }), resolved }
    })
    return res.data
  }

  async resolveAlert(id: string): Promise<void> {
    await this.client.post(`/api/v1/alerts/${id}/resolve`)
  }

  // ─── Threat Intelligence ──────────────────────────────────────────────────
  async checkThreatIntelligence(indicator_type: string, indicator_value: string): Promise<ThreatIntelligence> {
    const res = await this.client.post('/api/v1/threat-intelligence/check', {
      indicator_type, indicator_value
    })
    return res.data
  }

  // ─── Reports ──────────────────────────────────────────────────────────────
  async generateReport(asset_id: string, report_type: string, format = 'pdf'): Promise<Report> {
    const res = await this.client.post('/api/v1/reports', { asset_id, report_type, format })
    return res.data
  }

  async getReports(asset_id?: string): Promise<{ reports: Report[]; total: number }> {
    const res = await this.client.get('/api/v1/reports', {
      params: asset_id ? { asset_id } : {}
    })
    return res.data
  }

  // ─── Dashboard ────────────────────────────────────────────────────────────
  async getDashboard(): Promise<DashboardFull> {
    const res = await this.client.get('/api/v1/dashboard/full')
    return res.data
  }

  async getRiskSummary(): Promise<RiskSummary> {
    const res = await this.client.get('/api/v1/dashboard/risk-summary')
    return res.data
  }

  async getTimeline(days = 30): Promise<{ timeline: any[] }> {
    const res = await this.client.get('/api/v1/dashboard/timeline', { params: { days } })
    return res.data
  }

  async getScanStatistics(): Promise<any> {
    const res = await this.client.get('/api/v1/dashboard/scan-statistics')
    return res.data
  }

  // ─── AI Analysis ──────────────────────────────────────────────────────────
  async analyzeVulnerability(vuln_id: string, provider = 'claude'): Promise<AIAnalysis> {
    const res = await this.client.post(
      `/api/v1/ai/analyze/vulnerability/${vuln_id}`,
      null,
      { params: { provider } }
    )
    return res.data
  }

  async getRemediationSteps(vuln_id: string): Promise<{ remediation_steps: string[] }> {
    const res = await this.client.post(`/api/v1/ai/remediate/${vuln_id}`)
    return res.data
  }

  async prioritizeVulnerabilities(asset_id: string): Promise<any> {
    const res = await this.client.post('/api/v1/ai/prioritize', null, { params: { asset_id } })
    return res.data
  }

  async generateAIReport(asset_id: string): Promise<{ report: string }> {
    const res = await this.client.post(`/api/v1/ai/report/executive/${asset_id}`)
    return res.data
  }

  async getAIProviders(): Promise<AIProviders> {
    const res = await this.client.get('/api/v1/ai/providers')
    return res.data
  }

  // ─── Health ───────────────────────────────────────────────────────────────
  async healthCheck(): Promise<{ status: string }> {
    const res = await this.client.get('/health')
    return res.data
  }
}

export const api = new ApiClient()
export default api
