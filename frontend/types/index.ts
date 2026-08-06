// ─── Auth ────────────────────────────────────────────────────────────────────
export interface User {
  id: string
  email: string
  full_name: string
  role: 'super_admin' | 'admin' | 'user'
  platform_role: 'super_admin' | 'member'
  organization_id?: string | null
  organization_name?: string | null
  organization_role?: 'admin' | 'user' | null
  is_active: boolean
  created_at: string
}

export interface LoginRequest { email: string; password: string }
export interface RegisterRequest { email: string; password: string; full_name: string }
export interface AuthResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user_id: string
  email: string
  role: string
}

// ─── Assets ──────────────────────────────────────────────────────────────────
export type AssetType = 'domain' | 'ip_range' | 'web_application' | 'mobile_app' | 'cloud_service'
export type AssetStatus = 'active' | 'archived' | 'pending'

export interface Asset {
  id: string
  name: string
  description?: string
  asset_type: AssetType
  status: AssetStatus
  risk_score: number
  created_at: string
  updated_at: string
}

export interface AssetStats {
  total_domains: number
  total_subdomains: number
  total_ports: number
  total_vulnerabilities: number
  vulnerable_subdomains: number
  risk_score: number
}

// ─── Domain ───────────────────────────────────────────────────────────────────
export interface Domain {
  id: string
  asset_id: string
  domain: string
  registrar?: string
  expiration_date?: string
  scan_status: string
  created_at: string
}

export interface Subdomain {
  id: string
  domain_id: string
  subdomain: string
  ip_addresses: string[]
  is_responsive: boolean
  has_ssl: boolean
  created_at: string
}

// ─── Scans ────────────────────────────────────────────────────────────────────
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type ScanType = 'full' | 'quick' | 'port_scan' | 'vuln_scan' | 'ssl_check'

export interface Scan {
  id: string
  asset_id: string
  scan_type: ScanType
  status: ScanStatus
  target_domain?: string
  retry_count: number
  created_at: string
  updated_at: string
}

// ─── Ports & Services ─────────────────────────────────────────────────────────
export interface Port {
  id: string
  subdomain_id: string
  port_number: number
  protocol: string
  status: string
  service_name?: string
  services: Service[]
}

export interface Service {
  id: string
  port_id: string
  service_name: string
  version?: string
  product?: string
  confidence: number
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'

export interface Vulnerability {
  id: string
  cve_id?: string
  title: string
  description?: string
  severity: Severity
  cvss_score?: number
  cvss_vector?: string
  published_date?: string
  service_id?: string
  created_at: string
}

// ─── Threat Intelligence ──────────────────────────────────────────────────────
export interface ThreatIntelligence {
  id: string
  indicator_type: string
  indicator_value: string
  source: string
  reputation_score?: number
  is_malicious: boolean
  details?: string
  last_checked?: string
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
export interface Alert {
  id: string
  asset_id: string
  alert_type: string
  severity: Severity
  message: string
  is_resolved: boolean
  created_at: string
}

// ─── Reports ──────────────────────────────────────────────────────────────────
export interface Report {
  id: string
  asset_id: string
  report_type: string
  format: string
  title: string
  status: string
  created_at: string
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
export interface RiskSummary {
  total_assets: number
  total_domains: number
  total_subdomains: number
  avg_risk_score: number
  risk_distribution: Record<string, number>
}

export interface DashboardFull {
  risk_summary: RiskSummary
  timeline: TimelinePoint[]
  vulnerable_domains: Domain[]
  scan_statistics: ScanStats
}

export interface TimelinePoint {
  date: string
  scans: number
  vulnerabilities: number
  assets: number
}

export interface ScanStats {
  total: number
  completed: number
  failed: number
  running: number
  pending: number
}

// ─── AI ───────────────────────────────────────────────────────────────────────
export interface AIAnalysis {
  provider: string
  analysis: string
  vulnerability_id: string
  cve_id?: string
  severity: string
  timestamp: string
}

export interface AIProviders {
  providers: Record<string, {
    name: string
    available: boolean
    models: string[]
  }>
  recommended: string
}

// ─── API Pagination ───────────────────────────────────────────────────────────
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  skip: number
  limit: number
}

export interface ApiError {
  detail: string
  status_code: number
}
