import axios from "axios";

export const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const client = axios.create({ baseURL: API, timeout: 30000 });

client.interceptors.request.use((cfg) => {
  const t =
    typeof window !== "undefined" ? localStorage.getItem("access_token") : "";
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  const org =
    typeof window !== "undefined"
      ? localStorage.getItem("active_organization_id")
      : "";
  if (org) cfg.headers["X-Organization-ID"] = org;
  return cfg;
});

client.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("access_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  },
);

// ASM endpoints
export const asm = {
  // Assets
  getAssets: (p) =>
    client.get("/api/v1/assets", { params: p }).then((r) => r.data),
  getAsset: (id) => client.get(`/api/v1/assets/${id}`).then((r) => r.data),
  createAsset: (b) => client.post("/api/v1/assets", b).then((r) => r.data),
  updateAsset: (id, b) =>
    client.put(`/api/v1/assets/${id}`, b).then((r) => r.data),
  deleteAsset: (id) => client.delete(`/api/v1/assets/${id}`),

  // Attack Surface Management
  getAttackSurfaceOverview: (organizationId) =>
    client
      .get("/api/v1/attack-surface/overview", {
        params: organizationId ? { organization_id: organizationId } : {},
      })
      .then((r) => r.data),
  getAttackSurfaceInventory: (p) =>
    client
      .get("/api/v1/attack-surface/inventory", { params: p })
      .then((r) => r.data),
  getAttackSurfaceGraph: (organizationId) =>
    client
      .get("/api/v1/attack-surface/graph", {
        params: { organization_id: organizationId },
      })
      .then((r) => r.data),
  getAttackSurfaceAsset: (id) =>
    client.get(`/api/v1/attack-surface/inventory/${id}`).then((r) => r.data),
  updateAttackSurfaceAsset: (id, b) =>
    client
      .patch(`/api/v1/attack-surface/inventory/${id}`, b)
      .then((r) => r.data),
  getAttackSurfaceChanges: (p) =>
    client
      .get("/api/v1/attack-surface/changes", { params: p })
      .then((r) => r.data),
  getExposures: (p) =>
    client
      .get("/api/v1/attack-surface/exposures", { params: p })
      .then((r) => r.data),
  updateExposureStatus: (id, status) =>
    client
      .patch(`/api/v1/attack-surface/exposures/${id}`, { status })
      .then((r) => r.data),
  getDiscoverySeeds: (organizationId) =>
    client
      .get("/api/v1/attack-surface/seeds", {
        params: { organization_id: organizationId },
      })
      .then((r) => r.data),
  createDiscoverySeed: (b) =>
    client.post("/api/v1/attack-surface/seeds", b).then((r) => r.data),
  deleteDiscoverySeed: (id) =>
    client.delete(`/api/v1/attack-surface/seeds/${id}`).then((r) => r.data),
  rebuildAttackSurface: (organizationId) =>
    client
      .post(`/api/v1/attack-surface/rebuild/${organizationId}`)
      .then((r) => r.data),

  // Schedules / Continuous Monitoring
  getSchedules: (p) =>
    client.get("/api/v1/schedules", { params: p }).then((r) => r.data),
  createSchedule: (b) =>
    client.post("/api/v1/schedules", b).then((r) => r.data),
  toggleSchedule: (id) =>
    client.put(`/api/v1/schedules/${id}/toggle`).then((r) => r.data),
  pauseSchedule: (id) =>
    client.put(`/api/v1/schedules/${id}/pause`).then((r) => r.data),
  deleteSchedule: (id) => client.delete(`/api/v1/schedules/${id}`),
  previewSchedule: (b) =>
    client.post("/api/v1/schedules/preview", b).then((r) => r.data),
  getScheduleMailStatus: () =>
    client.get("/api/v1/schedules/mail/status").then((r) => r.data),
  sendScheduleTestEmail: (recipient) =>
    client
      .post("/api/v1/schedules/mail/test", recipient ? { recipient } : {})
      .then((r) => r.data),

  // Scan jobs
  triggerScan: (asset_id) =>
    client.post("/api/v1/scans/trigger", { asset_id }).then((r) => r.data),
  getScans: (p) =>
    client.get("/api/v1/scans", { params: p }).then((r) => r.data),
  getScan: (id) => client.get(`/api/v1/scans/${id}`).then((r) => r.data),
  getScanArchive: (id) =>
    client.get(`/api/v1/scans/${id}/archive`).then((r) => r.data),
  getScanTools: (id) =>
    client.get(`/api/v1/scans/${id}/tools`).then((r) => r.data),
  getScanLogs: (id, since) =>
    client
      .get(`/api/v1/scans/${id}/logs`, {
        params: since ? { since_id: since } : {},
      })
      .then((r) => r.data),
  cancelScan: (id) =>
    client.post(`/api/v1/scans/${id}/cancel`).then((r) => r.data),
  deleteScan: (id) => client.delete(`/api/v1/scans/${id}`).then((r) => r.data),
  // Real Recon results
  getReconStatus: (scanId) =>
    client.get(`/api/v1/recon/status/${scanId}`).then((r) => r.data),
  getReconSubdomains: (domainId, scanId) =>
    client
      .get("/api/v1/recon/subdomains", {
        params: { domain_id: domainId, ...(scanId ? { scan_id: scanId } : {}) },
      })
      .then((r) => r.data),
  getReconIPs: (domainId) =>
    client
      .get("/api/v1/recon/ips", { params: { domain_id: domainId } })
      .then((r) => r.data),
  getReconVulnerabilities: (domainId, scanId) =>
    client
      .get("/api/v1/recon/vulnerabilities", {
        params: { domain_id: domainId, ...(scanId ? { scan_id: scanId } : {}) },
      })
      .then((r) => r.data),
  getReconAIServiceAssessments: (scanId) =>
    client
      .get("/api/v1/recon/ai-service-assessments", {
        params: { scan_id: scanId },
      })
      .then((r) => r.data),
  getReconScreenshots: (domainId) =>
    client
      .get("/api/v1/recon/screenshots", { params: { domain_id: domainId } })
      .then((r) => r.data),

  // Vulnerabilities
  getVulns: (p) =>
    client.get("/api/v1/vulnerabilities", { params: p }).then((r) => r.data),
  getVulnerabilities: (severity) =>
    client
      .get("/api/v1/vulnerabilities", { params: severity ? { severity } : {} })
      .then((r) => r.data),
  getVuln: (id) =>
    client.get(`/api/v1/vulnerabilities/${id}`).then((r) => r.data),
  markFP: (id) =>
    client
      .post(`/api/v1/vulnerabilities/${id}/false-positive`)
      .then((r) => r.data),

  // Reports
  getReports: (p) =>
    client.get("/api/v1/reports", { params: p }).then((r) => r.data),
  getReport: (id) => client.get(`/api/v1/reports/${id}`).then((r) => r.data),
  exportReport: (id, fmt) => `${API}/api/v1/reports/${id}/export/${fmt}`,
  generateScanReport: (scanId) =>
    client
      .post("/api/v1/reports/generate", { scan_id: scanId })
      .then((r) => r.data),
  downloadScanReport: (scanId, format) =>
    client.get(
      `/api/v1/reports/scan/${encodeURIComponent(scanId)}/export/${format}`,
      { responseType: "blob", timeout: 120000 },
    ),

  // Dashboard
  getDashboard: () => client.get("/api/v1/dashboard/full").then((r) => r.data),
  getRiskSummary: () =>
    client.get("/api/v1/dashboard/risk-summary").then((r) => r.data),
  getTimeline: (days = 30) =>
    client
      .get("/api/v1/dashboard/timeline", { params: { days } })
      .then((r) => r.data),

  // AI Analysis (Phase 7)
  getAIProviders: () => client.get("/api/v1/ai/providers").then((r) => r.data),
  analyzeVulnerability: (id, provider) =>
    client
      .post(`/api/v1/ai/analyze/vulnerability/${id}`, null, {
        params: { provider },
      })
      .then((r) => r.data),
  prioritizeVulnerabilities: (assetId) =>
    client
      .post("/api/v1/ai/prioritize", null, { params: { asset_id: assetId } })
      .then((r) => r.data),
  generateAIReport: (assetId) =>
    client.post(`/api/v1/ai/report/executive/${assetId}`).then((r) => r.data),
  getRemediationSteps: (id) =>
    client.post(`/api/v1/ai/remediate/${id}`).then((r) => r.data),

  // Alerts
  getAlerts: (assetId) =>
    client
      .get("/api/v1/alerts", { params: assetId ? { asset_id: assetId } : {} })
      .then((r) => r.data),
  resolveAlert: (id) =>
    client.post(`/api/v1/alerts/${id}/resolve`).then((r) => r.data),

  // Multi-tenant platform / organization
  getSuperAdminOverview: () =>
    client.get("/api/v1/super-admin/overview").then((r) => r.data),
  getOrganizations: () =>
    client.get("/api/v1/super-admin/organizations").then((r) => r.data),
  createOrganization: (b) =>
    client.post("/api/v1/super-admin/organizations", b).then((r) => r.data),
  getOrganization: (id) =>
    client.get(`/api/v1/super-admin/organizations/${id}`).then((r) => r.data),
  updateOrganization: (id, b) =>
    client
      .patch(`/api/v1/super-admin/organizations/${id}`, b)
      .then((r) => r.data),
  assignOrganizationAdmin: (id, b) =>
    client
      .put(`/api/v1/super-admin/organizations/${id}/admin`, b)
      .then((r) => r.data),
  deleteOrganization: (id) =>
    client
      .delete(`/api/v1/super-admin/organizations/${id}`)
      .then((r) => r.data),
  getCurrentOrganization: () =>
    client.get("/api/v1/organization").then((r) => r.data),
  getOrganizationUsers: () =>
    client.get("/api/v1/organization/users").then((r) => r.data),
  createOrganizationUser: (b) =>
    client.post("/api/v1/organization/users", b).then((r) => r.data),
  setOrganizationUserStatus: (id, is_active) =>
    client
      .patch(`/api/v1/organization/users/${id}/status`, { is_active })
      .then((r) => r.data),

  // Auth
  register: (b) => client.post("/api/v1/auth/register", b).then((r) => r.data),
  login: (b) =>
    client.post("/api/v1/auth/login", b).then((r) => {
      localStorage.setItem("access_token", r.data.access_token);
      return r.data;
    }),
  logout: () => client.post("/api/v1/auth/logout").then((r) => r.data),
  getMe: () => client.get("/api/v1/auth/me").then((r) => r.data),
};

export default asm;

// AI Pentest endpoints (5-phase automated pentest)
export const pentest = {
  startScan:  (target_url) => client.post("/api/v1/pentest/scan", { target_url }).then(r => r.data),
  getScan:    (id) => client.get(`/api/v1/pentest/scan/${id}`).then(r => r.data),
  listScans:  () => client.get("/api/v1/pentest/scans").then(r => r.data),
  deleteScan: (id) => client.delete(`/api/v1/pentest/scan/${id}`).then(r => r.data),
};
