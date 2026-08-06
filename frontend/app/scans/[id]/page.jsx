"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertCircle,
  ArrowLeft,
  Bug,
  Camera,
  CheckCircle2,
  Clock3,
  Globe2,
  Loader2,
  Network,
  Radar,
  Search,
  Server,
  ShieldAlert,
  Sparkles,
  XCircle,
} from "lucide-react";

import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider } from "@/lib/auth";
import asm, { API } from "@/lib/api";

const ACTIVE_STATUSES = new Set(["pending", "queued", "running"]);

const SEVERITY_META = {
  critical: {
    label: "Critical",
    color: "#ef4444",
    className: "text-red-400 bg-red-500/10 border-red-500/20",
    fallback: 95,
  },
  high: {
    label: "High",
    color: "#f97316",
    className: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    fallback: 80,
  },
  medium: {
    label: "Medium",
    color: "#eab308",
    className: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    fallback: 55,
  },
  low: {
    label: "Low",
    color: "#3b82f6",
    className: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    fallback: 25,
  },
  info: {
    label: "Info",
    color: "#64748b",
    className: "text-gray-400 bg-gray-500/10 border-gray-500/20",
    fallback: 0,
  },
};

function severityKey(value) {
  const key = String(value || "info").toLowerCase();
  return SEVERITY_META[key] ? key : "info";
}

function SeverityBadge({ severity }) {
  const meta = SEVERITY_META[severityKey(severity)];
  return (
    <span
      className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-semibold ${meta.className}`}
    >
      {meta.label}
    </span>
  );
}

function RiskMeter({ score }) {
  const color =
    score >= 90
      ? "#ef4444"
      : score >= 70
        ? "#f97316"
        : score >= 40
          ? "#eab308"
          : "#22c55e";
  const label =
    score >= 90
      ? "Critical"
      : score >= 70
        ? "High"
        : score >= 40
          ? "Medium"
          : score > 0
            ? "Low"
            : "Clean";
  return (
    <div className="flex items-center gap-5">
      <div
        className="relative grid h-28 w-28 shrink-0 place-items-center rounded-full"
        style={{
          background: `conic-gradient(${color} ${score * 3.6}deg, var(--asm-surface-raised) 0deg)`,
        }}
      >
        <div className="grid h-20 w-20 place-items-center rounded-full bg-[#161b22] text-center">
          <div>
            <p className="text-2xl font-bold text-gray-100">{score}</p>
            <p className="text-[9px] uppercase tracking-wide text-gray-500">
              of 100
            </p>
          </div>
        </div>
      </div>
      <div>
        <p className="text-xs uppercase tracking-wide text-gray-500">
          Vulnerability risk
        </p>
        <p className="mt-1 text-lg font-bold" style={{ color }}>
          {label}
        </p>
        <p className="mt-1 text-xs text-gray-500">
          Calculated from persisted scanner evidence and grounded AI service
          assessments.
        </p>
      </div>
    </div>
  );
}

function SeverityColumns({ findings }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const counts = Object.fromEntries(order.map((key) => [key, 0]));
  findings.forEach((finding) => {
    counts[severityKey(finding.severity)] += 1;
  });
  const maximum = Math.max(1, ...Object.values(counts));

  return (
    <div className="grid h-36 grid-cols-5 items-end gap-3">
      {order.map((key) => {
        const meta = SEVERITY_META[key];
        const count = counts[key];
        const height = count
          ? Math.max(14, Math.round((count / maximum) * 88))
          : 4;
        return (
          <div
            key={key}
            className="flex h-full flex-col items-center justify-end gap-2"
          >
            <span className="text-sm font-bold text-gray-200">{count}</span>
            <div
              className="w-full max-w-10 rounded-t-md transition-all"
              style={{
                height,
                backgroundColor: meta.color,
                opacity: count ? 1 : 0.2,
              }}
            />

            <span className="text-[9px] uppercase text-gray-500">
              {meta.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function ResultsEmpty({ message }) {
  return (
    <div className="rounded-lg border border-dashed border-[#30363d] px-4 py-8 text-center text-xs text-gray-500">
      {message}
    </div>
  );
}

function asDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value) {
  const date = asDate(value);
  return date ? date.toLocaleString() : "—";
}

function formatDuration(start, end) {
  const startedAt = asDate(start);
  if (!startedAt) return "—";

  const endedAt = asDate(end);
  if (!endedAt) return "In progress";

  const seconds = Math.max(
    0,
    Math.round((endedAt.getTime() - startedAt.getTime()) / 1000),
  );
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return minutes ? `${minutes}m ${remainingSeconds}s` : `${remainingSeconds}s`;
}

function StatusIcon({ status }) {
  if (status === "running")
    return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />;
  if (status === "completed")
    return <CheckCircle2 className="h-4 w-4 text-green-400" />;
  if (status === "failed") return <XCircle className="h-4 w-4 text-red-400" />;
  if (status === "cancelled")
    return <XCircle className="h-4 w-4 text-gray-500" />;
  return <Clock3 className="h-4 w-4 text-yellow-400" />;
}

function statusClasses(status) {
  if (status === "running")
    return "border-blue-500/30 bg-blue-500/10 text-blue-400";
  if (status === "completed")
    return "border-green-500/30 bg-green-500/10 text-green-400";
  if (status === "failed")
    return "border-red-500/30 bg-red-500/10 text-red-400";
  if (status === "cancelled")
    return "border-gray-500/30 bg-gray-500/10 text-gray-400";
  return "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";
}

function ScanDetailPageInner({ params }) {
  const { id } = params;
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [resultsError, setResultsError] = useState("");

  const loadScan = useCallback(async () => {
    try {
      const response = await asm.getScan(id);
      setScan(response);
      setError("");
    } catch (requestError) {
      const detail = requestError?.response?.data?.detail;
      setError(
        typeof detail === "string" ? detail : "Unable to load this scan.",
      );
    } finally {
      setLoading(false);
    }
  }, [id]);

  const loadResults = useCallback(async () => {
    setResultsLoading(true);
    try {
      try {
        const archive = await asm.getScanArchive(id);
        if (archive?.domain_id) {
          setResults({
            domainId: archive.domain_id,
            subdomains: archive.subdomains || [],
            ips: archive.ips || [],
            vulnerabilities: archive.vulnerabilities || [],
            aiAssessments: archive.ai_assessments || [],
            screenshots: archive.screenshots || [],
          });
          setResultsError("");
          return;
        }
      } catch {
        // Older/active installations can still use the canonical database
        // endpoints while a missing archive is backfilled.
      }
      const statusResponse = await asm.getReconStatus(id);
      const domainId = statusResponse?.domain_id;
      if (!domainId) {
        setResults(null);
        setResultsError("No persisted domain is associated with this scan.");
        return;
      }

      const [
        subdomainResponse,
        ipResponse,
        vulnerabilityResponse,
        aiAssessmentResponse,
        screenshotResponse,
      ] = await Promise.all([
        asm.getReconSubdomains(domainId, id),
        asm.getReconIPs(domainId),
        asm.getReconVulnerabilities(domainId, id),
        asm.getReconAIServiceAssessments(id),
        asm.getReconScreenshots(domainId),
      ]);

      setResults({
        domainId,
        subdomains: subdomainResponse?.subdomains || [],
        ips: ipResponse?.ips || [],
        vulnerabilities: vulnerabilityResponse?.vulnerabilities || [],
        aiAssessments: aiAssessmentResponse?.assessments || [],
        screenshots: screenshotResponse?.screenshots || [],
      });
      setResultsError("");
    } catch (requestError) {
      const detail = requestError?.response?.data?.detail;
      setResults(null);
      setResultsError(
        typeof detail === "string"
          ? detail
          : "Unable to load persisted scanner results.",
      );
    } finally {
      setResultsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadScan();
  }, [loadScan]);

  useEffect(() => {
    if (!scan || !ACTIVE_STATUSES.has(String(scan.status).toLowerCase()))
      return;
    const timer = window.setInterval(loadScan, 3000);
    return () => window.clearInterval(timer);
  }, [scan?.status, loadScan]);

  useEffect(() => {
    if (
      scan &&
      String(scan.status).toLowerCase() === "completed" &&
      scan.scan_type === "recon_full"
    ) {
      loadResults();
    }
  }, [scan?.status, scan?.scan_type, loadResults]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2
          className="h-9 w-9 animate-spin text-blue-400"
          aria-label="Loading scan"
        />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="card mx-auto mt-16 max-w-lg p-8 text-center">
        <AlertCircle className="mx-auto mb-3 h-10 w-10 text-red-400" />
        <h1 className="text-base font-semibold text-gray-100">
          Scan details unavailable
        </h1>
        <p className="mt-2 text-sm text-gray-500">
          {error || "This scan could not be found."}
        </p>
        <Link
          href="/scans"
          className="btn-blue mt-5 inline-flex items-center gap-2 text-xs"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Scan History
        </Link>
      </div>
    );
  }

  const status = String(scan.status || "pending").toLowerCase();
  const isActive = ACTIVE_STATUSES.has(status);
  const title = scan.target_domain || scan.reference_id || scan.id;
  const serviceRows = (results?.subdomains || []).flatMap((subdomain) => {
    const servicesByPort = new Map(
      subdomain.services.map((service) => [service.port, service]),
    );
    return subdomain.open_ports.map((port) => {
      const service = servicesByPort.get(port);
      return {
        id: service?.id || null,
        host: subdomain.subdomain,
        port,
        protocol: service?.protocol || "TCP",
        name: service?.name || "unknown",
        product: service?.product || null,
        version: service?.version || null,
      };
    });
  });
  const actionableFindings = (results?.vulnerabilities || []).filter(
    (finding) => severityKey(finding.severity) !== "info",
  );
  const informationalFindings = (results?.vulnerabilities || []).filter(
    (finding) => severityKey(finding.severity) === "info",
  );
  const severityFindings = [
    ...(results?.vulnerabilities || []),
    ...(results?.aiAssessments || []),
  ];
  const nucleiRisk =
    results?.vulnerabilities.reduce((highest, vulnerability) => {
      const cvssRisk =
        typeof vulnerability.cvss_score === "number"
          ? Math.round(Math.min(10, Math.max(0, vulnerability.cvss_score)) * 10)
          : SEVERITY_META[severityKey(vulnerability.severity)].fallback;
      return Math.max(highest, cvssRisk);
    }, 0) || 0;
  const aiRisk =
    results?.aiAssessments.reduce(
      (highest, assessment) =>
        Math.max(
          highest,
          SEVERITY_META[severityKey(assessment.severity)].fallback,
        ),
      0,
    ) || 0;
  const vulnerabilityRisk = Math.max(nucleiRisk, aiRisk);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link
            href="/scans"
            className="mb-2 inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-blue-400"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Scan History
          </Link>
          <h1 className="break-all text-xl font-bold text-gray-100">{title}</h1>
          <p className="mt-1 font-mono text-xs text-blue-400">
            {scan.reference_id || scan.id}
          </p>
        </div>

        <span
          className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold capitalize ${statusClasses(status)}`}
        >
          <StatusIcon status={status} />
          {status === "pending" ? "queued" : status}
        </span>
      </div>

      {scan.error_message && (
        <div
          className={`flex items-start gap-3 rounded-xl border p-4 ${
            status === "completed"
              ? "border-yellow-500/30 bg-yellow-500/10"
              : "border-red-500/30 bg-red-500/10"
          }`}
        >
          <AlertCircle
            className={`mt-0.5 h-4 w-4 shrink-0 ${
              status === "completed" ? "text-yellow-400" : "text-red-400"
            }`}
          />
          <div>
            <p
              className={`text-xs font-semibold ${
                status === "completed" ? "text-yellow-200" : "text-red-300"
              }`}
            >
              {status === "completed"
                ? "Scan completed with warning"
                : "Scan failed"}
            </p>
            <p
              className={`mt-1 whitespace-pre-wrap text-xs ${
                status === "completed"
                  ? "text-yellow-100/80"
                  : "text-red-200/80"
              }`}
            >
              {scan.error_message}
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">
              Scan type
            </p>
            <Radar className="h-4 w-4 text-blue-400" />
          </div>
          <p className="text-lg font-bold capitalize text-gray-100">
            {(scan.scan_type || "scan").replace(/_/g, " ")}
          </p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">
              Discoveries
            </p>
            <Search className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold text-gray-100">
            {scan.discovered_count ?? 0}
          </p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">
              Findings
            </p>
            <ShieldAlert className="h-4 w-4 text-orange-400" />
          </div>
          <p className="text-2xl font-bold text-gray-100">
            {scan.vulnerable_count ?? 0}
          </p>
        </div>

        <div className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs uppercase tracking-wide text-gray-500">
              Duration
            </p>
            <Clock3 className="h-4 w-4 text-purple-400" />
          </div>
          <p className="text-lg font-bold text-gray-100">
            {formatDuration(scan.started_at, scan.completed_at)}
          </p>
        </div>
      </div>

      <div className="card p-5">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Execution status
            </h2>
            <p className="mt-1 text-xs text-gray-500">
              {isActive
                ? "This page refreshes every 3 seconds while the real scan is active."
                : `The scan is ${status}.`}
            </p>
          </div>
          <StatusIcon status={status} />
        </div>

        <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#21262d]">
          {status === "running" ? (
            <div className="h-full w-1/3 animate-pulse rounded-full bg-blue-500" />
          ) : (
            <div
              className={`h-full rounded-full ${
                status === "completed"
                  ? "w-full bg-green-500"
                  : status === "failed"
                    ? "w-full bg-red-500"
                    : status === "cancelled"
                      ? "w-full bg-gray-600"
                      : "w-1/12 bg-yellow-500"
              }`}
            />
          )}
        </div>
      </div>

      {status === "completed" && scan.scan_type === "recon_full" && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-blue-400" />
                <h2 className="text-base font-semibold text-gray-100">
                  Real scanner findings
                </h2>
              </div>
              <p className="mt-1 text-xs text-gray-500">
                Persisted output from the real multi-stage reconnaissance
                pipeline.
              </p>
            </div>
            <button
              type="button"
              onClick={loadResults}
              disabled={resultsLoading}
              className="btn-gray inline-flex items-center gap-2 px-3 py-1.5 text-xs"
            >
              <Loader2
                className={`h-3.5 w-3.5 ${resultsLoading ? "animate-spin" : ""}`}
              />
              Refresh findings
            </button>
          </div>

          {resultsLoading && !results && (
            <div className="card flex items-center justify-center gap-2 py-16 text-sm text-gray-500">
              <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
              Loading persisted scanner results…
            </div>
          )}

          {resultsError && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-xs text-red-300">
              {resultsError}
            </div>
          )}

          {results && (
            <>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                {[
                  {
                    label: "Subdomains",
                    value: results.subdomains.length,
                    detail: `${results.subdomains.filter((item) => item.is_responsive).length} responsive`,
                    icon: Globe2,
                    color: "text-cyan-400",
                  },
                  {
                    label: "Resolved IPs",
                    value: results.ips.length,
                    detail: "Factual DNS records",
                    icon: Network,
                    color: "text-blue-400",
                  },
                  {
                    label: "Open services",
                    value: serviceRows.length,
                    detail: "Port and version evidence",
                    icon: Server,
                    color: "text-purple-400",
                  },
                  {
                    label: "Actionable findings",
                    value: actionableFindings.length,
                    detail: `${informationalFindings.length} informational observations`,
                    icon: Bug,
                    color: "text-orange-400",
                  },
                  {
                    label: "AI version checks",
                    value: results.aiAssessments.length,
                    detail: "Grounded AI analysis",
                    icon: Sparkles,
                    color: "text-pink-400",
                  },
                ].map((item) => {
                  const Icon = item.icon;
                  return (
                    <div key={item.label} className="card p-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="text-[10px] uppercase tracking-wide text-gray-500">
                            {item.label}
                          </p>
                          <p className="mt-2 text-2xl font-bold text-gray-100">
                            {item.value}
                          </p>
                          <p className="mt-1 text-[10px] text-gray-500">
                            {item.detail}
                          </p>
                        </div>
                        <Icon className={`h-4 w-4 ${item.color}`} />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <div className="card p-5">
                  <RiskMeter score={vulnerabilityRisk} />
                </div>
                <div className="card p-5">
                  <div className="mb-2">
                    <h3 className="text-sm font-semibold text-gray-100">
                      Severity distribution
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Actionable findings, informational observations, and
                      grounded AI service-version assessments.
                    </p>
                  </div>
                  <SeverityColumns findings={severityFindings} />
                </div>
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-100">
                      Informational observations
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Technology and configuration detections are evidence, but
                      are not counted as vulnerabilities.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-gray-400">
                    {informationalFindings.length}
                  </span>
                </div>
                {informationalFindings.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No informational observations were recorded for this scan." />
                  </div>
                ) : (
                  <div className="max-h-80 overflow-auto">
                    <table className="w-full min-w-[720px] text-xs">
                      <thead className="sticky top-0 bg-[#161b22]">
                        <tr className="border-b border-[#21262d]">
                          {[
                            "Category",
                            "Observation",
                            "Source",
                            "Affected service",
                          ].map((header) => (
                            <th
                              key={header}
                              className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500"
                            >
                              {header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {informationalFindings.map((finding) => (
                          <tr
                            key={finding.id}
                            className="border-b border-[#21262d] align-top transition hover:bg-[#1c2128]"
                          >
                            <td className="px-4 py-3">
                              <SeverityBadge severity="Info" />
                            </td>
                            <td className="max-w-xl px-4 py-3">
                              <p className="font-medium text-gray-300">
                                {finding.title}
                              </p>
                              {finding.description && (
                                <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-gray-500">
                                  {finding.description}
                                </p>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono text-gray-500">
                              {finding.source || "scanner"}
                            </td>
                            <td className="px-4 py-3 font-mono text-gray-400">
                              {finding.subdomain}
                              {finding.port != null ? `:${finding.port}` : ""}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                      <Globe2 className="h-4 w-4 text-cyan-400" />
                      Discovered subdomains
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Asset discovery enriched with DNS and web-response
                      evidence.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-cyan-400">
                    {results.subdomains.length}
                  </span>
                </div>
                {results.subdomains.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No persisted subdomains were found." />
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-xs">
                      <thead>
                        <tr className="border-b border-[#21262d]">
                          {[
                            "Host",
                            "Resolved IPs",
                            "HTTP",
                            "Technologies",
                            "Open ports",
                          ].map((header) => (
                            <th
                              key={header}
                              className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500"
                            >
                              {header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {results.subdomains.map((subdomain) => (
                          <tr
                            key={subdomain.id}
                            className="border-b border-[#21262d] transition hover:bg-[#1c2128]"
                          >
                            <td className="px-4 py-3 font-mono text-gray-200">
                              {subdomain.subdomain}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex flex-wrap gap-1">
                                {subdomain.ip_addresses.length ? (
                                  subdomain.ip_addresses.map((ip) => (
                                    <code
                                      key={ip}
                                      className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-400"
                                    >
                                      {ip}
                                    </code>
                                  ))
                                ) : (
                                  <span className="text-gray-600">—</span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              {subdomain.is_responsive ? (
                                <span className="text-green-400">
                                  {subdomain.response_status_code ||
                                    "Responsive"}
                                  {subdomain.has_ssl ? " · TLS" : ""}
                                </span>
                              ) : (
                                <span className="text-gray-600">
                                  Not responsive
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex max-w-xs flex-wrap gap-1">
                                {subdomain.technologies.length ? (
                                  subdomain.technologies.map((technology) => (
                                    <span
                                      key={technology}
                                      className="rounded border border-[#30363d] bg-[#0d1117] px-1.5 py-0.5 text-[10px] text-gray-400"
                                    >
                                      {technology}
                                    </span>
                                  ))
                                ) : (
                                  <span className="text-gray-600">—</span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-3 font-mono text-purple-400">
                              {subdomain.open_ports.length
                                ? subdomain.open_ports.join(", ")
                                : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                      <Server className="h-4 w-4 text-purple-400" />
                      Detected services
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Open ports with factual product and version detection.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-purple-400">
                    {serviceRows.length}
                  </span>
                </div>
                {serviceRows.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No open services were persisted." />
                  </div>
                ) : (
                  <div className="max-h-96 overflow-auto">
                    <table className="w-full min-w-[700px] text-xs">
                      <thead className="sticky top-0 bg-[#161b22]">
                        <tr className="border-b border-[#21262d]">
                          {[
                            "Host",
                            "Port",
                            "Protocol",
                            "Service",
                            "Product / version",
                          ].map((header) => (
                            <th
                              key={header}
                              className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500"
                            >
                              {header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {serviceRows.map((service, index) => (
                          <tr
                            key={`${service.host}-${service.port}-${index}`}
                            className="border-b border-[#21262d] transition hover:bg-[#1c2128]"
                          >
                            <td className="px-4 py-3 font-mono text-gray-300">
                              {service.host}
                            </td>
                            <td className="px-4 py-3 font-mono font-semibold text-purple-400">
                              {service.port}
                            </td>
                            <td className="px-4 py-3 text-gray-500">
                              {service.protocol}
                            </td>
                            <td className="px-4 py-3 text-gray-300">
                              {service.name}
                            </td>
                            <td className="px-4 py-3 text-gray-400">
                              {[service.product, service.version]
                                .filter(Boolean)
                                .join(" ") || "Unknown"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                      <Sparkles className="h-4 w-4 text-pink-400" />
                      AI service-version assessments
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Grounded version and CVE checks are kept separate from
                      scanner-confirmed findings.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-pink-400">
                    {results.aiAssessments.length}
                  </span>
                </div>
                {results.aiAssessments.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No AI service assessments were persisted. Configure the AI API key and run a new Full Recon scan." />
                  </div>
                ) : (
                  <div className="max-h-[32rem] overflow-auto">
                    <table className="w-full min-w-[980px] text-xs">
                      <thead className="sticky top-0 bg-[#161b22]">
                        <tr className="border-b border-[#21262d]">
                          {[
                            "Severity",
                            "Affected service",
                            "Version status",
                            "Assessment",
                            "Evidence",
                          ].map((header) => (
                            <th
                              key={header}
                              className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500"
                            >
                              {header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {results.aiAssessments.map((assessment) => {
                          const lifecycleClass =
                            assessment.lifecycle_status === "current"
                              ? "text-green-400"
                              : assessment.lifecycle_status === "outdated"
                                ? "text-orange-400"
                                : "text-gray-500";
                          return (
                            <tr
                              key={assessment.id}
                              className="border-b border-[#21262d] align-top transition hover:bg-[#1c2128]"
                            >
                              <td className="px-4 py-3">
                                <SeverityBadge severity={assessment.severity} />
                              </td>
                              <td className="px-4 py-3">
                                <p className="font-mono text-gray-300">
                                  {assessment.host}:{assessment.port}
                                </p>
                                <p className="mt-1 text-[10px] text-gray-500">
                                  {assessment.product ||
                                    assessment.service_name}
                                </p>
                              </td>
                              <td className="px-4 py-3">
                                <p
                                  className={`font-semibold capitalize ${lifecycleClass}`}
                                >
                                  {assessment.lifecycle_status}
                                </p>
                                <p className="mt-1 font-mono text-[10px] text-gray-500">
                                  Detected:{" "}
                                  {assessment.detected_version || "unknown"}
                                </p>
                                {assessment.latest_version && (
                                  <p className="mt-0.5 font-mono text-[10px] text-green-500">
                                    Latest: {assessment.latest_version}
                                  </p>
                                )}
                              </td>
                              <td className="max-w-xl px-4 py-3">
                                <p className="font-medium text-gray-200">
                                  {assessment.title}
                                </p>
                                <p className="mt-1 text-[10px] leading-relaxed text-gray-500">
                                  {assessment.summary}
                                </p>
                                {assessment.remediation && (
                                  <p className="mt-2 text-[10px] leading-relaxed text-blue-300/80">
                                    Remediation: {assessment.remediation}
                                  </p>
                                )}
                                {assessment.cves.length > 0 && (
                                  <div className="mt-2 flex flex-wrap gap-1">
                                    {assessment.cves.map((cve) => (
                                      <span
                                        key={cve.cve_id}
                                        className="rounded border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 font-mono text-[10px] text-red-300"
                                      >
                                        {cve.cve_id}
                                        {typeof cve.cvss_score === "number"
                                          ? ` · ${cve.cvss_score.toFixed(1)}`
                                          : ""}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td className="px-4 py-3">
                                <p className="mb-2 text-[10px] text-gray-500">
                                  Confidence{" "}
                                  {Math.round(
                                    (assessment.confidence || 0) * 100,
                                  )}
                                  %
                                </p>
                                <div className="flex max-w-xs flex-col gap-1">
                                  {assessment.evidence_urls.length ? (
                                    assessment.evidence_urls
                                      .slice(0, 3)
                                      .map((url, index) => (
                                        <a
                                          key={url}
                                          href={url}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="truncate text-[10px] text-blue-400 hover:text-blue-300"
                                          title={url}
                                        >
                                          Source {index + 1} ↗
                                        </a>
                                      ))
                                  ) : (
                                    <span className="text-[10px] text-gray-600">
                                      No cited evidence
                                    </span>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                      <Bug className="h-4 w-4 text-orange-400" />
                      Actionable vulnerabilities
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Critical through Low scanner matches, categorized from
                      factual tool output.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-orange-400">
                    {actionableFindings.length}
                  </span>
                </div>
                {actionableFindings.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No Critical, High, Medium, or Low scanner matches were recorded for this scan." />
                  </div>
                ) : (
                  <div className="max-h-[32rem] overflow-auto">
                    <table className="w-full min-w-[820px] text-xs">
                      <thead className="sticky top-0 bg-[#161b22]">
                        <tr className="border-b border-[#21262d]">
                          {[
                            "Severity",
                            "Finding",
                            "CVE",
                            "Affected service",
                            "CVSS",
                          ].map((header) => (
                            <th
                              key={header}
                              className="px-4 py-3 text-left font-medium uppercase tracking-wide text-gray-500"
                            >
                              {header}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {actionableFindings.map((vulnerability) => (
                          <tr
                            key={vulnerability.id}
                            className="border-b border-[#21262d] align-top transition hover:bg-[#1c2128]"
                          >
                            <td className="px-4 py-3">
                              <SeverityBadge
                                severity={vulnerability.severity}
                              />
                            </td>
                            <td className="max-w-lg px-4 py-3">
                              <p className="font-medium text-gray-200">
                                {vulnerability.title}
                              </p>
                              {vulnerability.description && (
                                <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-gray-500">
                                  {vulnerability.description}
                                </p>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono text-blue-400">
                              {vulnerability.cve_id || "—"}
                            </td>
                            <td className="px-4 py-3 font-mono text-gray-400">
                              {vulnerability.subdomain}
                              {vulnerability.port != null
                                ? `:${vulnerability.port}`
                                : ""}
                            </td>
                            <td className="px-4 py-3 font-semibold text-gray-300">
                              {typeof vulnerability.cvss_score === "number"
                                ? vulnerability.cvss_score.toFixed(1)
                                : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                      <Camera className="h-4 w-4 text-green-400" />
                      Captured screenshots
                    </h3>
                    <p className="mt-1 text-xs text-gray-500">
                      Captured only from responsive web URLs.
                    </p>
                  </div>
                  <span className="text-xs font-semibold text-green-400">
                    {results.screenshots.length}
                  </span>
                </div>
                {results.screenshots.length === 0 ? (
                  <div className="p-4">
                    <ResultsEmpty message="No valid screenshots were persisted for this scan." />
                  </div>
                ) : (
                  <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
                    {results.screenshots.map((screenshot) => (
                      <article
                        key={screenshot.id}
                        className="overflow-hidden rounded-lg border border-[#30363d] bg-[#0d1117]"
                      >
                        {screenshot.file_url ? (
                          <img
                            src={`${API}${screenshot.file_url}`}
                            alt={`Screenshot of ${screenshot.subdomain}`}
                            className="h-40 w-full bg-[#21262d] object-cover"
                            loading="lazy"
                          />
                        ) : (
                          <div className="grid h-40 place-items-center bg-[#21262d] text-gray-600">
                            <Camera className="h-6 w-6" />
                          </div>
                        )}
                        <div className="p-3">
                          <p className="truncate font-mono text-xs text-gray-200">
                            {screenshot.subdomain}
                          </p>
                          <p className="mt-1 truncate text-[10px] text-gray-500">
                            {screenshot.title || screenshot.url}
                          </p>
                          <p className="mt-2 text-[10px] text-green-400">
                            {screenshot.status_code || "HTTP response captured"}
                          </p>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      )}

      <div className="card overflow-hidden">
        <div className="border-b border-[#21262d] px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-100">Scan record</h2>
          <p className="mt-1 text-xs text-gray-500">
            Values below come directly from the saved scan record.
          </p>
        </div>

        <dl className="grid sm:grid-cols-2">
          {[
            ["Scan ID", scan.id],
            ["Reference", scan.reference_id || "—"],
            ["Asset ID", scan.asset_id],
            ["Target", scan.target_domain || "—"],
            ["Created", formatDate(scan.created_at)],
            ["Started", formatDate(scan.started_at)],
            ["Completed", formatDate(scan.completed_at)],
            ["Last updated", formatDate(scan.updated_at)],
          ].map(([label, value]) => (
            <div
              key={label}
              className="border-b border-[#21262d] px-5 py-4 even:sm:border-l"
            >
              <dt className="text-[10px] uppercase tracking-wide text-gray-600">
                {label}
              </dt>
              <dd className="mt-1 break-all font-mono text-xs text-gray-300">
                {value}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

export default function ScanDetailPage({ params }) {
  return (
    <AuthProvider>
      <AppLayout>
        <ScanDetailPageInner params={params} />
      </AppLayout>
    </AuthProvider>
  );
}
