"use client";

import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider } from "@/lib/auth";
import asm from "@/lib/api";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Download,
  FileText,
  Loader2,
  Search,
  ShieldCheck,
  Target,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

const SEVERITIES = [
  {
    key: "critical",
    label: "Critical",
    color: "#ef4444",
    text: "text-red-400",
    panel: "border-red-500/20 bg-red-500/5",
  },
  {
    key: "high",
    label: "High",
    color: "#f97316",
    text: "text-orange-400",
    panel: "border-orange-500/20 bg-orange-500/5",
  },
  {
    key: "medium",
    label: "Medium",
    color: "#eab308",
    text: "text-yellow-400",
    panel: "border-yellow-500/20 bg-yellow-500/5",
  },
  {
    key: "low",
    label: "Low",
    color: "#3b82f6",
    text: "text-blue-400",
    panel: "border-blue-500/20 bg-blue-500/5",
  },
  {
    key: "info",
    label: "Info",
    color: "#64748b",
    text: "text-gray-400",
    panel: "border-gray-500/20 bg-gray-500/5",
  },
];

const formatDate = (value) => {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString();
};

function ReportsPageInner() {
  const [scanId, setScanId] = useState("");
  const [report, setReport] = useState(null);
  const [building, setBuilding] = useState(false);
  const [downloading, setDownloading] = useState(null);
  const [error, setError] = useState("");

  const findingsBySeverity = useMemo(() => {
    const grouped = {
      Critical: [],
      High: [],
      Medium: [],
      Low: [],
    };
    report?.findings.forEach((finding) => {
      if (grouped[finding.severity]) grouped[finding.severity].push(finding);
    });
    return grouped;
  }, [report]);

  const generate = async (event) => {
    event.preventDefault();
    const value = scanId.trim();
    if (!value) {
      setError("Enter a Scan ID before generating the report.");
      return;
    }
    setBuilding(true);
    setError("");
    setReport(null);
    try {
      const result = await asm.generateScanReport(value);
      setReport(result);
      setScanId(result.scan.reference_id);
    } catch (requestError) {
      setError(
        requestError?.response?.data?.detail ||
          "Unable to generate a report for this Scan ID.",
      );
    } finally {
      setBuilding(false);
    }
  };

  const download = async (format) => {
    if (!report) return;
    setDownloading(format);
    setError("");
    try {
      const response = await asm.downloadScanReport(
        report.scan.reference_id,
        format,
      );
      const blob =
        response.data instanceof Blob
          ? response.data
          : new Blob([response.data], {
              type:
                format === "pdf"
                  ? "application/pdf"
                  : "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `security-report-${report.scan.reference_id}.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (requestError) {
      setError(
        requestError?.response?.data?.detail ||
          `Unable to download the ${format.toUpperCase()} report.`,
      );
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="mx-auto space-y-5">
      <div>
        <h1 className="text-xl font-bold text-gray-100">
          Security Report Builder
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Enter your Scan ID to generate a structured security assessment report
          from that scan&apos;s saved findings.
        </p>
      </div>

      <form onSubmit={generate} className="card p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
          <label className="flex-1">
            <span className="mb-2 block text-xs font-semibold uppercase tracking-wide text-gray-400">
              Scan ID
            </span>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-600" />
              <input
                value={scanId}
                onChange={(event) => setScanId(event.target.value)}
                placeholder="Example: SCN-20260804-A4C2024123AB4BC8"
                className="w-full rounded-lg border border-[#30363d] bg-[#0d1117] py-2.5 pl-10 pr-3 font-mono text-sm text-gray-200 outline-none transition focus:border-blue-500"
                aria-label="Scan ID"
              />
            </div>
          </label>
          <button
            type="submit"
            disabled={building}
            className="btn-blue inline-flex min-w-48 items-center justify-center gap-2 py-2.5 text-xs disabled:opacity-50"
          >
            {building ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FileText className="h-4 w-4" />
            )}
            {building ? "Building report..." : "Generate report"}
          </button>
        </div>
        <p className="mt-3 text-xs text-gray-600">
          Copy the Scan ID from{" "}
          <Link href="/scans" className="text-blue-400 hover:text-blue-300">
            Scan History
          </Link>
          . Both the readable SCN reference and internal scan UUID are accepted.
        </p>
      </form>

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!report && !building && (
        <div className="card grid min-h-64 place-items-center p-8 text-center">
          <div>
            <FileText className="mx-auto h-10 w-10 text-gray-700" />
            <p className="mt-4 text-sm font-medium text-gray-400">
              Your report will appear here
            </p>
            <p className="mt-1 text-xs text-gray-600">
              Enter a completed Scan ID above to load its real saved findings.
            </p>
          </div>
        </div>
      )}

      {report && (
        <div className="space-y-5">
          <section className="card p-5">
            <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
              <div>
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-green-500/20 bg-green-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide text-green-400">
                    Report built
                  </span>
                  <span className="text-xs capitalize text-gray-500">
                    Scan {report.scan.status}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-gray-100">
                  {report.title}
                </h2>
                <p className="mt-1 font-mono text-xs text-blue-400">
                  {report.scan.reference_id}
                </p>
                <p className="mt-1 text-xs text-gray-600">
                  Generated {formatDate(report.generated_at)}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => download("docx")}
                  disabled={downloading !== null}
                  className="btn-blue inline-flex items-center gap-2 text-xs disabled:opacity-50"
                >
                  {downloading === "docx" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4" />
                  )}
                  Word
                </button>
                <button
                  onClick={() => download("pdf")}
                  disabled={downloading !== null}
                  className="btn-gray inline-flex items-center gap-2 text-xs disabled:opacity-50"
                >
                  {downloading === "pdf" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4" />
                  )}
                  PDF
                </button>
                <Link
                  href={`/scans/${report.scan.id}`}
                  className="btn-gray inline-flex items-center gap-2 text-xs"
                >
                  <Target className="h-4 w-4" /> View scan
                </Link>
              </div>
            </div>
          </section>

          {report.scan.warning && (
            <section className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-400" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-yellow-300">
                    Scan warning included in report
                  </p>
                  <p className="mt-1 whitespace-pre-wrap text-xs leading-relaxed text-yellow-100/70">
                    {report.scan.warning}
                  </p>
                </div>
              </div>
            </section>
          )}

          <div className="grid gap-4 lg:grid-cols-3">
            <section className="card p-5">
              <div className="mb-3 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-gray-100">
                  1. Project objective
                </h3>
              </div>
              <p className="text-xs leading-relaxed text-gray-400">
                {report.project_objective}
              </p>
            </section>

            <section className="card p-5">
              <div className="mb-3 flex items-center gap-2">
                <Target className="h-4 w-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-gray-100">
                  2. Target system
                </h3>
              </div>
              <dl className="space-y-2 text-xs">
                {[
                  ["Asset", report.target_system.asset_name],
                  ["Primary target", report.target_system.primary_target],
                  ["Target IP", report.target_system.target_ip],
                  ["Discovered assets", report.target_system.discovered_assets],
                  [
                    "Affected ports",
                    report.target_system.affected_ports.join(", ") ||
                      "None recorded",
                  ],
                  ["Completed", formatDate(report.scan.completed_at)],
                ].map(([label, value]) => (
                  <div
                    key={String(label)}
                    className="grid grid-cols-[7rem_1fr] gap-2"
                  >
                    <dt className="text-gray-600">{label}</dt>
                    <dd className="break-all text-gray-300">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <section className="card p-5">
              <div className="mb-3 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-400" />
                <h3 className="text-sm font-semibold text-gray-100">
                  3. Key observations/findings
                </h3>
              </div>
              <div className="space-y-3">
                {report.key_observations.map((observation) => (
                  <div key={observation.title}>
                    <p className="text-xs font-medium text-gray-300">
                      {observation.title}
                    </p>
                    <p className="mt-0.5 whitespace-pre-wrap text-[11px] leading-relaxed text-gray-600">
                      {observation.detail}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <section className="card p-5">
            <div className="mb-5 flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              <div>
                <h3 className="text-sm font-semibold text-gray-100">
                  Security posture dashboard
                </h3>
                <p className="mt-1 text-xs text-gray-600">
                  Maturity indicator and severity percentage for the selected
                  scan.
                </p>
              </div>
            </div>

            <div className="grid gap-6 xl:grid-cols-[18rem_1fr]">
              <div className="flex flex-col items-center justify-center rounded-xl border border-[#21262d] bg-[#0d1117] p-5">
                <div
                  className="grid h-40 w-40 place-items-center rounded-full"
                  style={{
                    background: `conic-gradient(#22c55e ${report.maturity.score * 3.6}deg, #21262d 0deg)`,
                  }}
                >
                  <div className="grid h-28 w-28 place-items-center rounded-full bg-[#0d1117] text-center">
                    <div>
                      <p className="text-3xl font-bold text-gray-100">
                        {report.maturity.score}
                      </p>
                      <p className="text-[10px] uppercase tracking-wide text-gray-600">
                        of 100
                      </p>
                    </div>
                  </div>
                </div>
                <p className="mt-3 text-sm font-semibold text-green-400">
                  {report.maturity.level}
                </p>
                <p className="mt-2 text-center text-[10px] leading-relaxed text-gray-600">
                  {report.maturity.description}
                </p>
              </div>

              <div className="space-y-3">
                {SEVERITIES.map((severity) => {
                  const count = report.severity.counts[severity.key];
                  const percentage = report.severity.percentages[severity.key];
                  return (
                    <div
                      key={severity.key}
                      className={`rounded-xl border p-4 ${severity.panel}`}
                    >
                      <div className="mb-2 flex items-center justify-between gap-3">
                        <span
                          className={`text-xs font-semibold ${severity.text}`}
                        >
                          {severity.label}
                        </span>
                        <span className="text-xs text-gray-400">
                          {count} finding{count === 1 ? "" : "s"} ·{" "}
                          {percentage.toFixed(1)}%
                        </span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-[#21262d]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${percentage}%`,
                            backgroundColor: severity.color,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          <section className="space-y-4">
            <div>
              <h3 className="text-base font-semibold text-gray-100">
                Detailed observation details
              </h3>
              <p className="mt-1 text-xs text-gray-600">
                Critical, High, Medium, and Low findings only. Informational
                observations are excluded.
              </p>
            </div>

            {["Critical", "High", "Medium", "Low"].map((severityName) => {
              const config = SEVERITIES.find(
                (item) => item.label === severityName,
              );
              const findings = findingsBySeverity[severityName];
              return (
                <div
                  key={severityName}
                  className={`overflow-hidden rounded-xl border ${config.panel}`}
                >
                  <div className="flex items-center justify-between border-b border-[#21262d] px-5 py-4">
                    <h4 className={`text-sm font-semibold ${config.text}`}>
                      {severityName} findings
                    </h4>
                    <span className="rounded-full bg-[#0d1117] px-2 py-0.5 text-xs text-gray-400">
                      {findings.length}
                    </span>
                  </div>
                  {findings.length === 0 ? (
                    <p className="px-5 py-6 text-xs text-gray-600">
                      No {severityName.toLowerCase()} findings were recorded for
                      this scan.
                    </p>
                  ) : (
                    <div className="divide-y divide-[#21262d]">
                      {findings.map((finding) => (
                        <article
                          key={finding.id}
                          className="space-y-4 bg-[#161b22]/70 p-5"
                        >
                          <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
                            <div>
                              <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                                Finding {finding.number}
                              </p>
                              <h5 className="mt-1 text-sm font-semibold text-gray-100">
                                {finding.title}
                              </h5>
                            </div>
                            <span
                              className={`w-fit rounded border px-2 py-1 text-[10px] font-semibold ${config.panel} ${config.text}`}
                            >
                              {finding.severity}
                            </span>
                          </div>

                          <dl className="grid gap-3 text-xs md:grid-cols-2 xl:grid-cols-4">
                            {[
                              ["Finding ID", finding.id],
                              ["Attack complexity", finding.attack_complexity],
                              ["CVE / CWE", finding.cve_cwe],
                              [
                                "Affected URL & ports",
                                finding.affected_url_ports,
                              ],
                            ].map(([label, value]) => (
                              <div
                                key={label}
                                className="rounded-lg border border-[#30363d] bg-[#0d1117] p-3"
                              >
                                <dt className="text-[10px] uppercase tracking-wide text-gray-600">
                                  {label}
                                </dt>
                                <dd className="mt-1 break-all font-mono text-[11px] leading-relaxed text-gray-300">
                                  {value}
                                </dd>
                              </div>
                            ))}
                          </dl>

                          <div className="grid gap-4 lg:grid-cols-3">
                            {[
                              ["Finding summary", finding.summary],
                              ["Potential impact", finding.potential_impact],
                              ["Recommendation", finding.recommendation],
                            ].map(([label, value]) => (
                              <div key={label}>
                                <p className="text-xs font-semibold text-gray-300">
                                  {label}
                                </p>
                                <p className="mt-1 whitespace-pre-wrap text-xs leading-relaxed text-gray-500">
                                  {value}
                                </p>
                              </div>
                            ))}
                          </div>
                        </article>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}

            {report.findings.length === 0 && (
              <div className="rounded-xl border border-dashed border-[#30363d] p-8 text-center text-sm text-gray-600">
                No actionable Critical-Low scanner matches were saved for this
                scan.
              </div>
            )}
          </section>

          <section className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 text-xs leading-relaxed text-blue-100/60">
            {report.report_scope_note}
          </section>
        </div>
      )}
    </div>
  );
}

export default function ReportsPage() {
  return (
    <AuthProvider>
      <AppLayout>
        <ReportsPageInner />
      </AppLayout>
    </AuthProvider>
  );
}
