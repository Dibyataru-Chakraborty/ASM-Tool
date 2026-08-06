"use client";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider } from "@/lib/auth";
import { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  AlertTriangle,
  Bot,
  Bug,
  CheckCircle2,
  FileText,
  Loader2,
  Map as MapIcon,
  Rocket,
} from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const H = () => ({
  Authorization: `Bearer ${typeof window !== "undefined" ? localStorage.getItem("access_token") : ""}`,
});

const SEV_STYLE = {
  critical: "tag-crit",
  high: "tag-high",
  medium: "tag-med",
  low: "tag-low",
};
const SEV_BAR = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-yellow-400",
  low: "bg-blue-400",
};

const PHASES = [
  { id: "phase2", label: "Crawl" },
  { id: "phase1", label: "Stack ID" },
  { id: "phase2b", label: "Attack Map" },
  { id: "phase3", label: "5× Agents" },
  { id: "phase4", label: "Exploit" },
  { id: "phase5", label: "Report" },
  { id: "done", label: "Done" },
];

function SeverityTag({ s }) {
  return <span className={SEV_STYLE[s?.toLowerCase()] || "tag-info"}>{s}</span>;
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const s = f.severity?.toLowerCase() || "low";
  return (
    <div
      className={`card overflow-hidden border-l-2 ${
        s === "critical"
          ? "border-l-red-500"
          : s === "high"
            ? "border-l-orange-500"
            : s === "medium"
              ? "border-l-yellow-500"
              : "border-l-blue-500"
      }`}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-[#1c2128] transition"
      >
        <div
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_BAR[s] || "bg-gray-400"}`}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <SeverityTag s={f.severity} />
            <span className="text-xs text-gray-500">CVSS {f.cvss_score}</span>
            <span className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-500 px-1.5 py-0.5 rounded">
              {f.vuln_class?.toUpperCase()}
            </span>
          </div>
          <p className="text-sm text-gray-200 font-medium truncate">
            {f.title}
          </p>
          <p className="text-xs text-gray-500 font-mono truncate">
            {f.target_url}
          </p>
        </div>
        <span className="text-gray-600 text-xs">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-[#21262d]">
          <div className="pt-3 grid grid-cols-2 gap-3 text-xs">
            <div>
              <p className="text-gray-500 mb-0.5">Parameter</p>
              <p className="font-mono text-gray-300">{f.parameter || "—"}</p>
            </div>
            <div>
              <p className="text-gray-500 mb-0.5">Method</p>
              <p className="font-mono text-gray-300">{f.method}</p>
            </div>
          </div>

          {f.description && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Description</p>
              <p className="text-xs text-gray-300 leading-relaxed">
                {f.description}
              </p>
            </div>
          )}

          {f.evidence && (
            <div className="bg-[#0d1117] rounded-lg p-3 border border-[#30363d]">
              <p className="text-xs text-gray-500 mb-1">Evidence</p>
              <p className="text-xs text-yellow-300">{f.evidence}</p>
            </div>
          )}

          {f.payload && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Payload</p>
              <code className="block bg-[#0d1117] border border-[#30363d] rounded-lg p-3 text-xs text-green-400 font-mono whitespace-pre-wrap break-all">
                {f.payload}
              </code>
            </div>
          )}

          {f.curl_command && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs text-gray-500">Reproduce</p>
                <button
                  onClick={() => navigator.clipboard.writeText(f.curl_command)}
                  className="text-[10px] text-blue-400 hover:text-blue-300"
                >
                  Copy
                </button>
              </div>
              <code className="block bg-[#0d1117] border border-[#30363d] rounded-lg p-3 text-xs text-cyan-300 font-mono whitespace-pre-wrap break-all">
                {f.curl_command}
              </code>
            </div>
          )}

          {f.poc && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Steps</p>
              <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-line bg-[#0d1117] border border-[#30363d] rounded-lg p-3">
                {f.poc}
              </div>
            </div>
          )}

          {f.remediation && (
            <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-3">
              <p className="text-xs text-green-400 font-medium mb-1 flex items-center gap-1.5">
                <span className="material-icons text-sm">build</span> Fix
              </p>
              <p className="text-xs text-gray-300">{f.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ShannonPageInner() {
  const [url, setUrl] = useState("");
  const [scanId, setScanId] = useState(null);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("findings");
  const poll = useRef(null);

  const start = async () => {
    if (!url.trim()) {
      setError("Enter a target URL");
      return;
    }
    setError("");
    setScan(null);
    setLoading(true);
    try {
      const r = await axios.post(
        `${API}/api/v1/shannon/scan`,
        { target_url: url },
        { headers: H() },
      );
      setScanId(r.data.scan_id);
    } catch (e) {
      setError(
        e.response?.data?.detail ||
          "Failed — check API is running and GEMINI_API_KEY is set",
      );
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!scanId) return;
    const fetch = async () => {
      try {
        const r = await axios.get(`${API}/api/v1/shannon/scan/${scanId}`, {
          headers: H(),
        });
        setScan(r.data);
        if (r.data.status === "completed" || r.data.status === "failed") {
          setLoading(false);
          clearInterval(poll.current);
        }
      } catch {}
    };
    fetch();
    poll.current = setInterval(fetch, 3000);
    return () => clearInterval(poll.current);
  }, [scanId]);

  const findings = scan?.report?.findings || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    counts[f.severity?.toLowerCase()] =
      (counts[f.severity?.toLowerCase()] || 0) + 1;
  });
  const currentPhaseIdx = PHASES.findIndex((p) => p.id === scan?.phase);

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold text-gray-100 flex items-center gap-2">
          <Bot className="h-5 w-5 text-blue-400" aria-hidden="true" />
          <span>AI Pentester</span>
        </h1>
        <p className="text-xs text-gray-500 mt-0.5">
          5-phase AI pentest · No exploit = no finding · Full Gemini-powered
          report
        </p>
      </div>

      {/* Input */}
      <div className="card p-4 space-y-3">
        <div className="flex gap-2">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !loading && start()}
            placeholder="https://target.com"
            type="url"
            className="input flex-1"
          />
          <button
            onClick={start}
            disabled={loading}
            className="btn-blue inline-flex items-center gap-2 whitespace-nowrap"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Rocket className="h-4 w-4" aria-hidden="true" />
            )}
            <span>{loading ? "Scanning…" : "Start Scan"}</span>
          </button>
        </div>
        {error && (
          <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            {error}
          </p>
        )}
        <p className="flex items-center gap-1 text-[10px] text-gray-600">
          <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />
          <span>
            Only scan targets you own or have written permission to test.
          </span>
        </p>
      </div>

      {/* How it works */}
      {!scan && !loading && (
        <div className="card p-4">
          <p className="text-xs font-semibold text-gray-400 mb-3">
            How it works
          </p>
          <div className="grid grid-cols-3 gap-2">
            {[
              {
                n: "1",
                t: "Crawl + Stack",
                d: "Discovers all endpoints, detects framework & auth",
              },
              {
                n: "2",
                t: "5× Gemini Agents",
                d: "Injection · XSS · Auth · AuthZ · SSRF — in parallel",
              },
              {
                n: "3",
                t: "Prove + Report",
                d: "Only confirmed exploits → Gemini writes full report",
              },
            ].map((s) => (
              <div
                key={s.n}
                className="bg-[#0d1117] border border-[#21262d] rounded-lg p-3"
              >
                <p className="text-blue-400 font-bold text-sm mb-1">
                  Phase {s.n}
                </p>
                <p className="text-xs text-gray-300 font-medium mb-0.5">
                  {s.t}
                </p>
                <p className="text-xs text-gray-600">{s.d}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Progress */}
      {scan && scan.status !== "completed" && scan.status !== "failed" && (
        <div className="card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-gray-200">Scanning…</p>
            <span className="text-xs text-blue-400 animate-pulse">● Live</span>
          </div>
          {/* Phase steps */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            {PHASES.map((p, i) => {
              const done = scan.status === "completed" || i < currentPhaseIdx;
              const active = i === currentPhaseIdx;
              return (
                <div key={p.id} className="flex items-center gap-1 shrink-0">
                  <span
                    className={`text-xs px-2 py-1 rounded font-medium transition ${
                      done
                        ? "text-green-400 bg-green-500/10"
                        : active
                          ? "text-blue-300 bg-blue-500/10 animate-pulse"
                          : "text-gray-600 bg-[#0d1117]"
                    }`}
                  >
                    {done ? "✓ " : active ? "● " : ""}
                    {p.label}
                  </span>
                  {i < PHASES.length - 1 && (
                    <span className="text-gray-700 text-xs">›</span>
                  )}
                </div>
              );
            })}
          </div>
          <p className="text-xs text-gray-400 bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-2">
            {scan.message || "Processing…"}
          </p>
        </div>
      )}

      {/* Failed */}
      {scan?.status === "failed" && (
        <div className="card p-4 border-red-500/20 bg-red-500/5">
          <p className="text-sm font-semibold text-red-400 mb-1">Scan Failed</p>
          <p className="text-xs text-gray-400">{scan.message}</p>
        </div>
      )}

      {/* Results */}
      {scan?.status === "completed" && scan.report && (
        <div className="space-y-4">
          {/* Done banner */}
          <div className="card p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <CheckCircle2
                className="h-7 w-7 text-green-400"
                aria-hidden="true"
              />
              <div>
                <p className="text-sm font-semibold text-gray-200">
                  Scan Complete
                </p>
                <p className="text-xs text-gray-500">
                  {findings.length} confirmed finding
                  {findings.length !== 1 ? "s" : ""} · Powered by AI
                </p>
              </div>
            </div>
            <div className="text-xs text-gray-600 font-mono">
              #{scan.report.scan_id}
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-4 gap-2">
            {[
              {
                label: "Critical",
                count: counts.critical || 0,
                cls: "text-red-400 bg-red-500/10 border-red-500/20",
              },
              {
                label: "High",
                count: counts.high || 0,
                cls: "text-orange-400 bg-orange-500/10 border-orange-500/20",
              },
              {
                label: "Medium",
                count: counts.medium || 0,
                cls: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
              },
              {
                label: "Low",
                count: counts.low || 0,
                cls: "text-blue-400 bg-blue-500/10 border-blue-500/20",
              },
            ].map((s) => (
              <div key={s.label} className={`rounded-xl border p-3 ${s.cls}`}>
                <p className={`text-2xl font-bold ${s.cls.split(" ")[0]}`}>
                  {s.count}
                </p>
                <p className="text-xs text-gray-500">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Summary */}
          {scan.report.summary && (
            <div className="card p-4">
              <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-2">
                Executive Summary
              </p>
              <p className="text-sm text-gray-300 leading-relaxed">
                {scan.report.summary}
              </p>
            </div>
          )}

          {/* Tabs */}
          <div className="flex gap-1">
            {[
              {
                id: "findings",
                label: `Findings (${findings.length})`,
                icon: <Bug className="h-3.5 w-3.5" aria-hidden="true" />,
              },
              {
                id: "surface",
                label: "Attack Surface",
                icon: <MapIcon className="h-3.5 w-3.5" aria-hidden="true" />,
              },
              {
                id: "report",
                label: "Full Report",
                icon: <FileText className="h-3.5 w-3.5" aria-hidden="true" />,
              },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${tab === t.id ? "bg-blue-600 text-white" : "text-gray-500 hover:text-gray-300 hover:bg-[#21262d]"}`}
              >
                {t.icon}
                <span>{t.label}</span>
              </button>
            ))}
          </div>

          {/* Findings */}
          {tab === "findings" && (
            <div className="space-y-2">
              {findings.length === 0 ? (
                <div className="card p-10 text-center">
                  <CheckCircle2
                    className="mx-auto mb-2 h-8 w-8 text-green-400"
                    aria-hidden="true"
                  />
                  <p className="text-sm font-medium text-gray-300">
                    No confirmed exploits
                  </p>
                  <p className="text-xs text-gray-600 mt-1">
                    Shannon policy: No exploit = No finding
                  </p>
                </div>
              ) : (
                findings.map((f, i) => <FindingCard key={i} f={f} />)
              )}
            </div>
          )}

          {/* Surface */}
          {tab === "surface" && scan.report.attack_surface && (
            <div className="card p-4 space-y-4">
              <div className="grid grid-cols-2 gap-3 text-sm">
                {[
                  ["Framework", scan.report.attack_surface.framework],
                  ["Language", scan.report.attack_surface.language],
                  ["Auth", scan.report.attack_surface.auth_mechanism],
                  ["Target", scan.report.attack_surface.target_url],
                ].map(([l, v]) => (
                  <div key={l}>
                    <p className="text-xs text-gray-500 mb-0.5">{l}</p>
                    <p className="text-gray-200 font-mono text-xs">
                      {v || "—"}
                    </p>
                  </div>
                ))}
              </div>
              {scan.report.attack_surface.technologies?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">Technologies</p>
                  <div className="flex flex-wrap gap-1.5">
                    {scan.report.attack_surface.technologies.map((t) => (
                      <span
                        key={t}
                        className="text-xs bg-[#0d1117] border border-[#30363d] text-gray-300 px-2 py-0.5 rounded"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {scan.report.attack_surface.endpoints?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">
                    High-Value Endpoints
                  </p>
                  <div className="space-y-1">
                    {scan.report.attack_surface.endpoints
                      .slice(0, 8)
                      .map((e, i) => (
                        <div
                          key={i}
                          className="flex gap-2 text-xs bg-[#0d1117] border border-[#21262d] rounded-lg px-3 py-1.5"
                        >
                          <span className="text-blue-400 font-mono shrink-0">
                            {e.method}
                          </span>
                          <span className="text-gray-300 font-mono truncate">
                            {e.url}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Full Gemini Report */}
          {tab === "report" && (
            <div className="card overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#21262d]">
                <span className="text-xs text-gray-500">
                  Full Report — Written by AI
                </span>
                <button
                  onClick={() => {
                    const blob = new Blob([scan.report.markdown], {
                      type: "text/markdown",
                    });
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = `shannon-report-${scan.report.scan_id}.md`;
                    a.click();
                  }}
                  className="text-xs text-blue-400 hover:text-blue-300 transition"
                >
                  ⬇ Download .md
                </button>
              </div>
              <pre className="p-4 text-xs text-gray-300 leading-relaxed whitespace-pre-wrap overflow-auto max-h-[60vh]">
                {scan.report.markdown}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ShannonPage(props) {
  return (
    <AuthProvider>
      <AppLayout>
        <ShannonPageInner {...props} />
      </AppLayout>
    </AuthProvider>
  );
}
