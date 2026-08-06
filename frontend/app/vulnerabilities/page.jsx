"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider, useAuth } from "@/lib/auth";
import asm from "@/lib/api";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const SEV_CLS = {
  critical: "tag-crit",
  high: "tag-high",
  medium: "tag-med",
  low: "tag-low",
  info: "tag-info",
};
const EMPTY_COUNTS = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

export default function VulnsPage() {
  const { user } = useAuth();
  const isAdmin =
    user?.platform_role === "super_admin" ||
    user?.organization_role === "admin";
  const [vulns, setVulns] = useState([]);
  const [scans, setScans] = useState([]);
  const [counts, setCounts] = useState(EMPTY_COUNTS);
  const [total, setTotal] = useState(0);
  const [sev, setSev] = useState("");
  const [scanId, setScanId] = useState("");
  const [skip, setSkip] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const LIMIT = 20;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = { skip, limit: LIMIT };
      if (sev) params.severity = sev;
      if (scanId) params.scan_id = scanId;

      const response = await asm.getVulns(params);
      setVulns(response.vulnerabilities || []);
      setScans(response.scans || []);
      setCounts({ ...EMPTY_COUNTS, ...(response.severity_counts || {}) });
      setTotal(response.total || 0);
    } catch (requestError) {
      setVulns([]);
      setTotal(0);
      setError(
        requestError?.response?.data?.detail ||
          requestError?.message ||
          "Failed to load vulnerability history",
      );
    } finally {
      setLoading(false);
    }
  }, [sev, scanId, skip]);

  useEffect(() => {
    load();
  }, [load]);

  const markFP = async (id) => {
    await asm.markFP(id);
    await load();
  };

  const clearFilters = () => {
    setSev("");
    setScanId("");
    setSkip(0);
  };

  return (
    <AuthProvider>
      <AppLayout>
        <div className="space-y-4">
          <div>
            <h1 className="text-base font-bold text-gray-100">
              Vulnerabilities
            </h1>
            <p className="text-xs text-gray-500">
              {total} real scanner findings and observations from saved scan
              history
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            {["critical", "high", "medium", "low", "info"].map((severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => {
                  setSev(sev === severity ? "" : severity);
                  setSkip(0);
                }}
                className={`card p-3 text-center transition hover:border-blue-500/30 ${sev === severity ? "border-blue-500/50" : ""}`}
              >
                <p
                  className={`text-xl font-bold ${SEV_CLS[severity]?.split(" ")[0] || "text-gray-400"}`}
                >
                  {counts[severity] || 0}
                </p>
                <p className="text-[10px] capitalize text-gray-600">
                  {severity === "info" ? "observations" : severity}
                </p>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap gap-2">
            <select
              className="input w-36 py-1.5 text-xs"
              value={sev}
              onChange={(event) => {
                setSev(event.target.value);
                setSkip(0);
              }}
              aria-label="Filter findings by severity"
            >
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity || "All Severity"}
                </option>
              ))}
            </select>
            <select
              className="input min-w-64 py-1.5 text-xs"
              value={scanId}
              onChange={(event) => {
                setScanId(event.target.value);
                setSkip(0);
              }}
              aria-label="Filter findings by scan ID"
            >
              <option value="">All Scan IDs</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.reference_id} · {scan.target_domain || "Unknown target"}{" "}
                  ({scan.finding_count})
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={clearFilters}
              className="btn-gray text-xs"
            >
              Clear
            </button>
          </div>

          {error && (
            <div className="flex items-center justify-between rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-3">
              <p className="text-xs text-red-400">{error}</p>
              <button
                type="button"
                onClick={load}
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                Retry
              </button>
            </div>
          )}

          <div className="card overflow-x-auto">
            {loading ? (
              <div className="py-12 text-center text-sm text-gray-600 animate-pulse">
                Loading…
              </div>
            ) : vulns.length === 0 ? (
              <div className="py-12 text-center">
                <p className="mb-2"><span className="material-icons text-4xl text-gray-600">bug_report</span></p>
                <p className="text-sm text-gray-500">
                  No vulnerabilities found
                </p>
                <p className="mt-1 text-xs text-gray-600">
                  {sev || scanId
                    ? "Clear the filters to view all saved findings"
                    : "Run a scan to discover real vulnerabilities"}
                </p>
              </div>
            ) : (
              <table className="w-full min-w-[1180px] text-xs">
                <thead>
                  <tr className="border-b border-[#21262d]">
                    {[
                      "Title",
                      "Severity",
                      "CVSS",
                      "CVE",
                      "Host",
                      "Scan ID",
                      "Date",
                      "Actions",
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
                  {vulns.map((vulnerability) => (
                    <tr
                      key={vulnerability.id}
                      className={`border-b border-[#21262d] transition hover:bg-[#1c2128] ${vulnerability.is_false_positive ? "opacity-40" : ""}`}
                    >
                      <td className="max-w-xs px-4 py-2.5">
                        <Link
                          href={`/vulnerabilities/${vulnerability.id}`}
                          className="block truncate text-gray-200 hover:text-blue-400"
                        >
                          {vulnerability.title}
                        </Link>
                        <div className="mt-0.5 flex gap-2 text-[10px] text-gray-600">
                          {vulnerability.source && (
                            <span>{vulnerability.source}</span>
                          )}
                          {vulnerability.is_false_positive && (
                            <span>False positive</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={
                            SEV_CLS[vulnerability.severity] || "tag-info"
                          }
                        >
                          {vulnerability.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        {vulnerability.cvss_score == null ? (
                          <span className="text-gray-600">—</span>
                        ) : (
                          <span
                            className={`text-xs font-bold ${vulnerability.cvss_score >= 9 ? "text-red-400" : vulnerability.cvss_score >= 7 ? "text-orange-400" : vulnerability.cvss_score >= 4 ? "text-yellow-400" : "text-blue-400"}`}
                          >
                            {Number(vulnerability.cvss_score).toFixed(1)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-blue-400">
                        {vulnerability.cve_id || "—"}
                      </td>
                      <td className="max-w-[160px] px-4 py-2.5 font-mono text-gray-400">
                        <p
                          className="truncate"
                          title={vulnerability.host || undefined}
                        >
                          {vulnerability.host || "—"}
                        </p>
                        {vulnerability.port != null && (
                          <p className="text-[10px] text-gray-600">
                            Port {vulnerability.port}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <Link
                          href={`/scans/${vulnerability.scan_id}`}
                          className="font-mono text-[10px] text-blue-400 hover:text-blue-300"
                          title={vulnerability.scan_id}
                        >
                          {vulnerability.scan_reference ||
                            vulnerability.scan_id}
                        </Link>
                        {vulnerability.scan_target && (
                          <p className="mt-0.5 max-w-[180px] truncate font-mono text-[10px] text-gray-600">
                            {vulnerability.scan_target}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-gray-500">
                        {vulnerability.created_at
                          ? new Date(
                              vulnerability.created_at,
                            ).toLocaleDateString()
                          : ""}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-2">
                          <Link
                            href={`/vulnerabilities/${vulnerability.id}`}
                            className="text-xs text-blue-400 hover:text-blue-300"
                          >
                            Detail
                          </Link>
                          {isAdmin && (
                            <>
                              <span className="text-gray-700">|</span>
                              <button
                                type="button"
                                onClick={() => markFP(vulnerability.id)}
                                className="text-xs text-gray-500 hover:text-gray-300"
                              >
                                {vulnerability.is_false_positive
                                  ? "Restore"
                                  : "FP"}
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {total > LIMIT && (
              <div className="flex items-center justify-between border-t border-[#21262d] px-4 py-3">
                <span className="text-xs text-gray-500">
                  Showing {skip + 1}–{Math.min(skip + LIMIT, total)} of {total}
                </span>
                <div className="flex gap-1">
                  <button
                    type="button"
                    disabled={skip === 0}
                    onClick={() => setSkip(Math.max(0, skip - LIMIT))}
                    className="btn-gray text-xs disabled:opacity-40"
                  >
                    ← Prev
                  </button>
                  <button
                    type="button"
                    disabled={skip + LIMIT >= total}
                    onClick={() => setSkip(skip + LIMIT)}
                    className="btn-gray text-xs disabled:opacity-40"
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </AppLayout>
    </AuthProvider>
  );
}
