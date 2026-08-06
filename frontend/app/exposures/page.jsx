"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider } from "@/lib/auth";
import asm from "@/lib/api";

const SEV = {
  critical: "tag-crit",
  high: "tag-high",
  medium: "tag-med",
  low: "tag-low",
  info: "tag-info",
};
const REMEDIATION = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["accepted_risk", "Accepted risk"],
  ["false_positive", "False positive"],
  ["resolved", "Resolved"],
];

function ExposuresContent() {
  const [rows, setRows] = useState([]);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("severity")) setSeverity(params.get("severity") || "");
    if (params.has("status")) setStatus(params.get("status") || "");
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    asm
      .getExposures({ ...(severity ? { severity } : {}), status, limit: 500 })
      .then((d) => setRows(d.exposures || []))
      .finally(() => setLoading(false));
  }, [severity, status]);
  useEffect(() => {
    load();
  }, [load]);

  const updateStatus = async (id, next) => {
    setSaving(id);
    try {
      const updated = await asm.updateExposureStatus(id, next);
      if (status && next !== status)
        setRows((prev) => prev.filter((row) => row.id !== id));
      else
        setRows((prev) =>
          prev.map((row) =>
            row.id === id
              ? {
                  ...row,
                  status: updated.status,
                  resolved_at: updated.resolved_at,
                }
              : row,
          ),
        );
    } finally {
      setSaving("");
    }
  };

  return (
    <AppLayout>
      <div className="space-y-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-lg font-bold text-gray-100">
              Exposures & Remediation
            </h1>
            <p className="mt-1 text-xs text-gray-500">
              Prioritize internet-facing risk using vulnerability severity,
              asset criticality and exposure context, then track the remediation
              state.
            </p>
          </div>
          <Link href="/vulnerabilities" className="btn-gray text-xs">
            Raw Vulnerability Findings
          </Link>
        </div>
        <div className="card p-3">
          <div className="grid gap-2 sm:grid-cols-2 md:max-w-xl">
            <select
              className="input"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
            <select
              className="input"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All remediation states</option>
              {REMEDIATION.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
            <ShieldAlert className="h-4 w-4 text-orange-400" />
            <p className="text-xs font-semibold text-gray-300">
              {rows.length} exposures
            </p>
          </div>
          {loading ? (
            <div className="py-16 text-center text-xs text-gray-600">
              Loading exposures…
            </div>
          ) : rows.length === 0 ? (
            <div className="py-16 text-center text-xs text-gray-600">
              No exposures match this view.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1120px] text-xs">
                <thead>
                  <tr className="border-b border-[#21262d] text-left text-[10px] uppercase tracking-wide text-gray-600">
                    {[
                      "Exposure",
                      "Asset",
                      "Type",
                      "Severity",
                      "ASM Risk",
                      "CVSS",
                      "First Seen",
                      "Last Seen",
                      "Remediation",
                    ].map((h) => (
                      <th className="px-4 py-3 font-medium" key={h}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((e) => (
                    <tr
                      key={e.id}
                      className="border-b border-[#21262d] hover:bg-[#1c2128]"
                    >
                      <td className="px-4 py-3">
                        <p className="font-medium text-gray-300">{e.title}</p>
                        <p className="mt-1 text-[10px] text-gray-600">
                          {e.organization_name}
                        </p>
                      </td>
                      <td className="px-4 py-3">
                        {e.asset_id ? (
                          <Link
                            className="font-mono text-blue-400"
                            href={`/attack-surface/${e.asset_id}`}
                          >
                            {e.asset_value}
                          </Link>
                        ) : (
                          <span className="text-gray-600">Unmapped</span>
                        )}
                      </td>
                      <td className="px-4 py-3 capitalize text-gray-400">
                        {e.exposure_type.replace(/_/g, " ")}
                      </td>
                      <td className="px-4 py-3">
                        <span className={SEV[e.severity] || "tag-info"}>
                          {e.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-bold text-gray-200">
                        {e.risk_score}/100
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {e.cvss_score ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {new Date(e.first_seen).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {new Date(e.last_seen).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <select
                          className="input min-w-[145px] py-1 text-[11px]"
                          value={e.status}
                          disabled={saving === e.id}
                          onChange={(ev) => updateStatus(e.id, ev.target.value)}
                        >
                          {REMEDIATION.map(([value, label]) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
export default function ExposuresPage() {
  return (
    <AuthProvider>
      <ExposuresContent />
    </AuthProvider>
  );
}
