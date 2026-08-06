"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Clock3, Link2, ShieldAlert } from "lucide-react";

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

function AssetDetailContent() {
  const params = useParams();
  const id = String(params.id);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const load = () =>
    asm
      .getAttackSurfaceAsset(id)
      .then(setData)
      .finally(() => setLoading(false));
  useEffect(() => {
    load();
  }, [id]);
  const update = async (field, value) => {
    setSaving(true);
    try {
      await asm.updateAttackSurfaceAsset(id, { [field]: value });
      await load();
    } finally {
      setSaving(false);
    }
  };
  if (loading)
    return (
      <AppLayout>
        <div className="py-20 text-center text-xs text-gray-600">
          Loading asset history…
        </div>
      </AppLayout>
    );
  if (!data)
    return (
      <AppLayout>
        <div className="py-20 text-center text-xs text-gray-600">
          Asset not found.
        </div>
      </AppLayout>
    );
  const a = data.asset;
  return (
    <AppLayout>
      <div className="space-y-4">
        <div>
          <Link
            href="/attack-surface"
            className="mb-3 inline-flex items-center gap-1 text-xs text-blue-400"
          >
            <ArrowLeft className="h-3 w-3" />
            Back to inventory
          </Link>
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <h1 className="break-all font-mono text-lg font-bold text-gray-100">
                {a.display_name || a.value}
              </h1>
              <p className="mt-1 text-xs text-gray-500">
                {a.organization_name} · {a.asset_type.replaceAll("_", " ")} ·{" "}
                {a.status}
              </p>
            </div>
            <div className="rounded-lg border border-[#30363d] px-4 py-2 text-right">
              <p
                className={`${a.risk_score >= 80 ? "text-red-400" : a.risk_score >= 60 ? "text-orange-400" : a.risk_score >= 40 ? "text-yellow-400" : "text-blue-400"} text-xl font-bold`}
              >
                {a.risk_score}/100
              </p>
              <p className="text-[10px] text-gray-600">ASM risk</p>
            </div>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <div className="card p-4 lg:col-span-2">
            <p className="mb-3 text-xs font-semibold text-gray-300">
              Asset Context
            </p>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <p className="text-[10px] uppercase text-gray-600">
                  First seen
                </p>
                <p className="mt-1 text-xs text-gray-300">
                  {new Date(a.first_seen).toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase text-gray-600">Last seen</p>
                <p className="mt-1 text-xs text-gray-300">
                  {new Date(a.last_seen).toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase text-gray-600">
                  Internet exposed
                </p>
                <p className="mt-1 text-xs text-gray-300">
                  {a.internet_exposed ? "Yes" : "No"}
                </p>
              </div>
              <div>
                <p className="mb-1 text-[10px] uppercase text-gray-600">
                  Criticality
                </p>
                <select
                  disabled={saving}
                  className="input py-1.5 text-xs"
                  value={a.criticality}
                  onChange={(e) => update("criticality", e.target.value)}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="normal">Normal</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="sm:col-span-2">
                <p className="mb-1 text-[10px] uppercase text-gray-600">
                  Ownership attribution
                </p>
                <select
                  disabled={saving}
                  className="input py-1.5 text-xs"
                  value={a.ownership_status}
                  onChange={(e) => update("ownership_status", e.target.value)}
                >
                  <option value="confirmed">Confirmed</option>
                  <option value="high_confidence">High confidence</option>
                  <option value="requires_investigation">
                    Requires investigation
                  </option>
                  <option value="rejected">Rejected</option>
                </select>
                <p className="mt-1 text-[10px] text-gray-600">
                  Confidence {Math.round((a.confidence_score || 0) * 100)}%
                </p>
              </div>
            </div>
          </div>
          <div className="card p-4">
            <p className="mb-3 text-xs font-semibold text-gray-300">
              Observed Metadata
            </p>
            <div className="space-y-2">
              {Object.entries(a.metadata || {})
                .slice(0, 10)
                .map(([k, v]) => (
                  <div key={k}>
                    <p className="text-[10px] uppercase text-gray-600">
                      {k.replaceAll("_", " ")}
                    </p>
                    <p className="break-all text-xs text-gray-400">
                      {Array.isArray(v) ? v.join(", ") : String(v ?? "—")}
                    </p>
                  </div>
                ))}
            </div>
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <div className="card overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
              <Link2 className="h-4 w-4 text-cyan-400" />
              <p className="text-xs font-semibold text-gray-300">
                Asset Relationships
              </p>
            </div>
            {data.relationships.length === 0 ? (
              <div className="py-10 text-center text-xs text-gray-600">
                No relationships recorded.
              </div>
            ) : (
              <div className="divide-y divide-[#21262d]">
                {data.relationships.map((r) => (
                  <div key={r.id} className="px-4 py-3">
                    <p className="text-[10px] uppercase text-gray-600">
                      {r.relationship_type.replaceAll("_", " ")} · {r.direction}
                    </p>
                    {r.peer ? (
                      <Link
                        href={`/attack-surface/${r.peer.id}`}
                        className="mt-1 block font-mono text-xs text-blue-400"
                      >
                        {r.peer.display_name || r.peer.value}
                      </Link>
                    ) : (
                      <p className="mt-1 text-xs text-gray-500">
                        Relationship target unavailable
                      </p>
                    )}
                    <p className="mt-1 text-[10px] text-gray-600">
                      Confidence {Math.round((r.confidence_score || 0) * 100)}%
                      · {r.is_active ? "active" : "historical"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="card overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
              <ShieldAlert className="h-4 w-4 text-orange-400" />
              <p className="text-xs font-semibold text-gray-300">
                Open / Historical Exposures
              </p>
            </div>
            {data.exposures.length === 0 ? (
              <div className="py-10 text-center text-xs text-gray-600">
                No exposures recorded for this asset.
              </div>
            ) : (
              <div className="divide-y divide-[#21262d]">
                {data.exposures.map((e) => (
                  <div key={e.id} className="px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-medium text-gray-300">
                          {e.title}
                        </p>
                        <p className="mt-1 text-[10px] capitalize text-gray-600">
                          {e.exposure_type.replaceAll("_", " ")} · {e.status}
                        </p>
                      </div>
                      <span className={SEV[e.severity] || "tag-info"}>
                        {e.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="mt-2 text-[10px] text-gray-600">
                      ASM risk {e.risk_score}/100 · Last seen{" "}
                      {new Date(e.last_seen).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
            <Clock3 className="h-4 w-4 text-purple-400" />
            <p className="text-xs font-semibold text-gray-300">Asset History</p>
          </div>
          {data.changes.length === 0 ? (
            <div className="py-10 text-center text-xs text-gray-600">
              No material changes recorded yet.
            </div>
          ) : (
            <div className="divide-y divide-[#21262d]">
              {data.changes.map((c) => (
                <div key={c.id} className="flex items-start gap-3 px-4 py-3">
                  <span
                    className={`mt-1.5 h-2 w-2 rounded-full ${c.severity === "critical" ? "bg-red-400" : c.severity === "high" ? "bg-orange-400" : c.severity === "medium" ? "bg-yellow-400" : "bg-blue-400"}`}
                  />
                  <div>
                    <p className="text-xs text-gray-300">{c.title}</p>
                    <p className="mt-1 text-[10px] text-gray-600">
                      {new Date(c.detected_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
export default function AssetDetailPage() {
  return (
    <AuthProvider>
      <AssetDetailContent />
    </AuthProvider>
  );
}
