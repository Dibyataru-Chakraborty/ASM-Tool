"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Boxes, Filter, Search, ShieldQuestion } from "lucide-react";

import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider, useAuth } from "@/lib/auth";
import asm from "@/lib/api";

const STATUS_CLS = {
  new: "text-cyan-400",
  active: "text-green-400",
  changed: "text-yellow-400",
  inactive: "text-gray-500",
  historical: "text-gray-600",
};

function AttackSurfaceInventory() {
  const { user } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [status, setStatus] = useState("");
  const [ownership, setOwnership] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setSearch(params.get("search") || "");
    setType(params.get("asset_type") || "");
    setStatus(params.get("status") || "");
    setOwnership(params.get("ownership_status") || "");
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const inventory = await asm.getAttackSurfaceInventory({
        ...(search ? { search } : {}),
        ...(type ? { asset_type: type } : {}),
        ...(status ? { status } : {}),
        ...(ownership ? { ownership_status: ownership } : {}),
      });
      setRows(inventory.assets || []);
    } finally {
      setLoading(false);
    }
  }, [search, type, status, ownership]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <AppLayout>
      <div className="space-y-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-lg font-bold text-gray-100">
              Attack Surface Inventory
            </h1>
            <p className="mt-1 text-xs text-gray-500">
              {user?.organization_name || "Current organization"} · persistent
              assets with first/last-seen, ownership, criticality and risk
              context.
            </p>
          </div>
          <div className="flex gap-2">
            <Link href="/assets" className="btn-gray text-xs">
              Company Domains & Seeds
            </Link>
            <Link href="/recon" className="btn-blue text-xs">
              Run Discovery
            </Link>
          </div>
        </div>

        <div className="card p-3">
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
            <div className="relative xl:col-span-2">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-600" />
              <input
                className="input pl-9"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search asset, host, IP or service"
              />
            </div>
            <select
              className="input"
              value={type}
              onChange={(e) => setType(e.target.value)}
            >
              <option value="">All asset types</option>
              {[
                "domain",
                "subdomain",
                "ip",
                "service",
                "certificate",
                "candidate_domain",
              ].map((v) => (
                <option key={v} value={v}>
                  {v.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <select
              className="input"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All lifecycle states</option>
              {["new", "active", "changed", "inactive", "historical"].map(
                (v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ),
              )}
            </select>
            <select
              className="input"
              value={ownership}
              onChange={(e) => setOwnership(e.target.value)}
            >
              <option value="">All ownership states</option>
              <option value="confirmed">Confirmed</option>
              <option value="high_confidence">High confidence</option>
              <option value="requires_investigation">
                Requires investigation
              </option>
              <option value="rejected">Rejected</option>
            </select>
          </div>
        </div>

        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-[#21262d] px-4 py-3">
            <div className="flex items-center gap-2">
              <Boxes className="h-4 w-4 text-blue-400" />
              <p className="text-xs font-semibold text-gray-300">
                {rows.length} inventoried assets
              </p>
            </div>
            <div className="flex items-center gap-1 text-[10px] text-gray-600">
              <Filter className="h-3 w-3" /> Dynamic ASM state
            </div>
          </div>
          {loading ? (
            <div className="py-16 text-center text-xs text-gray-600">
              Loading attack surface…
            </div>
          ) : rows.length === 0 ? (
            <div className="py-16 text-center">
              <ShieldQuestion className="mx-auto mb-3 h-8 w-8 text-gray-600" />
              <p className="text-sm text-gray-400">
                No persistent assets match these filters.
              </p>
              <p className="mt-1 text-xs text-gray-600">
                Run a discovery cycle or rebuild from an existing completed
                scan.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1050px] text-xs">
                <thead>
                  <tr className="border-b border-[#21262d] text-left text-[10px] uppercase tracking-wide text-gray-600">
                    {[
                      "Asset",
                      "Organization",
                      "Type",
                      "Lifecycle",
                      "Ownership",
                      "Criticality",
                      "First Seen",
                      "Last Seen",
                      "ASM Risk",
                    ].map((h) => (
                      <th key={h} className="px-4 py-3 font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((asset) => (
                    <tr
                      key={asset.id}
                      className="border-b border-[#21262d] hover:bg-[#1c2128]"
                    >
                      <td className="px-4 py-3">
                        <Link
                          href={`/attack-surface/${asset.id}`}
                          className="font-mono font-medium text-gray-200 hover:text-blue-400"
                        >
                          {asset.display_name || asset.value}
                        </Link>
                        <p className="mt-1 max-w-xs truncate text-[10px] text-gray-600">
                          {asset.value}
                        </p>
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {asset.organization_name}
                      </td>
                      <td className="px-4 py-3 capitalize text-gray-400">
                        {asset.asset_type.replaceAll("_", " ")}
                      </td>
                      <td
                        className={`px-4 py-3 capitalize font-medium ${STATUS_CLS[asset.status] || "text-gray-400"}`}
                      >
                        {asset.status}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={
                            asset.ownership_status === "requires_investigation"
                              ? "text-yellow-400"
                              : asset.ownership_status === "rejected"
                                ? "text-red-400"
                                : "text-gray-400"
                          }
                        >
                          {asset.ownership_status.replaceAll("_", " ")}
                        </span>
                      </td>
                      <td className="px-4 py-3 capitalize text-gray-400">
                        {asset.criticality}
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {new Date(asset.first_seen).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {new Date(asset.last_seen).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`${asset.risk_score >= 80 ? "text-red-400" : asset.risk_score >= 60 ? "text-orange-400" : asset.risk_score >= 40 ? "text-yellow-400" : "text-blue-400"} font-bold`}
                        >
                          {asset.risk_score}
                        </span>
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

export default function AttackSurfacePage() {
  return (
    <AuthProvider>
      <AttackSurfaceInventory />
    </AuthProvider>
  );
}
