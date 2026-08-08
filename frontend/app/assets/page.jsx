"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Building2,
  KeyRound,
  Plus,
  RefreshCw,
  Trash2,
  X,
  ShieldAlert,
} from "lucide-react";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider, useAuth } from "@/lib/auth";
import asm from "@/lib/api";

function DomainModal({ onClose, onSaved }) {
  const [domain, setDomain] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const clean = domain
        .trim()
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "")
        .toLowerCase();
      await asm.createAsset({
        name: clean,
        target: clean,
        description,
        asset_type: "domain",
        tags: [],
      });
      onSaved();
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not add company domain");
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="card relative w-full max-w-lg p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">
              Add Company Domain
            </h2>
            <p className="mt-1 text-[10px] text-gray-600">
              This domain becomes an approved target inside your organization
              only.
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-600 hover:text-gray-300"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {error && (
          <div className="mb-3 rounded-lg border border-red-500/20 bg-red-500/10 p-2 text-xs text-red-400">
            {error}
          </div>
        )}
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-gray-500">
              Company domain *
            </label>
            <input
              className="input font-mono"
              required
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
            />
            <p className="mt-1 text-[10px] text-gray-600">
              Only add domains your organization owns or is authorized to
              monitor.
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-500">
              Description
            </label>
            <textarea
              className="input h-20 resize-none"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Production website, subsidiary, customer portal…"
            />
          </div>
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="btn-gray flex-1">
              Cancel
            </button>
            <button className="btn-blue flex-1" disabled={saving}>
              {saving ? "Adding…" : "Add Domain"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function SeedsPanel({ organizationId }) {
  const [seeds, setSeeds] = useState([]);
  const [value, setValue] = useState("");
  const [type, setType] = useState("domain");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(() => {
    setLoading(true);
    asm
      .getDiscoverySeeds(organizationId)
      .then((d) => setSeeds(d.seeds || []))
      .catch((e) =>
        setError(e.response?.data?.detail || "Could not load seeds"),
      )
      .finally(() => setLoading(false));
  }, [organizationId]);
  useEffect(() => {
    load();
  }, [load]);
  const add = async (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    setError("");
    try {
      await asm.createDiscoverySeed({
        organization_id: organizationId,
        seed_type: type,
        value: value.trim(),
        is_primary: false,
      });
      setValue("");
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not add discovery seed");
    }
  };
  const remove = async (id) => {
    try {
      await asm.deleteDiscoverySeed(id);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Could not remove seed");
    }
  };
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
        <KeyRound className="h-4 w-4 text-cyan-400" />
        <div>
          <p className="text-xs font-semibold text-gray-300">
            Organization Discovery Seeds
          </p>
          <p className="text-[10px] text-gray-600">
            Known starting points for continuous attack-surface discovery.
          </p>
        </div>
      </div>
      <div className="p-4">
        {error && (
          <div className="mb-3 rounded-lg border border-red-500/20 bg-red-500/10 p-2 text-xs text-red-400">
            {error}
          </div>
        )}
        <form
          onSubmit={add}
          className="mb-4 grid gap-2 sm:grid-cols-[140px_1fr_auto]"
        >
          <select
            className="input"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="domain">Domain</option>
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="asn">ASN</option>
          </select>
          <input
            className="input font-mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={
              type === "domain"
                ? "subsidiary.example.com"
                : type === "asn"
                  ? "AS64500"
                  : "203.0.113.0/24"
            }
          />
          <button className="btn-blue flex items-center justify-center gap-1">
            <Plus className="h-4 w-4" />
            Add
          </button>
        </form>
        <div className="max-h-72 overflow-y-auto rounded-lg border border-[#30363d]">
          {loading ? (
            <div className="py-10 text-center text-xs text-gray-600">
              Loading seeds…
            </div>
          ) : seeds.length === 0 ? (
            <div className="py-10 text-center text-xs text-gray-600">
              No organization-level seeds yet.
            </div>
          ) : (
            <div className="divide-y divide-[#21262d]">
              {seeds.map((seed) => (
                <div
                  key={seed.id}
                  className="flex items-center gap-3 px-3 py-3"
                >
                  <KeyRound className="h-4 w-4 text-cyan-400" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs text-gray-300">
                      {seed.value}
                    </p>
                    <p className="mt-1 text-[10px] uppercase text-gray-600">
                      {seed.seed_type} ·{" "}
                      {(seed.ownership_status || "confirmed").replaceAll(
                        "_",
                        " ",
                      )}{" "}
                      · {Math.round((seed.confidence_score || 0) * 100)}%
                      confidence
                    </p>
                  </div>
                  {seed.is_primary && (
                    <span className="rounded border border-blue-500/20 bg-blue-500/10 px-2 py-1 text-[10px] text-blue-400">
                      PRIMARY
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => remove(seed.id)}
                    className="text-gray-600 hover:text-red-400"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CompanyDomainsContent() {
  const { user } = useAuth();
  const organizationId = user?.organization_id || "";
  const isAdmin =
    user?.platform_role === "super_admin" ||
    user?.organization_role === "admin";
  if (user && !isAdmin)
    return (
      <AppLayout>
        <div className="card p-8 text-center">
          <ShieldAlert className="mx-auto h-8 w-8 text-red-400" />
          <h2 className="mt-3 font-semibold">
            Organization Admin access required
          </h2>
        </div>
      </AppLayout>
    );
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await asm.getAssets({ limit: 100 });
      setTargets(d.items || d.assets || []);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  const rebuild = async () => {
    if (!organizationId) return;
    setWorking(true);
    setMessage("");
    try {
      const r = await asm.rebuildAttackSurface(organizationId);
      setMessage(
        r.total
          ? `Attack surface rebuilt from ${r.total} completed domain scan(s).`
          : "No completed scan is available yet. Run Discovery first.",
      );
    } catch (e) {
      setMessage(e.response?.data?.detail || "Rebuild failed");
    } finally {
      setWorking(false);
    }
  };
  const del = async (target) => {
    if (
      !confirm(
        `Remove ${target.target || target.name} and its associated scan history?`,
      )
    )
      return;
    await asm.deleteAsset(target.id);
    load();
  };
  return (
    <AppLayout>
      <div className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-lg font-bold text-gray-100">
              Company Domains & Discovery Seeds
            </h1>
            <p className="mt-1 text-xs text-gray-500">
              {user?.organization_name || "Your organization"} controls this
              scope. Domains and seeds added here cannot be seen by another
              tenant.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              className="btn-gray flex items-center gap-1.5 text-xs"
              onClick={rebuild}
              disabled={!organizationId || working}
            >
              <RefreshCw
                className={`h-4 w-4 ${working ? "animate-spin" : ""}`}
              />
              Rebuild Inventory
            </button>
            <button
              className="btn-blue flex items-center gap-1.5 text-xs"
              onClick={() => setCreateOpen(true)}
            >
              <Plus className="h-4 w-4" />
              Add Domain
            </button>
          </div>
        </div>
        {message && (
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-2 text-xs text-gray-300">
            {message}
          </div>
        )}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
            <Building2 className="h-4 w-4 text-indigo-400" />
            <p className="text-xs font-semibold text-gray-300">
              {targets.length} approved target{targets.length === 1 ? "" : "s"}
            </p>
          </div>
          {loading ? (
            <div className="py-14 text-center text-xs text-gray-600">
              Loading company domains…
            </div>
          ) : targets.length === 0 ? (
            <div className="py-14 text-center">
              <Building2 className="mx-auto mb-3 h-8 w-8 text-gray-600" />
              <p className="text-sm text-gray-400">No company domains yet.</p>
              <p className="mt-1 text-xs text-gray-600">
                Add the first approved domain to begin discovery.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#21262d]">
              {targets.map((t) => (
                <div
                  key={t.id}
                  className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center"
                >
                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-sm font-semibold text-cyan-400">
                      {t.target || t.name}
                    </p>
                    {t.description && (
                      <p className="mt-1 text-xs text-gray-600">
                        {t.description}
                      </p>
                    )}
                    <div className="mt-2 flex gap-4 text-[10px] text-gray-600">
                      <span>{t.scan_count || 0} discovery cycles</span>
                      <span>
                        Last observed:{" "}
                        {t.last_scanned_at
                          ? new Date(t.last_scanned_at).toLocaleString()
                          : "Never"}
                      </span>
                      <span>Risk: {t.risk_score || 0}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => del(t)}
                    className="btn-gray flex items-center gap-1 text-xs text-red-400"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
        {organizationId && <SeedsPanel organizationId={organizationId} />}
        {createOpen && (
          <DomainModal onClose={() => setCreateOpen(false)} onSaved={load} />
        )}
      </div>
    </AppLayout>
  );
}

export default function AssetsPage() {
  return (
    <AuthProvider>
      <CompanyDomainsContent />
    </AuthProvider>
  );
}
