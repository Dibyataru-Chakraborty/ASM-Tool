"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, ArrowRight } from "lucide-react";
import AppLayout from "@/components/layout/AppLayout";
import { AuthProvider } from "@/lib/auth";
import asm from "@/lib/api";

function ChangesContent() {
  const [changes, setChanges] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    asm
      .getAttackSurfaceChanges({ limit: 300 })
      .then((d) => setChanges(d.changes || []))
      .finally(() => setLoading(false));
  }, []);

  return (
    <AppLayout>
      <div className="space-y-4">
        <div>
          <h1 className="text-lg font-bold text-gray-100">
            Attack Surface Changes
          </h1>
          <p className="mt-1 text-xs text-gray-500">
            Difference between monitoring observations: newly found, modified,
            disappeared, reappeared and resolved exposure events.
          </p>
        </div>
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-[#21262d] px-4 py-3">
            <Activity className="h-4 w-4 text-cyan-400" />
            <p className="text-xs font-semibold text-gray-300">
              Change timeline
            </p>
          </div>
          {loading ? (
            <div className="py-16 text-center text-xs text-gray-600">
              Loading changes…
            </div>
          ) : changes.length === 0 ? (
            <div className="py-16 text-center text-xs text-gray-600">
              No changes have been recorded yet.
            </div>
          ) : (
            <div className="divide-y divide-[#21262d]">
              {changes.map((change) => (
                <div
                  key={change.id}
                  className="flex items-start gap-4 px-4 py-3"
                >
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${change.severity === "critical" ? "bg-red-400" : change.severity === "high" ? "bg-orange-400" : change.severity === "medium" ? "bg-yellow-400" : change.severity === "low" ? "bg-blue-400" : "bg-gray-500"}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-xs font-medium text-gray-300">
                        {change.title}
                      </p>
                      <span className="rounded border border-[#30363d] px-1.5 py-0.5 text-[9px] uppercase text-gray-600">
                        {change.change_type.replaceAll("_", " ")}
                      </span>
                    </div>
                    <p className="mt-1 text-[10px] text-gray-600">
                      {change.organization_name} ·{" "}
                      {new Date(change.detected_at).toLocaleString()}
                    </p>
                  </div>
                  {change.asset_id && (
                    <Link
                      href={`/attack-surface/${change.asset_id}`}
                      className="flex items-center gap-1 text-xs text-blue-400"
                    >
                      Asset <ArrowRight className="h-3 w-3" />
                    </Link>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
export default function ChangesPage() {
  return (
    <AuthProvider>
      <ChangesContent />
    </AuthProvider>
  );
}
