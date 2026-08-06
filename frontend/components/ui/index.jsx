"use client";

import { X, AlertTriangle } from "lucide-react";

// ─── Severity Badge ───────────────────────────────────────────────────────────
export function SeverityBadge({ severity }) {
  const normalized =
    typeof severity === "string" && severity
      ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()
      : String(severity);

  const map = {
    Critical: "badge-critical",
    High: "badge-high",
    Medium: "badge-medium",
    Low: "badge-low",
    Info: "badge-info",
  };
  return <span className={map[normalized] || "badge-info"}>{normalized}</span>;
}

// ─── Status Badge ─────────────────────────────────────────────────────────────
export function StatusBadge({ status }) {
  const map = {
    active: "badge-low",
    running:
      "bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded text-xs font-medium",
    completed:
      "bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 rounded text-xs font-medium",
    failed: "badge-critical",
    pending: "badge-medium",
    cancelled: "badge-info",
    archived: "badge-info",
    open: "badge-critical",
    resolved:
      "bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 rounded text-xs font-medium",
  };
  return (
    <span className={map[status] || "badge-info"}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

// ─── Spinner ─────────────────────────────────────────────────────────────────
export function Spinner({ size = "md" }) {
  const s = { sm: "w-4 h-4", md: "w-6 h-6", lg: "w-8 h-8" }[size];
  return (
    <div
      className={`${s} border-2 border-blue-500 border-t-transparent rounded-full animate-spin`}
    />
  );
}

// ─── Loading State ────────────────────────────────────────────────────────────
export function LoadingState({ text = "Loading..." }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-3">
      <Spinner size="lg" />
      <span className="text-sm text-gray-500">{text}</span>
    </div>
  );
}

// ─── Empty State ─────────────────────────────────────────────────────────────
export function EmptyState({ title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-3 text-center">
      <div className="w-12 h-12 rounded-xl bg-[#21262d] border border-[#30363d] flex items-center justify-center">
        <AlertTriangle className="w-5 h-5 text-gray-500" />
      </div>
      <div>
        <p className="text-sm font-medium text-gray-300">{title}</p>
        {description && (
          <p className="text-xs text-gray-500 mt-1">{description}</p>
        )}
      </div>
      {action}
    </div>
  );
}

// ─── Error State ─────────────────────────────────────────────────────────────
export function ErrorState({ message }) {
  return (
    <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 flex items-start gap-3">
      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
      <p className="text-sm text-red-400">{message}</p>
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────
export function StatCard({ label, value, icon: Icon, color = "blue", sub }) {
  const colors = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    red: "text-red-400 bg-red-500/10 border-red-500/20",
    yellow: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    green: "text-green-400 bg-green-500/10 border-green-500/20",
    purple: "text-purple-400 bg-purple-500/10 border-purple-500/20",
  }[color];

  return (
    <div className="stat-card">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500 font-medium uppercase tracking-wider">
          {label}
        </span>
        {Icon && (
          <div className={`p-1.5 rounded-lg border ${colors}`}>
            <Icon className="w-3.5 h-3.5" />
          </div>
        )}
      </div>
      <div className="text-2xl font-bold text-gray-100">{value}</div>
      {sub && <div className="text-xs text-gray-500">{sub}</div>}
    </div>
  );
}

// ─── Modal ────────────────────────────────────────────────────────────────────
export function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative card w-full max-w-lg p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-sm font-semibold text-gray-100">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 text-gray-500 hover:text-gray-300 rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ─── Confirm Dialog ───────────────────────────────────────────────────────────
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  message,
  danger = false,
}) {
  return (
    <Modal open={open} onClose={onClose} title={title}>
      <p className="text-sm text-gray-400 mb-6">{message}</p>
      <div className="flex gap-3 justify-end">
        <button className="btn-secondary text-sm" onClick={onClose}>
          Cancel
        </button>
        <button
          className={danger ? "btn-danger text-sm" : "btn-primary text-sm"}
          onClick={() => {
            onConfirm();
            onClose();
          }}
        >
          Confirm
        </button>
      </div>
    </Modal>
  );
}

// ─── Table ────────────────────────────────────────────────────────────────────
export function Table({ headers, children, empty }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#21262d]">
            {headers.map((h) => (
              <th
                key={h}
                className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
      {empty && (
        <EmptyState
          title="No data found"
          description="Try adjusting your filters"
        />
      )}
    </div>
  );
}

// ─── Pagination ───────────────────────────────────────────────────────────────
export function Pagination({ page, total, limit, onChange }) {
  const totalPages = Math.ceil(total / limit);
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-[#21262d]">
      <span className="text-xs text-gray-500">
        Showing {page * limit + 1}–{Math.min((page + 1) * limit, total)} of{" "}
        {total}
      </span>
      <div className="flex gap-1">
        <button
          className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
          disabled={page === 0}
          onClick={() => onChange(page - 1)}
        >
          Previous
        </button>
        <button
          className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
          disabled={page >= totalPages - 1}
          onClick={() => onChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
