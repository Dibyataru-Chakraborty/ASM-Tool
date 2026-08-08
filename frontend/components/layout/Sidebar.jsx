"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import {
  Activity,
  Bug,
  CalendarClock,
  FileText,
  History,
  LayoutDashboard,
  LogOut,
  Network,
  Radar,
  Server,
  Settings,
  Share2,
  Shield,
  ShieldAlert,
  Users,
  Building2,
  ArrowLeftCircle,
  Zap,
} from "lucide-react";
const asmSections = [
  {
    label: "OVERVIEW",
    items: [
      { href: "/dashboard", icon: LayoutDashboard, label: "Attack Surface" },
    ],
  },
  {
    label: "ASSET INVENTORY",
    items: [
      { href: "/attack-surface", icon: Network, label: "Inventory" },
      { href: "/asset-map", icon: Share2, label: "Asset Map" },
      { href: "/changes", icon: Activity, label: "Changes" },
      { href: "/exposures", icon: ShieldAlert, label: "Exposures" },
    ],
  },
  {
    label: "MONITORING",
    adminOnly: true,
    items: [
      { href: "/assets", icon: Server, label: "Company Domains" },
      { href: "/recon", icon: Radar, label: "Discovery Engine" },
      {
        href: "/scheduler",
        icon: CalendarClock,
        label: "Continuous Monitoring",
      },
    ],
  },
  {
    label: "ASSESSMENT",
    items: [
      { href: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
      { href: "/scans", icon: History, label: "Discovery History" },
      { href: "/reports", icon: FileText, label: "Reports" },
      { href: "/pentest", icon: Zap, label: "AI Pentest" },
    ],
  },
];
export default function Sidebar() {
  const path = usePathname();
  const { user, logout, exitOrganization } = useAuth();
  const isSuper = user?.platform_role === "super_admin";
  const inTenant = !!user?.organization_id;
  const isAdmin = isSuper || user?.organization_role === "admin";
  const sections =
    isSuper && !inTenant
      ? [
          {
            label: "PLATFORM",
            items: [
              {
                href: "/dashboard",
                icon: LayoutDashboard,
                label: "Platform Overview",
              },
              {
                href: "/super-admin/organizations",
                icon: Building2,
                label: "Organizations",
              },
            ],
          },
        ]
      : asmSections.filter((s) => !s.adminOnly || isAdmin);
  return (
    <aside className="fixed left-0 top-0 z-50 flex h-screen w-52 flex-col border-r border-[#21262d] bg-[#010409]">
      <div className="border-b border-[#21262d] px-4 py-4">
        <div className="flex items-center gap-2">
          <span className="material-icons text-xl text-blue-400">shield</span>
          <div>
            <p className="text-sm font-bold text-gray-100">Digi Samurai ASM Platform</p>
            <p className="text-[10px] text-gray-600">Digi Samurai EASM</p>
          </div>
        </div>
        {inTenant && (
          <p className="mt-2 truncate text-[10px] text-cyan-400">
            {user?.organization_name}
          </p>
        )}
      </div>
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {sections.map((sec) => (
          <div key={sec.label} className="mb-4">
            <p className="mb-1.5 px-3 text-[9px] font-semibold tracking-[.16em] text-gray-600">
              {sec.label}
            </p>
            {sec.items.map((it) => {
              const Icon = it.icon;
              const active = path === it.href || path.startsWith(it.href + "/");
              return (
                <Link
                  key={it.href}
                  href={it.href}
                  className={active ? "nav-active" : "nav-item"}
                >
                  <Icon className="h-4 w-4 shrink-0 text-blue-400" />
                  <span>{it.label}</span>
                </Link>
              );
            })}
          </div>
        ))}
        {inTenant && isAdmin && (
          <Link
            href="/organization/users"
            className={
              path.startsWith("/organization/users") ? "nav-active" : "nav-item"
            }
          >
            <Users className="h-4 w-4 text-indigo-400" />
            <span>Users</span>
          </Link>
        )}
      </nav>
      <div className="border-t border-[#21262d] px-2 pb-3 pt-2">
        {isSuper && inTenant && (
          <button onClick={exitOrganization} className="nav-item w-full">
            <ArrowLeftCircle className="h-4 w-4" />
            <span>Platform Console</span>
          </button>
        )}
        {inTenant && isAdmin && (
          <Link href="/settings" className="nav-item">
            <Settings className="h-4 w-4" />
            <span>Settings</span>
          </Link>
        )}
        <div className="px-3 py-2">
          <p className="truncate text-xs text-gray-300">{user?.full_name}</p>
          <p className="text-[10px] text-gray-600">
            {isSuper ? "Super Admin" : user?.organization_role}
          </p>
        </div>
        <button onClick={logout} className="nav-item w-full text-red-400">
          <LogOut className="h-4 w-4" />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}
