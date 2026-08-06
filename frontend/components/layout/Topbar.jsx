"use client";
import { usePathname } from "next/navigation";
import {
  Bot,
  Bug,
  CalendarClock,
  FileText,
  Globe2,
  History,
  LayoutDashboard,
  Moon,
  Server,
  Settings,
  Shield,
  Sun,
} from "lucide-react";
import { useTheme } from "@/lib/theme";
import { useAuth } from "@/lib/auth";

const TITLES = {
  "/super-admin": { label: "Super Admin Console", icon: Shield },
  "/organization/users": { label: "Organization Users", icon: Server },
  "/dashboard": { label: "Dashboard", icon: LayoutDashboard },
  "/assets": { label: "Assets", icon: Server },
  "/scheduler": { label: "Scan Scheduler", icon: CalendarClock },
  "/scans": { label: "Scan History", icon: History },
  "/recon": { label: "Recon Engine", icon: Globe2 },
  "/shannon": { label: "AI Pentest (Shannon)", icon: Bot },
  "/vulnerabilities": { label: "Vulnerabilities", icon: Bug },
  "/reports": { label: "Reports", icon: FileText },
  "/settings": { label: "Settings", icon: Settings },
};

export default function Topbar() {
  const path = usePathname();
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();
  const isSuper = user?.platform_role === "super_admin";
  const inTenant = !!user?.organization_id;

  let title = Object.entries(TITLES).find(
    ([k]) => path === k || path.startsWith(k + "/"),
  )?.[1] || { label: "Digi Samurai ASM Platform", icon: Shield };

  if (path === "/dashboard" && isSuper && !inTenant) {
    title = { label: "Super Admin Console", icon: Shield };
  }

  const Icon = title.icon;

  return (
    <header className="h-12 border-b border-[#21262d] bg-[#010409] flex items-center px-5 gap-3">
      <h1 className="flex flex-1 items-center gap-2 text-sm font-semibold text-gray-300">
        <Icon className="h-4 w-4 text-blue-400" aria-hidden="true" />
        <span>{title.label}</span>
      </h1>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={toggleTheme}
          className="theme-toggle"
          aria-label={
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
          }
          title={
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
          }
        >
          {theme === "dark" ? (
            <Sun className="h-4 w-4" aria-hidden="true" />
          ) : (
            <Moon className="h-4 w-4" aria-hidden="true" />
          )}
        </button>
      </div>
    </header>
  );
}
