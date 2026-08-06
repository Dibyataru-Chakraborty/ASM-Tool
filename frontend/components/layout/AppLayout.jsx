"use client";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import { Loader2 } from "lucide-react";

export default function AppLayout({ children }) {
  const { isAuthenticated, loading, user } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [isOffline, setIsOffline] = useState(false);

  useEffect(() => {
    const handleOnline = () => setIsOffline(false);
    const handleOffline = () => setIsOffline(true);

    setIsOffline(!navigator.onLine);

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      router.push("/login");
      return;
    }

    if (!loading && isAuthenticated && user) {
      const isSuper = user.platform_role === "super_admin";
      const inTenant = !!user.organization_id;

      if (isSuper && !inTenant) {
        const allowedPaths = ["/dashboard", "/super-admin", "/super-admin/organizations"];
        const isAllowed = allowedPaths.some(
          (p) => pathname === p || pathname.startsWith(p + "/"),
        );
        if (!isAllowed) {
          router.replace("/dashboard");
        }
      }
    }
  }, [isAuthenticated, loading, user, pathname, router]);

  if (loading)
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2
            className="h-9 w-9 animate-spin text-blue-400"
            aria-label="Loading"
          />
          <p className="text-sm text-gray-500">Loading…</p>
        </div>
      </div>
    );

  if (!isAuthenticated) return null;

  return (
    <div className="min-h-screen bg-[#0d1117]">
      {isOffline && (
        <div className="bg-red-950/90 border-b border-red-800 text-red-200 px-4 py-2.5 text-xs flex items-center justify-center gap-2 transition duration-300 backdrop-blur-sm sticky top-0 z-50">
          <span className="material-icons text-sm animate-pulse">wifi_off</span>
          <span>You are currently offline. Running in offline cache mode. Some active scanning actions may be unavailable.</span>
        </div>
      )}
      <Sidebar />
      <div className="ml-52 flex flex-col min-h-screen">
        <Topbar />
        <main className="flex-1 p-5">{children}</main>
      </div>
    </div>
  );
}
