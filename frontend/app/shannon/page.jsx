"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function ShannonRedirect() {
  const router = useRouter();
  useEffect(() => { router.replace("/pentest"); }, [router]);
  return <div className="flex items-center justify-center min-h-screen bg-[#0d1117] text-gray-400 text-sm">Redirecting...</div>;
}
