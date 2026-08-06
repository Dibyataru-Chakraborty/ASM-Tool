"use client";
import { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import api from "./api";
const AuthContext = createContext({
  user: null,
  loading: true,
  login: async () => {},
  logout: async () => {},
  isAuthenticated: false,
  selectOrganization: () => {},
  exitOrganization: () => {},
  refreshUser: async () => {},
});
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const refreshUser = async () => {
    const me = await api.getMe();
    setUser(me);
  };
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (token) {
      refreshUser()
        .catch(() => {
          localStorage.removeItem("access_token");
          localStorage.removeItem("active_organization_id");
        })
        .finally(() => setLoading(false));
    } else setLoading(false);
  }, []);
  const login = async (email, password) => {
    const result = await api.login({ email, password });
    if (result.platform_role !== "super_admin")
      localStorage.removeItem("active_organization_id");
    await refreshUser();
    router.push(
      result.platform_role === "super_admin" ? "/super-admin" : "/dashboard",
    );
  };
  const logout = async () => {
    try {
      await api.logout();
    } catch {}
    localStorage.removeItem("access_token");
    localStorage.removeItem("active_organization_id");
    setUser(null);
    router.push("/login");
  };
  const selectOrganization = (id) => {
    localStorage.setItem("active_organization_id", id);
    window.location.href = "/dashboard";
  };
  const exitOrganization = () => {
    localStorage.removeItem("active_organization_id");
    window.location.href = "/super-admin";
  };
  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        logout,
        isAuthenticated: !!user,
        selectOrganization,
        exitOrganization,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
export const useAuth = () => useContext(AuthContext);
