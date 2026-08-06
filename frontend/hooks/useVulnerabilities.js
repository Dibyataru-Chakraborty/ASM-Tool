import { useState, useEffect, useCallback } from "react";
import api from "@/lib/api";

export function useVulnerabilities(severity) {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getVulnerabilities(severity);
      setVulnerabilities(res.vulnerabilities);
      setTotal(res.total);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to fetch vulnerabilities");
    } finally {
      setLoading(false);
    }
  }, [severity]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { vulnerabilities, total, loading, error, refetch: fetch };
}

export function useAlerts(asset_id) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      const res = await api.getAlerts(asset_id);
      setAlerts(res.alerts);
    } catch {
    } finally {
      setLoading(false);
    }
  }, [asset_id]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  const resolve = async (id) => {
    await api.resolveAlert(id);
    fetch();
  };

  return { alerts, loading, resolve, refetch: fetch };
}
