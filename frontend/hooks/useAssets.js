import { useState, useEffect, useCallback } from "react";
import api from "@/lib/api";

export function useAssets(page = 0, limit = 10) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getAssets({ skip: page * limit, limit });
      setData(res);
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to fetch assets");
    } finally {
      setLoading(false);
    }
  }, [page, limit]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { data, loading, error, refetch: fetch };
}

export function useAsset(id) {
  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) return;
    api
      .getAsset(id)
      .then(setAsset)
      .catch((e) =>
        setError(e.response?.data?.detail || "Failed to fetch asset"),
      )
      .finally(() => setLoading(false));
  }, [id]);

  return { asset, loading, error };
}
