import { useState, useEffect, useCallback } from 'react'
import api from '@/lib/api'
import type { Asset, PaginatedResponse } from '@/types'

export function useAssets(page = 0, limit = 10) {
  const [data, setData] = useState<PaginatedResponse<Asset> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetch = useCallback(async () => {
    try {
      setLoading(true)
      const res = await api.getAssets({ skip: page * limit, limit })
      setData(res)
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to fetch assets')
    } finally {
      setLoading(false)
    }
  }, [page, limit])

  useEffect(() => { fetch() }, [fetch])

  return { data, loading, error, refetch: fetch }
}

export function useAsset(id: string) {
  const [asset, setAsset] = useState<Asset | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.getAsset(id)
      .then(setAsset)
      .catch((e) => setError(e.response?.data?.detail || 'Failed to fetch asset'))
      .finally(() => setLoading(false))
  }, [id])

  return { asset, loading, error }
}
