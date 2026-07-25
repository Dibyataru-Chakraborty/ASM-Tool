import { useState, useEffect, useCallback } from 'react'
import api from '@/lib/api'
import type { Vulnerability } from '@/types'

export function useVulnerabilities(severity?: string) {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetch = useCallback(async () => {
    try {
      setLoading(true)
      const res = await api.getVulnerabilities(severity)
      setVulnerabilities(res.vulnerabilities)
      setTotal(res.total)
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to fetch vulnerabilities')
    } finally {
      setLoading(false)
    }
  }, [severity])

  useEffect(() => { fetch() }, [fetch])

  return { vulnerabilities, total, loading, error, refetch: fetch }
}

export function useAlerts(asset_id?: string) {
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  const fetch = useCallback(async () => {
    try {
      const res = await api.getAlerts(asset_id)
      setAlerts(res.alerts)
    } catch {}
    finally { setLoading(false) }
  }, [asset_id])

  useEffect(() => { fetch() }, [fetch])

  const resolve = async (id: string) => {
    await api.resolveAlert(id)
    fetch()
  }

  return { alerts, loading, resolve, refetch: fetch }
}
