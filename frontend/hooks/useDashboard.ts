import { useState, useEffect } from 'react'
import api from '@/lib/api'
import type { DashboardFull, RiskSummary } from '@/types'

export function useDashboard() {
  const [data, setData] = useState<DashboardFull | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.getDashboard()
      .then(setData)
      .catch((e) => setError(e.response?.data?.detail || 'Failed to fetch dashboard'))
      .finally(() => setLoading(false))
  }, [])

  return { data, loading, error }
}

export function useRiskSummary() {
  const [data, setData] = useState<RiskSummary | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getRiskSummary()
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return { data, loading }
}

export function useTimeline(days = 30) {
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getTimeline(days)
      .then((res) => setTimeline(res.timeline || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [days])

  return { timeline, loading }
}
