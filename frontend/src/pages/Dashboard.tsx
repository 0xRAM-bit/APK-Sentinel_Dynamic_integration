import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'
import { StatusBadge, RiskBadge } from '../components/StatusBadge'
import type { AnalysisSummary } from '../types/analysis'

export default function Dashboard() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/analyses?limit=10')
      .then(res => {
        setAnalyses(res.data.items)
        setTotal(res.data.total)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const completed = analyses.filter(a => a.status === 'COMPLETED')
  const avgScore = completed.length
    ? completed.reduce((sum, a) => sum + (a.risk_score || 0), 0) / completed.length
    : 0

  const riskCounts = { LOW: 0, MODERATE: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
  completed.forEach(a => {
    if (a.risk_level && a.risk_level in riskCounts) {
      riskCounts[a.risk_level as keyof typeof riskCounts]++
    }
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-sm text-sentinel-muted">Loading…</div>
      </div>
    )
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-sentinel-text mb-5">Dashboard</h1>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Analyses" value={total} />
        <StatCard label="Completed" value={completed.length} />
        <StatCard label="Avg. Risk Score" value={avgScore.toFixed(1)} />
        <StatCard
          label="High/Critical"
          value={riskCounts.HIGH + riskCounts.CRITICAL}
          highlight={riskCounts.HIGH + riskCounts.CRITICAL > 0}
        />
      </div>

      {/* Risk Distribution */}
      {completed.length > 0 && (
        <div className="bg-sentinel-surface border border-sentinel-border rounded p-4 mb-6">
          <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
            Risk Distribution
          </h2>
          <div className="flex gap-3">
            {Object.entries(riskCounts).map(([level, count]) => (
              <div
                key={level}
                className={`flex-1 text-center py-2 rounded border text-xs font-medium risk-bg-${level.toLowerCase()} risk-${level.toLowerCase()}`}
              >
                <div className="text-lg font-bold font-mono">{count}</div>
                <div className="text-[10px] opacity-70">{level}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Analyses */}
      <div className="bg-sentinel-surface border border-sentinel-border rounded">
        <div className="px-4 py-3 border-b border-sentinel-border flex items-center justify-between">
          <h2 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
            Recent Analyses
          </h2>
          <Link
            to="/history"
            className="text-xs text-sentinel-accent hover:underline"
          >
            View all →
          </Link>
        </div>

        {analyses.length === 0 ? (
          <div className="px-4 py-8 text-center">
            <p className="text-sm text-sentinel-muted mb-2">No analyses yet</p>
            <Link
              to="/upload"
              className="text-sm text-sentinel-accent hover:underline"
            >
              Upload your first APK →
            </Link>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-sentinel-muted text-left">
                <th className="px-4 py-2 font-medium">Filename</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {analyses.map(a => (
                <tr
                  key={a.id}
                  className="border-t border-sentinel-border hover:bg-sentinel-hover transition-colors"
                >
                  <td className="px-4 py-2">
                    <Link
                      to={
                        a.status === 'COMPLETED' || a.status === 'FAILED'
                          ? `/analysis/${a.id}`
                          : `/analysis/${a.id}/progress`
                      }
                      className="text-sentinel-text hover:text-sentinel-accent transition-colors"
                    >
                      {a.original_filename}
                    </Link>
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-4 py-2">
                    <RiskBadge level={a.risk_level} score={a.risk_score} />
                  </td>
                  <td className="px-4 py-2 text-sentinel-muted">
                    {new Date(a.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  highlight = false,
}: {
  label: string
  value: string | number
  highlight?: boolean
}) {
  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded p-4">
      <div className="text-[10px] text-sentinel-muted uppercase tracking-wider mb-1">
        {label}
      </div>
      <div
        className={`text-xl font-bold font-mono ${
          highlight ? 'text-risk-high' : 'text-sentinel-text'
        }`}
      >
        {value}
      </div>
    </div>
  )
}
