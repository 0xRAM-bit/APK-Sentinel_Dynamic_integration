import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'
import { StatusBadge, RiskBadge } from '../components/StatusBadge'
import type { AnalysisSummary } from '../types/analysis'

export default function History() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const limit = 20

  useEffect(() => {
    setLoading(true)
    api.get(`/analyses?skip=${page * limit}&limit=${limit}`)
      .then(res => {
        setAnalyses(res.data.items)
        setTotal(res.data.total)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [page])

  const totalPages = Math.ceil(total / limit)

  return (
    <div>
      <h1 className="text-lg font-semibold text-sentinel-text mb-5">Analysis History</h1>

      <div className="bg-sentinel-surface border border-sentinel-border rounded">
        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-sentinel-muted">
            Loading…
          </div>
        ) : analyses.length === 0 ? (
          <div className="px-4 py-8 text-center">
            <p className="text-sm text-sentinel-muted mb-2">No analyses found</p>
            <Link
              to="/upload"
              className="text-sm text-sentinel-accent hover:underline"
            >
              Upload an APK →
            </Link>
          </div>
        ) : (
          <>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-sentinel-muted text-left border-b border-sentinel-border">
                  <th className="px-4 py-2.5 font-medium">Filename</th>
                  <th className="px-4 py-2.5 font-medium">SHA-256</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 font-medium">Risk</th>
                  <th className="px-4 py-2.5 font-medium">Size</th>
                  <th className="px-4 py-2.5 font-medium">Date</th>
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
                    <td className="px-4 py-2 font-mono text-sentinel-muted">
                      {a.sha256.substring(0, 12)}…
                    </td>
                    <td className="px-4 py-2">
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="px-4 py-2">
                      <RiskBadge level={a.risk_level} score={a.risk_score} />
                    </td>
                    <td className="px-4 py-2 text-sentinel-muted">
                      {(a.file_size / 1024 / 1024).toFixed(1)} MB
                    </td>
                    <td className="px-4 py-2 text-sentinel-muted">
                      {new Date(a.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-sentinel-border">
                <span className="text-xs text-sentinel-muted">
                  {total} total analyses
                </span>
                <div className="flex gap-1">
                  <button
                    onClick={() => setPage(p => Math.max(0, p - 1))}
                    disabled={page === 0}
                    className="px-2 py-1 text-xs text-sentinel-muted hover:text-sentinel-text disabled:opacity-30 transition-colors"
                  >
                    ← Prev
                  </button>
                  <span className="px-2 py-1 text-xs text-sentinel-muted">
                    {page + 1} / {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                    className="px-2 py-1 text-xs text-sentinel-muted hover:text-sentinel-text disabled:opacity-30 transition-colors"
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
