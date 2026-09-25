import type { ScoreBreakdown as ScoreBreakdownType } from '../types/analysis'

interface ScoreBreakdownProps {
  breakdown: ScoreBreakdownType['breakdown']
}

const categoryLabels: Record<string, string> = {
  permissions: 'Permissions',
  code_api: 'Code / API',
  components: 'Components',
  indicators: 'Indicators',
}

const categoryColors: Record<string, string> = {
  permissions: '#3b82f6',
  code_api: '#f97316',
  components: '#eab308',
  indicators: '#8b5cf6',
}

export default function ScoreBreakdown({ breakdown }: ScoreBreakdownProps) {
  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
        Score Breakdown
      </h3>
      {Object.entries(breakdown).map(([key, cat]) => {
        const color = categoryColors[key] || '#6b7280'
        const pct = cat.normalized
        return (
          <div key={key}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-sentinel-text">
                {categoryLabels[key] || key}
              </span>
              <span className="text-xs font-mono text-sentinel-muted">
                {cat.weighted.toFixed(1)} pts
                <span className="text-sentinel-border mx-1">·</span>
                {(cat.weight * 100).toFixed(0)}% weight
              </span>
            </div>
            <div className="h-1.5 bg-sentinel-border rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${Math.min(pct, 100)}%`,
                  backgroundColor: color,
                }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
