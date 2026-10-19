// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – RiskScore component
// ──────────────────────────────────────────────────────────────────────────────
import type { VerdictType } from '../types'

interface RiskScoreProps {
  score: number
  verdict?: VerdictType | null
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
}

function getColour(score: number): { bar: string; text: string; ring: string } {
  if (score <= 40) return { bar: 'bg-green-500', text: 'text-green-600 dark:text-green-400', ring: 'stroke-green-500' }
  if (score <= 70) return { bar: 'bg-amber-500',  text: 'text-amber-600 dark:text-amber-400',  ring: 'stroke-amber-500' }
  return              { bar: 'bg-red-500',   text: 'text-red-600  dark:text-red-400',   ring: 'stroke-red-500' }
}

const SIZE_MAP = {
  sm: { radius: 20, stroke: 4, viewBox: 52, fontSize: 'text-xs', wrapperSize: 'w-12 h-12' },
  md: { radius: 30, stroke: 5, viewBox: 72, fontSize: 'text-sm', wrapperSize: 'w-18 h-18' },
  lg: { radius: 42, stroke: 6, viewBox: 96, fontSize: 'text-base', wrapperSize: 'w-24 h-24' },
}

export default function RiskScore({
  score,
  verdict,
  size = 'md',
  showLabel = true,
}: RiskScoreProps) {
  const { bar: _bar, text, ring } = getColour(score)
  const { radius, stroke, viewBox, fontSize, wrapperSize } = SIZE_MAP[size]
  const normalised = Math.max(0, Math.min(100, score))
  const circumference = 2 * Math.PI * radius
  const dashOffset = circumference - (normalised / 100) * circumference
  const centre = viewBox / 2

  const label = verdict ?? (score <= 40 ? 'Legitimate' : score <= 70 ? 'Suspicious' : 'Malicious')

  return (
    <div className="flex flex-col items-center gap-1">
      {/* Circular progress */}
      <div className={`relative ${wrapperSize}`}>
        <svg
          className="w-full h-full -rotate-90"
          viewBox={`0 0 ${viewBox} ${viewBox}`}
        >
          {/* Track */}
          <circle
            cx={centre}
            cy={centre}
            r={radius}
            fill="none"
            strokeWidth={stroke}
            className="stroke-gray-200 dark:stroke-gray-700"
          />
          {/* Progress arc */}
          <circle
            cx={centre}
            cy={centre}
            r={radius}
            fill="none"
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            className={`${ring} transition-all duration-700`}
          />
        </svg>
        {/* Numeric label in the centre */}
        <div className={`absolute inset-0 flex items-center justify-center font-bold ${fontSize} ${text}`}>
          {normalised}
        </div>
      </div>

      {/* Verdict label */}
      {showLabel && (
        <span className={`${fontSize} font-medium ${text}`}>{label}</span>
      )}
    </div>
  )
}
