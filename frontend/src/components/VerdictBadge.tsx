// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – VerdictBadge component
// ──────────────────────────────────────────────────────────────────────────────
import type { VerdictType } from '../types'

interface VerdictBadgeProps {
  verdict: VerdictType | null | undefined
  size?: 'sm' | 'md' | 'lg'
}

const VERDICT_STYLES: Record<VerdictType, string> = {
  LEGITIMATE: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  SUSPICIOUS: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  MALICIOUS:  'bg-red-100  text-red-800  dark:bg-red-900  dark:text-red-200',
}

const SIZE_STYLES = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
}

export default function VerdictBadge({
  verdict,
  size = 'md',
}: VerdictBadgeProps) {
  const label = verdict ?? 'UNKNOWN'
  const colourClass =
    verdict ? VERDICT_STYLES[verdict] : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'

  return (
    <span
      className={`inline-flex items-center rounded-full font-semibold ${colourClass} ${SIZE_STYLES[size]}`}
    >
      {label}
    </span>
  )
}
