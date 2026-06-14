import type { Verdict } from '../types'

const styles: Record<Verdict, string> = {
  PASS: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  FAIL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  VOID: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
}

const icons: Record<Verdict, string> = { PASS: '✓', FAIL: '✗', VOID: '?' }

export function VerdictBadge({ verdict, large }: { verdict: Verdict; large?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-mono font-semibold
      ${large ? 'px-5 py-2 text-2xl' : 'px-3 py-0.5 text-sm'}
      ${styles[verdict]}`}>
      <span>{icons[verdict]}</span>
      {verdict}
    </span>
  )
}
