import type { LintIssue } from '../types'

const severityStyle: Record<string, string> = {
  error:   'text-red-400 bg-red-500/10 border-red-500/20',
  warning: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  info:    'text-blue-400 bg-blue-500/10 border-blue-500/20',
}
const severityIcon: Record<string, string> = { error: '●', warning: '◆', info: '○' }

export function LintPanel({ issues }: { issues: LintIssue[] }) {
  if (!issues.length) return null
  const errors = issues.filter(i => i.severity === 'error').length
  const warnings = issues.filter(i => i.severity === 'warning').length

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Lint</h3>
        <div className="flex gap-3 text-xs">
          {errors > 0 && <span className="text-red-400">{errors} error{errors !== 1 ? 's' : ''}</span>}
          {warnings > 0 && <span className="text-yellow-400">{warnings} warning{warnings !== 1 ? 's' : ''}</span>}
        </div>
      </div>
      <ul className="divide-y divide-slate-700/50">
        {issues.map((issue, i) => (
          <li key={i} className={`flex gap-3 px-4 py-2.5 text-sm border-l-2
            ${severityStyle[issue.severity]}`}>
            <span className="shrink-0 mt-0.5">{severityIcon[issue.severity]}</span>
            <div className="min-w-0">
              <span className="font-mono text-xs opacity-60 mr-2">{issue.code}</span>
              {issue.message}
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
