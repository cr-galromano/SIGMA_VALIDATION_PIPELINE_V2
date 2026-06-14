import { useEffect, useState } from 'react'
import type { CorpusStats } from '../types'

export function CorpusPage() {
  const [stats, setStats] = useState<CorpusStats | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/corpus')
      .then(r => r.json())
      .then(setStats)
      .catch(e => setError(e.message))
  }, [])

  if (error) return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-3 text-sm text-red-400">{error}</div>
    </div>
  )

  if (!stats) return (
    <div className="max-w-5xl mx-auto px-4 py-8 text-slate-400 text-sm">Loading corpus stats…</div>
  )

  const platforms = [...new Set(stats.bad_pool.map(e => e.platform))]

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Corpus</h1>
        <p className="text-slate-400 mt-1 text-sm">Version {stats.version} · created {stats.created}</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Techniques', value: stats.techniques_covered },
          { label: 'Bad-pool entries', value: stats.bad_pool.reduce((n, e) => n + e.verified_samples, 0) },
          { label: 'Good-pool signed off', value: stats.signed_off_good_pool },
          { label: 'Controls', value: stats.controls.length },
        ].map(c => (
          <div key={c.label} className="rounded-xl border border-slate-700 bg-slate-800/50 px-4 py-4 text-center">
            <p className="text-3xl font-bold text-slate-100">{c.value}</p>
            <p className="text-xs text-slate-400 mt-1">{c.label}</p>
          </div>
        ))}
      </div>

      {/* Bad pool by platform */}
      {platforms.map(platform => (
        <div key={platform} className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700">
            <h3 className="text-sm font-semibold text-slate-200">
              Bad Pool — <span className="capitalize">{platform}</span>
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 border-b border-slate-700/50">
                <th className="text-left px-4 py-2 font-medium">Technique</th>
                <th className="text-left px-4 py-2 font-medium">Name</th>
                <th className="text-left px-4 py-2 font-medium">Format</th>
                <th className="text-right px-4 py-2 font-medium">Samples</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/30">
              {stats.bad_pool.filter(e => e.platform === platform).map((entry, i) => (
                <tr key={i} className="hover:bg-slate-700/20 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs text-violet-400">{entry.technique}</td>
                  <td className="px-4 py-2.5 text-slate-300 text-xs">{entry.technique_name || '—'}</td>
                  <td className="px-4 py-2.5 text-slate-400 text-xs font-mono">{entry.format}</td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={entry.verified_samples > 0 ? 'text-emerald-400' : 'text-red-400'}>
                      {entry.verified_samples}
                    </span>
                    <span className="text-slate-600">/{entry.total_samples}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {/* Good pool */}
      <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-700">
          <h3 className="text-sm font-semibold text-slate-200">Good Pool</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-slate-500 border-b border-slate-700/50">
              <th className="text-left px-4 py-2 font-medium">Platform</th>
              <th className="text-left px-4 py-2 font-medium">Source</th>
              <th className="text-left px-4 py-2 font-medium">Format</th>
              <th className="text-right px-4 py-2 font-medium">Events</th>
              <th className="text-right px-4 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {stats.good_pool.map((entry, i) => (
              <tr key={i} className="hover:bg-slate-700/20 transition-colors">
                <td className="px-4 py-2.5 text-slate-300 text-xs capitalize">{entry.platform}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400 truncate max-w-xs">{entry.source_dir}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{entry.format}</td>
                <td className="px-4 py-2.5 text-right text-slate-300">{entry.events}</td>
                <td className="px-4 py-2.5 text-right">
                  {entry.signed_off
                    ? <span className="text-emerald-400 text-xs">✓ signed off</span>
                    : <span className="text-yellow-400 text-xs">⚠ unsigned</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
