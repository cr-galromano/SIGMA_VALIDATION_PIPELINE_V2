import { useEffect, useState } from 'react'
import type { HistoryItem } from '../types'
import { VerdictBadge } from '../components/VerdictBadge'

export function HistoryPage() {
  const [items, setItems] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/history')
      .then(r => r.json())
      .then(d => setItems(d.results))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">History</h1>
        <p className="text-slate-400 mt-1 text-sm">Recent validation runs this session.</p>
      </div>

      {loading && <p className="text-slate-400 text-sm">Loading…</p>}

      {!loading && items.length === 0 && (
        <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-6 py-12 text-center">
          <p className="text-slate-500">No validations yet — run a rule from the Validate tab.</p>
        </div>
      )}

      {items.length > 0 && (
        <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 border-b border-slate-700">
                <th className="text-left px-4 py-2.5 font-medium">Rule</th>
                <th className="text-left px-4 py-2.5 font-medium hidden md:table-cell">ID</th>
                <th className="text-right px-4 py-2.5 font-medium">Verdict</th>
                <th className="text-right px-4 py-2.5 font-medium hidden md:table-cell">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/30">
              {items.map((item, i) => (
                <tr key={i} className="hover:bg-slate-700/20 transition-colors">
                  <td className="px-4 py-3 text-slate-200">{item.rule_title || 'Untitled'}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 hidden md:table-cell">
                    {item.rule_id.slice(0, 8)}…
                  </td>
                  <td className="px-4 py-3 text-right">
                    <VerdictBadge verdict={item.verdict} />
                  </td>
                  <td className="px-4 py-3 text-right text-xs text-slate-500 hidden md:table-cell">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
