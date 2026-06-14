import { useState } from 'react'
import type { ValidationResult } from '../types'
import { VerdictBadge } from '../components/VerdictBadge'
import { LintPanel } from '../components/LintPanel'
import { BadPoolPanel, GoodPoolPanel } from '../components/PoolResult'

const PLACEHOLDER = `title: Example SIGMA Rule
id: 00000000-0000-0000-0000-000000000000
status: test
description: Detects suspicious activity
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key: 'susp_activity'
    condition: selection
tags:
    - attack.command-and-control
level: medium`

export function ValidatePage() {
  const [yaml, setYaml] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ValidationResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!yaml.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch('/api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_yaml: yaml }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${res.status}`)
      }
      setResult(await res.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Validate Rule</h1>
        <p className="text-slate-400 mt-1 text-sm">Paste a SIGMA rule YAML to run it against the corpus.</p>
      </div>

      {/* Editor */}
      <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700 bg-slate-800">
          <span className="text-xs text-slate-400 font-mono">rule.yml</span>
          <button
            onClick={() => setYaml(PLACEHOLDER)}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors">
            load example
          </button>
        </div>
        <textarea
          value={yaml}
          onChange={e => setYaml(e.target.value)}
          placeholder={PLACEHOLDER}
          spellCheck={false}
          className="w-full h-72 bg-transparent px-4 py-3 font-mono text-sm text-slate-200
                     placeholder:text-slate-600 resize-none outline-none leading-relaxed"
        />
      </div>

      <button
        onClick={handleSubmit}
        disabled={loading || !yaml.trim()}
        className="w-full py-2.5 rounded-lg font-semibold text-sm transition-all
                   bg-violet-600 hover:bg-violet-500 text-white
                   disabled:opacity-40 disabled:cursor-not-allowed">
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
            </svg>
            Validating…
          </span>
        ) : 'Validate'}
      </button>

      {error && (
        <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Verdict header */}
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-6 py-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="text-xs text-slate-500 font-mono mb-1">{result.rule_id}</p>
                <h2 className="text-lg font-semibold text-slate-100 truncate">{result.rule_title || 'Untitled Rule'}</h2>
                {result.reason && (
                  <p className="text-sm text-slate-400 mt-1">{result.reason}</p>
                )}
              </div>
              <VerdictBadge verdict={result.verdict} large />
            </div>
            {result.warnings.length > 0 && (
              <ul className="mt-4 space-y-1">
                {result.warnings.map((w, i) => (
                  <li key={i} className="text-xs text-yellow-400/80 flex gap-2">
                    <span>⚠</span><span>{w}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Lint */}
          {result.lint?.length > 0 && <LintPanel issues={result.lint} />}

          {/* Pools */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {result.bad_pool && <BadPoolPanel data={result.bad_pool} />}
            {result.good_pool && <GoodPoolPanel data={result.good_pool} />}
          </div>

          {/* Controls */}
          {result.positive_controls && (
            <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <h3 className="text-sm font-semibold text-slate-200">Positive Controls</h3>
                <span className={`text-sm font-mono font-semibold
                  ${result.positive_controls.result === 'PASS' ? 'text-emerald-400' : 'text-yellow-400'}`}>
                  {result.positive_controls.result}
                </span>
              </div>
              <ul className="divide-y divide-slate-700/50">
                {result.positive_controls.checks.map((c, i) => (
                  <li key={i} className="flex items-center justify-between px-4 py-2.5 text-xs">
                    <span className="text-slate-400 font-mono truncate">{c.anchor ?? c.note ?? '—'}</span>
                    <span className="ml-4 shrink-0 text-slate-400">
                      {c.expected != null && `${c.actual}/${c.expected}`}
                      {' '}
                      <span className={c.result === 'PASS' ? 'text-emerald-400' : 'text-yellow-400'}>
                        {c.result}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Timestamp */}
          <p className="text-xs text-slate-600 text-right font-mono">
            corpus: {result.corpus_version} · {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  )
}
