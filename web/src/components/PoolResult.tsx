import type { BadPoolResult, GoodPoolResult } from '../types'

function ResultLabel({ result }: { result: string }) {
  const s = result === 'PASS'
    ? 'text-emerald-400' : result === 'FAIL'
    ? 'text-red-400' : 'text-yellow-400'
  return <span className={`font-mono font-semibold text-sm ${s}`}>{result}</span>
}

export function BadPoolPanel({ data }: { data: BadPoolResult }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Bad Pool</h3>
        <ResultLabel result={data.result} />
      </div>
      <div className="px-4 py-3 space-y-3">
        <div className="flex gap-6 text-sm text-slate-400">
          <span><span className="text-slate-200 font-medium">{data.samples_tested}</span> samples tested</span>
          <span><span className="text-slate-200 font-medium">{data.total_detections}</span> total detections</span>
        </div>

        {data.reason && (
          <p className="text-sm text-red-400 bg-red-500/10 rounded-lg px-3 py-2">{data.reason}</p>
        )}

        {data.inferred_techniques && data.inferred_techniques.length > 0 && (
          <div className="text-sm text-yellow-400 bg-yellow-500/10 rounded-lg px-3 py-2">
            <span className="font-semibold">Inferred techniques: </span>
            {data.inferred_techniques.join(', ')}
            <span className="text-yellow-400/70 ml-1">— add as rule tags and re-run</span>
          </div>
        )}

        {data.hits.length > 0 && (
          <ul className="space-y-1">
            {data.hits.map((h, i) => (
              <li key={i} className="flex justify-between text-xs font-mono bg-slate-900/60 rounded px-3 py-1.5">
                <span className="text-slate-400 truncate">{h.file}</span>
                <span className="text-emerald-400 ml-4 shrink-0">{h.detections} hit{h.detections !== 1 ? 's' : ''}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

export function GoodPoolPanel({ data }: { data: GoodPoolResult }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Good Pool</h3>
        <ResultLabel result={data.result} />
      </div>
      <div className="px-4 py-3 space-y-3">
        <div className="flex gap-6 text-sm text-slate-400">
          <span><span className="text-slate-200 font-medium">{data.files_tested}</span> files tested</span>
          <span><span className="text-slate-200 font-medium">{data.total_hits}</span> false positives</span>
        </div>

        {data.reason && (
          <p className="text-sm text-yellow-400 bg-yellow-500/10 rounded-lg px-3 py-2">{data.reason}</p>
        )}

        {data.offenders.length > 0 && (
          <ul className="space-y-1">
            {data.offenders.map((o, i) => (
              <li key={i} className="flex justify-between text-xs font-mono bg-slate-900/60 rounded px-3 py-1.5">
                <span className="text-slate-400 truncate">{o.file}</span>
                <span className="text-red-400 ml-4 shrink-0">{o.detections} hit{o.detections !== 1 ? 's' : ''}</span>
              </li>
            ))}
          </ul>
        )}

        {data.result === 'PASS' && data.files_tested > 0 && (
          <p className="text-sm text-emerald-400/80">Silent on all {data.files_tested} baseline file{data.files_tested !== 1 ? 's' : ''}</p>
        )}
      </div>
    </div>
  )
}
