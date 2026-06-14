import { useState } from 'react'
import { ValidatePage } from './pages/ValidatePage'
import { CorpusPage } from './pages/CorpusPage'
import { HistoryPage } from './pages/HistoryPage'

type Tab = 'validate' | 'corpus' | 'history'

const tabs: { id: Tab; label: string }[] = [
  { id: 'validate', label: 'Validate' },
  { id: 'corpus',   label: 'Corpus' },
  { id: 'history',  label: 'History' },
]

export default function App() {
  const [tab, setTab] = useState<Tab>('validate')

  return (
    <div className="min-h-screen bg-[#0f1117]">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between gap-6">
          <div className="flex items-center gap-2.5">
            <span className="text-violet-400 text-lg">◈</span>
            <span className="font-bold text-slate-100 tracking-tight">SVP</span>
            <span className="text-slate-600 text-sm hidden sm:block">SIGMA Validation Pipeline</span>
          </div>
          <nav className="flex gap-1">
            {tabs.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors
                  ${tab === t.id
                    ? 'bg-slate-700 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'}`}>
                {t.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main>
        {tab === 'validate' && <ValidatePage />}
        {tab === 'corpus'   && <CorpusPage />}
        {tab === 'history'  && <HistoryPage />}
      </main>
    </div>
  )
}
