export type Severity = 'error' | 'warning' | 'info'
export type Verdict = 'PASS' | 'FAIL' | 'VOID'

export interface LintIssue {
  severity: Severity
  code: string
  message: string
}

export interface PoolHit {
  file: string
  detections: number
}

export interface ControlCheck {
  anchor: string | null
  expected: number | null
  actual: number | null
  result: 'PASS' | 'VOID' | 'SKIP'
  error: string | null
  note?: string
}

export interface BadPoolResult {
  result: 'PASS' | 'FAIL'
  reason?: string
  samples_tested: number
  total_detections: number
  hits: PoolHit[]
  inferred_techniques?: string[]
}

export interface GoodPoolResult {
  result: 'PASS' | 'FAIL' | 'VOID'
  reason?: string
  files_tested: number
  total_hits: number
  offenders: PoolHit[]
}

export interface ControlsResult {
  result: 'PASS' | 'VOID'
  checks: ControlCheck[]
}

export interface ValidationResult {
  rule_id: string
  rule_title: string
  rule_file: string
  corpus_version: string
  verdict: Verdict
  reason: string | null
  lint: LintIssue[]
  bad_pool: BadPoolResult
  good_pool: GoodPoolResult
  positive_controls: ControlsResult
  warnings: string[]
  timestamp: string
}

export interface HistoryItem {
  rule_id: string
  rule_title: string
  verdict: Verdict
  timestamp: string
}

export interface CorpusTechniqueEntry {
  platform: string
  technique: string
  technique_name: string
  format: string
  total_samples: number
  verified_samples: number
}

export interface CorpusGoodPoolEntry {
  platform: string
  source_dir: string
  system_type: string
  format: string
  events: number
  signed_off: boolean
}

export interface CorpusStats {
  version: string
  created: string
  bad_pool: CorpusTechniqueEntry[]
  good_pool: CorpusGoodPoolEntry[]
  controls: object[]
  techniques_covered: number
  signed_off_good_pool: number
}
