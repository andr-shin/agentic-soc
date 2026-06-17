import { useState } from 'react'
import { Terminal, Play, Sparkles, Loader2, AlertCircle, Database, Save, Bookmark, Trash2 } from 'lucide-react'
import clsx from 'clsx'
import {
  useLogSources, useRunLogQuery, useGenerateLogQuery,
  useSavedLogQueries, useSaveLogQuery, useDeleteLogQuery,
  type LogQueryResult,
} from '../hooks/useApi'

const TIME_RANGES = [
  { label: '15분', minutes: 15 },
  { label: '1시간', minutes: 60 },
  { label: '6시간', minutes: 360 },
  { label: '24시간', minutes: 1440 },
  { label: '3일', minutes: 4320 },
]

export default function LogExplorer() {
  const { data: sourcesData } = useLogSources()
  const runQuery = useRunLogQuery()
  const generateQuery = useGenerateLogQuery()
  const { data: savedQueries } = useSavedLogQueries()
  const saveQuery = useSaveLogQuery()
  const deleteQuery = useDeleteLogQuery()

  const sources = sourcesData?.sources || []
  const [source, setSource] = useState('')
  const [minutes, setMinutes] = useState(60)
  const [query, setQuery] = useState('')
  const [nl, setNl] = useState('')
  const [result, setResult] = useState<LogQueryResult | null>(null)

  // 검색 가능한 소스를 기본 선택(없으면 첫 번째)
  if (!source && sources.length > 0) {
    setSource((sources.find((s) => s.is_searchable) || sources[0]).source)
  }

  const activeSource = sources.find((s) => s.source === source)
  const activeSchema = activeSource?.schema || ''
  const activeSearchable = activeSource?.is_searchable !== false

  const handleSave = () => {
    if (!query.trim() || !source) return
    const name = window.prompt('저장할 쿼리 이름을 입력하세요', `${source} 쿼리`)
    if (name === null) return
    saveQuery.mutate({ name: name || `${source} 쿼리`, source, query, minutes })
  }

  const loadSaved = (q: { source: string; query: string; minutes: number }) => {
    setSource(q.source)
    setQuery(q.query)
    setMinutes(q.minutes || 60)
  }

  const handleGenerate = () => {
    if (!nl.trim() || !source) return
    generateQuery.mutate(
      { source, natural_language: nl },
      { onSuccess: (data) => { if (data.query) setQuery(data.query) } }
    )
  }

  const handleRun = () => {
    if (!query.trim() || !source) return
    runQuery.mutate(
      { source, query, minutes, limit: 100 },
      { onSuccess: (data) => setResult(data) }
    )
  }

  const columns = result?.rows?.length
    ? Array.from(result.rows.reduce((set, row) => {
        Object.keys(row).forEach((k) => { if (k !== '@ptr') set.add(k) })
        return set
      }, new Set<string>()))
    : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-primary-600" />
          Log Explorer
        </h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          CloudWatch Unified Data Store — LogsQL로 보안 로그를 조회합니다
        </p>
      </div>

      {/* Controls */}
      <div className="p-6 bg-white rounded-xl shadow-sm border border-gray-100 dark:border-gray-700/50 dark:bg-gray-800 space-y-4">
        {/* Source + time range */}
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">로그 소스</label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300"
            >
              {sources.map((s) => (
                <option key={s.source} value={s.source}>
                  {s.is_searchable ? '🟢' : '⚪'} {s.source}{s.is_searchable ? '' : ' (온보딩 대기)'}
                </option>
              ))}
            </select>
            {activeSource && (
              <p className={clsx('mt-1 text-xs flex items-center gap-1',
                activeSearchable ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400')}>
                <span className={clsx('w-1.5 h-1.5 rounded-full', activeSearchable ? 'bg-green-500' : 'bg-amber-500')} />
                {activeSource.status_detail || (activeSearchable ? '활성 — 검색 가능' : '온보딩 대기')}
              </p>
            )}
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">시간 범위</label>
            <select
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
              className="px-3 py-2 border rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300"
            >
              {TIME_RANGES.map((t) => (
                <option key={t.minutes} value={t.minutes}>{t.label}</option>
              ))}
            </select>
          </div>
        </div>

        {activeSchema && (
          <p className="text-xs text-gray-400 dark:text-gray-500">
            <span className="font-medium">필드:</span> {activeSchema}
          </p>
        )}

        {/* AI query generation */}
        <div className="flex gap-2">
          <input
            type="text"
            value={nl}
            onChange={(e) => setNl(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleGenerate() }}
            placeholder="자연어로 설명하면 LogsQL을 생성합니다 (예: REJECT된 트래픽을 포트별로 집계)"
            className="flex-1 px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-white dark:placeholder-gray-400"
          />
          <button
            onClick={handleGenerate}
            disabled={generateQuery.isPending || !nl.trim()}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-purple-700 bg-purple-100 rounded-lg hover:bg-purple-200 transition-colors disabled:opacity-50 dark:bg-purple-900/30 dark:text-purple-300"
          >
            {generateQuery.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            AI 쿼리 생성
          </button>
        </div>

        {/* LogsQL editor */}
        <div>
          <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">LogsQL</label>
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            rows={4}
            placeholder={'filter action="REJECT" | stats count(*) as n by dstPort | sort n desc'}
            className="w-full px-3 py-2 border rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:bg-gray-900 dark:border-gray-600 dark:text-gray-200"
          />
        </div>

        {!activeSearchable && (
          <p className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
            <AlertCircle className="w-3.5 h-3.5" />
            이 소스는 아직 온보딩되지 않아 결과가 비어 있을 수 있습니다.
          </p>
        )}

        <div className="flex justify-end gap-2">
          <button
            onClick={handleSave}
            disabled={saveQuery.isPending || !query.trim()}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          >
            {saveQuery.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            저장
          </button>
          <button
            onClick={handleRun}
            disabled={runQuery.isPending || !query.trim()}
            className="flex items-center gap-2 px-5 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-50"
          >
            {runQuery.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            실행
          </button>
        </div>
      </div>

      {/* 저장된 쿼리 */}
      {savedQueries && savedQueries.length > 0 && (
        <div className="p-4 bg-white rounded-xl shadow-sm border border-gray-100 dark:border-gray-700/50 dark:bg-gray-800">
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
            <Bookmark className="w-4 h-4" /> 저장된 쿼리 ({savedQueries.length})
          </h2>
          <div className="flex flex-wrap gap-2">
            {savedQueries.map((q) => (
              <div key={q.query_id}
                className="group flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-primary-300 dark:hover:border-primary-700 transition-colors">
                <button onClick={() => loadSaved(q)} className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300" title={q.query}>
                  <span className="font-medium">{q.name}</span>
                  <span className="text-xs text-gray-400 dark:text-gray-500">· {q.source}</span>
                </button>
                <button
                  onClick={() => { if (window.confirm(`'${q.name}' 쿼리를 삭제할까요?`)) deleteQuery.mutate(q.query_id) }}
                  className="text-gray-300 hover:text-red-500 dark:text-gray-600 dark:hover:text-red-400"
                  aria-label="쿼리 삭제"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Errors */}
      {generateQuery.data?.error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg text-sm text-red-700 dark:text-red-300">
          <AlertCircle className="w-4 h-4" /> AI 생성 실패: {generateQuery.data.error}
        </div>
      )}
      {(runQuery.error || result?.error) && (
        <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg text-sm text-red-700 dark:text-red-300">
          <AlertCircle className="w-4 h-4" /> {result?.error || String(runQuery.error)}
        </div>
      )}

      {/* Results */}
      {result && !result.error && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 dark:border-gray-700/50 dark:bg-gray-800 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b dark:border-gray-700">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {result.count}개 행
              {result.records_scanned != null && (
                <span className="text-gray-400 dark:text-gray-500"> · {result.records_scanned} records scanned</span>
              )}
            </span>
            <span className="text-xs text-gray-400 dark:text-gray-500 font-mono">{result.log_group}</span>
          </div>
          {result.rows.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                    {columns.map((c) => (
                      <th key={c} className="text-left px-4 py-2 text-xs font-medium text-gray-500 dark:text-gray-400 whitespace-nowrap">{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {result.rows.map((row, i) => (
                    <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      {columns.map((c) => (
                        <td key={c} className="px-4 py-2 text-gray-700 dark:text-gray-300 font-mono text-xs whitespace-nowrap">{row[c] ?? ''}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
              <Database className="w-12 h-12 mb-3" />
              <p>결과가 없습니다</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
