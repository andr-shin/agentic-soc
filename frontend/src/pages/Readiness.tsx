import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  RefreshCw,
  Radar,
  ScrollText,
  Bot,
  Activity,
} from 'lucide-react'
import clsx from 'clsx'
import { useReadiness, type ReadinessItem } from '../hooks/useApi'

const statusConfig: Record<string, { icon: typeof CheckCircle2; color: string; badge: string; label: string }> = {
  ok:      { icon: CheckCircle2,  color: 'text-green-500',  badge: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',   label: '정상' },
  warn:    { icon: AlertTriangle, color: 'text-yellow-500', badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300', label: '주의' },
  missing: { icon: XCircle,       color: 'text-red-500',    badge: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',           label: '미설정' },
  error:   { icon: HelpCircle,    color: 'text-gray-400',   badge: 'bg-gray-100 text-gray-700 dark:bg-gray-700/40 dark:text-gray-300',       label: '확인 불가' },
}

const categoryMeta: Record<string, { label: string; icon: typeof Radar }> = {
  detection:     { label: '탐지 서비스', icon: Radar },
  logs:          { label: '로그 소스', icon: ScrollText },
  agents:        { label: '에이전트 · 파이프라인', icon: Bot },
  observability: { label: 'Observability', icon: Activity },
}
const categoryOrder = ['detection', 'logs', 'agents', 'observability']

export default function Readiness() {
  const { data, isLoading, refetch, isRefetching } = useReadiness()
  const items: ReadinessItem[] = data?.items || []
  const summary = data?.summary

  const grouped = categoryOrder
    .map((cat) => ({ cat, items: items.filter((i) => i.category === cat) }))
    .filter((g) => g.items.length > 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-primary-600" />
            온보딩 Status
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Agentic SOC가 의존하는 AWS 보안 서비스·설정의 온보딩 현황을 점검합니다 (읽기 전용)
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isRefetching}
          aria-label="새로고침"
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', isRefetching && 'animate-spin')} />
          새로고침
        </button>
      </div>

      {/* Summary */}
      {summary && (
        <div className="p-6 rounded-xl border-2 border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">온보딩 완료율</span>
            <span className="text-2xl font-bold text-gray-900 dark:text-white">{summary.pct}%</span>
          </div>
          <div className="w-full h-3 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
            <div
              className={clsx('h-full rounded-full transition-all',
                summary.pct >= 80 ? 'bg-green-500' : summary.pct >= 50 ? 'bg-yellow-500' : 'bg-red-500')}
              style={{ width: `${summary.pct}%` }}
            />
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-sm">
            <span className="text-green-600 dark:text-green-400">✅ 정상 {summary.ok}</span>
            <span className="text-yellow-600 dark:text-yellow-400">⚠️ 주의 {summary.warn}</span>
            <span className="text-red-600 dark:text-red-400">❌ 미설정 {summary.missing}</span>
            {summary.error > 0 && <span className="text-gray-500">❔ 확인 불가 {summary.error}</span>}
            <span className="text-gray-400 dark:text-gray-500 ml-auto">총 {summary.total}개 항목</span>
          </div>
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 bg-gray-100 dark:bg-gray-700/50 rounded-xl animate-pulse" />
          ))}
        </div>
      )}

      {/* Category sections */}
      {!isLoading && grouped.map(({ cat, items }) => {
        const meta = categoryMeta[cat]
        const CatIcon = meta?.icon || Radar
        return (
          <div key={cat} className="space-y-3">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <CatIcon className="w-5 h-5 text-gray-400" />
              {meta?.label || cat}
            </h2>
            <div className="space-y-2">
              {items.map((item) => {
                const cfg = statusConfig[item.status] || statusConfig.error
                const Icon = cfg.icon
                return (
                  <div key={item.id} className="p-4 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
                    <div className="flex items-start gap-3">
                      <Icon className={clsx('w-5 h-5 mt-0.5 flex-shrink-0', cfg.color)} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-medium text-gray-900 dark:text-white">{item.label}</h3>
                          <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', cfg.badge)}>{cfg.label}</span>
                        </div>
                        {item.detail && (
                          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{item.detail}</p>
                        )}
                        {item.remediation && item.status !== 'ok' && (
                          <div className="mt-2 flex items-start gap-1.5 text-xs">
                            <span className="text-gray-400 dark:text-gray-500 flex-shrink-0">해결:</span>
                            <code className="font-mono text-amber-700 dark:text-amber-400 break-all">{item.remediation}</code>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}
