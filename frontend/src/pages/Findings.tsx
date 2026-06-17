import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Bell,
  CheckCircle,
  Clock,
  Filter,
  Search,
  XCircle,
  RefreshCw,
  Eye,
  CheckCheck,
  X,
  Shield,
  Server,
  MapPin,
  RotateCcw,
  Zap,
} from 'lucide-react'
import clsx from 'clsx'
import { useFindingsPaged, useFinding, useFindingActions, type Finding } from '../hooks/useApi'

const severityConfig: Record<string, {
  icon: typeof XCircle
  bg: string
  border: string
  text: string
  badge: string
}> = {
  critical: {
    icon: XCircle,
    bg: 'bg-red-50 dark:bg-red-900/20',
    border: 'border-red-200 dark:border-red-800',
    text: 'text-red-700',
    badge: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  },
  high: {
    icon: AlertTriangle,
    bg: 'bg-orange-50 dark:bg-orange-900/20',
    border: 'border-orange-200 dark:border-orange-800',
    text: 'text-orange-700',
    badge: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  },
  medium: {
    icon: AlertTriangle,
    bg: 'bg-yellow-50 dark:bg-yellow-900/20',
    border: 'border-yellow-200 dark:border-yellow-800',
    text: 'text-yellow-700',
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  },
  low: {
    icon: Bell,
    bg: 'bg-blue-50 dark:bg-blue-900/20',
    border: 'border-blue-200 dark:border-blue-800',
    text: 'text-blue-700',
    badge: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  },
  info: {
    icon: Bell,
    bg: 'bg-gray-50 dark:bg-gray-900/20',
    border: 'border-gray-200 dark:border-gray-700',
    text: 'text-gray-700',
    badge: 'bg-gray-100 text-gray-800 dark:bg-gray-700/40 dark:text-gray-300',
  },
}

const statusConfig: Record<string, { label: string; color: string }> = {
  active: { label: '활성', color: 'bg-red-500' },
  acknowledged: { label: '확인됨', color: 'bg-yellow-500' },
  resolved: { label: '해결됨', color: 'bg-green-500' },
}

const sourceConfig: Record<string, { label: string; color: string }> = {
  'aws.guardduty': { label: 'GuardDuty', color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' },
  'aws.securityhub': { label: 'Security Hub', color: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300' },
  'aws.inspector2': { label: 'Inspector', color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' },
}

const severityBarColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-400',
}

const STATUS_VALUES = ['all', 'active', 'acknowledged', 'resolved'] as const
type StatusFilter = (typeof STATUS_VALUES)[number]

// 페이지네이션 컨트롤 — 목록 위·아래에서 재사용. 컨트롤을 왼쪽에 모아 우하단 FloatingChat과 겹침 방지.
function PaginationBar({ page, totalPages, total, pageSize, search, onPage }: {
  page: number; totalPages: number; total: number; pageSize: number
  search: string; onPage: (updater: (p: number) => number) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-1">
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPage((p) => Math.max(1, p - 1))}
          disabled={page <= 1}
          className="px-3 py-1.5 text-sm rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:hover:bg-transparent"
        >
          이전
        </button>
        <span className="text-sm text-gray-600 dark:text-gray-300 tabular-nums">
          {page} / {totalPages}
        </span>
        <button
          onClick={() => onPage((p) => Math.min(totalPages, p + 1))}
          disabled={page >= totalPages}
          className="px-3 py-1.5 text-sm rounded-lg border border-gray-200 dark:border-gray-700 disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:hover:bg-transparent"
        >
          다음
        </button>
      </div>
      <span className="text-sm text-gray-500 dark:text-gray-400">
        전체 {total.toLocaleString()}건 중 {((page - 1) * pageSize + 1).toLocaleString()}–
        {Math.min(page * pageSize, total).toLocaleString()}
        {search && <span className="ml-2 text-amber-600 dark:text-amber-400">· 검색은 현재 페이지 내</span>}
      </span>
    </div>
  )
}

export default function Findings() {
  // 필터는 URL 쿼리파라미터와 연동 — 대시보드 빠른 작업(/findings?severity=critical) 진입,
  // 공유/북마크, 새로고침 유지가 가능. severity/source는 useFindings(서버 필터)로도 전달해
  // 최근 100건 한계 안에서 정확히 잡히게 한다(클라이언트 필터만 쓰면 100건 밖 누락).
  const [searchParams, setSearchParams] = useSearchParams()
  const initStatus = (searchParams.get('status') || 'all') as StatusFilter
  const filter: StatusFilter = STATUS_VALUES.includes(initStatus) ? initStatus : 'all'
  const severityFilter = searchParams.get('severity') || 'all'
  const sourceFilter = searchParams.get('source') || 'all'

  // 필터 변경 → URL 갱신(단일 진실원). 'all'이면 파라미터 제거.
  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams)
    if (!value || value === 'all') next.delete(key)
    else next.set(key, value)
    setSearchParams(next, { replace: true })
  }
  const setFilter = (v: string) => setParam('status', v)
  const setSeverityFilter = (v: string) => setParam('severity', v)
  const setSourceFilter = (v: string) => setParam('source', v)

  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [page, setPage] = useState(1)
  const PAGE_SIZE = 50
  const navigate = useNavigate()

  // 필터가 바뀌면 1페이지로 리셋
  const filterKey = `${filter}|${severityFilter}|${sourceFilter}`
  useEffect(() => { setPage(1) }, [filterKey])

  // 특정 finding을 Investigation Agent로 조사 — finding ID/타입/리소스를 컨텍스트로 채팅에 전달.
  // (Chat은 q를 입력창에만 채우므로 분석가가 검토 후 전송. Investigation은 단일 finding 기반이 강점)
  const investigateFinding = (f: Finding) => {
    const ctx = [
      `finding_id ${f.finding_id}`,
      f.finding_type && `유형 ${f.finding_type}`,
      (f.resource_arn || f.resource_id) && `리소스 ${f.resource_arn || f.resource_id}`,
    ].filter(Boolean).join(', ')
    const q = `이 보안 finding을 조사해줘 (근본원인·타임라인·MITRE·블라스트 래디우스): ${f.title} [${ctx}]`
    navigate('/chat?q=' + encodeURIComponent(q))
  }

  // 특정 finding에 대한 대응을 Response Agent에 제안 요청 — finding 컨텍스트를 채팅에 전달.
  // 구체 액션은 단정하지 않고 Response Agent가 finding 유형 보고 격리/차단/revoke 중 제안하도록 유도.
  // 실제 실행은 Task Board 승인 게이트를 거침(SOAR 안전 원칙).
  const proposeResponse = (f: Finding) => {
    const ctx = [
      `finding_id ${f.finding_id}`,
      f.finding_type && `유형 ${f.finding_type}`,
      (f.resource_arn || f.resource_id) && `리소스 ${f.resource_arn || f.resource_id}`,
      f.severity && `심각도 ${f.severity}`,
      f.recommendation && `권장조치 ${f.recommendation}`,
    ].filter(Boolean).join(', ')
    const q = `이 finding에 대한 대응을 제안해줘 (필요시 EC2 격리/SG 차단/IAM 키 revoke — 승인 게이트 경유): ${f.title} [${ctx}]`
    navigate('/chat?q=' + encodeURIComponent(q))
  }

  // 서버 페이지네이션 — 현재 페이지(50건)만 받아온다. total로 전체 건수 표시.
  const { data: paged, isLoading, refetch, isRefetching } = useFindingsPaged(
    page, PAGE_SIZE, filter, severityFilter, sourceFilter,
  )
  const { acknowledge, resolve, reopen } = useFindingActions()

  // Task Board → /findings?focus=<id> 진입 시 해당 finding을 단건 조회해 상세 자동 오픈.
  // (서버 페이지네이션이라 현재 페이지에 없을 수 있으므로 단건 GET)
  const focusId = searchParams.get('focus')
  const { data: focusFinding } = useFinding(focusId)
  useEffect(() => {
    if (focusFinding && focusFinding.finding_id) {
      setSelected(focusFinding)
      const next = new URLSearchParams(searchParams)
      next.delete('focus')
      setSearchParams(next, { replace: true })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusFinding])

  const findings: Finding[] = paged?.items || []
  const total = paged?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // 검색은 현재 페이지 내 클라이언트 필터(전역 검색은 limit/성능 이슈 — 안내 문구로 보완)
  const filtered = findings.filter((f) => {
    if (search) {
      const s = search.toLowerCase()
      const title = (f.title || '').toLowerCase()
      const desc = (f.description || '').toLowerCase()
      const res = (f.resource_id || '').toLowerCase()
      if (!title.includes(s) && !desc.includes(s) && !res.includes(s)) return false
    }
    return true
  })

  // status 탭 카운트: severity/source 필터를 반영한 status별 전체 개수(서버 COUNT, page_size=1).
  const cAll = useFindingsPaged(1, 1, 'all', severityFilter, sourceFilter, false)
  const cActive = useFindingsPaged(1, 1, 'active', severityFilter, sourceFilter, false)
  const cAck = useFindingsPaged(1, 1, 'acknowledged', severityFilter, sourceFilter, false)
  const cResolved = useFindingsPaged(1, 1, 'resolved', severityFilter, sourceFilter, false)
  const statusCounts = {
    all: cAll.data?.total ?? 0,
    active: cActive.data?.total ?? 0,
    acknowledged: cAck.data?.total ?? 0,
    resolved: cResolved.data?.total ?? 0,
  }

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return ''
    try {
      return new Date(dateStr).toLocaleString('ko-KR')
    } catch {
      return dateStr
    }
  }

  const handleAcknowledge = (id: string) => acknowledge.mutate(id)
  const handleResolve = (id: string) => resolve.mutate(id)
  const handleReopen = (id: string) => reopen.mutate(id)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">보안 Findings</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            GuardDuty · Security Hub · Inspector · CloudTrail 보안 탐지 (15초 자동 새로고침)
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

      {/* Status Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(['all', 'active', 'acknowledged', 'resolved'] as const).map((status) => (
          <button
            key={status}
            onClick={() => setFilter(status)}
            className={clsx(
              'p-4 rounded-lg border-2 transition-colors',
              filter === status
                ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                : 'border-gray-200 bg-white hover:border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-gray-600'
            )}
          >
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{statusCounts[status]}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {status === 'all' ? '전체' :
               status === 'active' ? '활성' :
               status === 'acknowledged' ? '확인됨' : '해결됨'}
            </p>
          </button>
        ))}
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
          <input
            type="text"
            placeholder="finding 검색 (제목, 설명, 리소스)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 dark:bg-gray-800 dark:border-gray-600 dark:text-white dark:placeholder-gray-400"
          />
        </div>
        <div className="relative flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400 dark:text-gray-500" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="appearance-none pl-2 pr-8 py-2 border rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300"
          >
            <option value="all">전체 심각도</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="appearance-none pl-2 pr-8 py-2 border rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300"
          >
            <option value="all">전체 소스</option>
            <option value="aws.guardduty">GuardDuty</option>
            <option value="aws.securityhub">Security Hub</option>
            <option value="aws.inspector2">Inspector</option>
          </select>
        </div>
      </div>

      {/* Skeleton Loading */}
      {isLoading && (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="p-4 rounded-xl border-2 border-gray-200 dark:border-gray-700 animate-pulse">
              <div className="flex items-center gap-3">
                <div className="w-5 h-5 bg-gray-200 dark:bg-gray-700 rounded" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
                </div>
                <div className="h-3 w-20 bg-gray-200 dark:bg-gray-700 rounded" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination (상단) */}
      {!isLoading && total > 0 && (
        <PaginationBar page={page} totalPages={totalPages} total={total}
          pageSize={PAGE_SIZE} search={search} onPage={setPage} />
      )}

      {/* Findings List */}
      {!isLoading && (
        <div className="space-y-3">
          {filtered.length > 0 ? (
            filtered.map((f) => {
              const severity = f.severity || 'info'
              const config = severityConfig[severity] || severityConfig.info
              const StatusIcon = config.icon
              const srcCfg = sourceConfig[f.source || '']

              return (
                <button
                  key={f.finding_id}
                  onClick={() => setSelected(f)}
                  className={clsx(
                    'w-full text-left p-4 rounded-xl border-2 transition-all duration-200 hover:shadow-md',
                    config.bg, config.border,
                    selected?.finding_id === f.finding_id && 'ring-2 ring-primary-500'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <StatusIcon className={clsx('w-5 h-5 flex-shrink-0', config.text)} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium text-gray-900 dark:text-white truncate">{f.title}</h3>
                        <span className={clsx('px-2 py-0.5 text-xs font-medium rounded uppercase flex-shrink-0', config.badge)}>{severity}</span>
                        {srcCfg && (
                          <span className={clsx('px-2 py-0.5 text-xs font-medium rounded flex-shrink-0', srcCfg.color)}>
                            {srcCfg.label}
                          </span>
                        )}
                      </div>
                      {f.resource_id && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">{f.resource_id}</p>
                      )}
                    </div>
                    <span className="flex items-center gap-1.5 text-sm flex-shrink-0">
                      <span className={clsx('w-2 h-2 rounded-full', statusConfig[f.status]?.color)} />
                      <span className="text-xs text-gray-500 dark:text-gray-400">{formatDate(f.created_at)}</span>
                    </span>
                  </div>
                </button>
              )
            })
          ) : (
            <div className="flex flex-col items-center justify-center py-16 bg-white dark:bg-gray-800 rounded-xl">
              <Shield className="w-16 h-16 text-gray-300 dark:text-gray-600 mb-4" />
              <p className="text-lg font-medium text-gray-500 dark:text-gray-400">Finding이 없습니다</p>
              <p className="text-sm text-gray-400 dark:text-gray-500">
                {findings.length === 0
                  ? '현재 보안 finding이 없습니다'
                  : '필터 조건에 맞는 finding이 없습니다'}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Pagination (하단) */}
      {!isLoading && total > 0 && (
        <div className="mt-4">
          <PaginationBar page={page} totalPages={totalPages} total={total}
            pageSize={PAGE_SIZE} search={search} onPage={setPage} />
        </div>
      )}

      {/* Finding Detail Drawer */}
      {selected && (
        <>
          <div className="fixed inset-0 bg-black/30 backdrop-blur-sm z-40" onClick={() => setSelected(null)} />
          <div className="fixed inset-y-0 right-0 w-full max-w-md bg-white dark:bg-gray-800 shadow-2xl z-50 overflow-y-auto transition-transform duration-300">
            <div className={clsx('h-1.5', severityBarColors[selected.severity || 'info'] || 'bg-gray-400')} />

            <div className="flex items-center justify-between p-6 border-b dark:border-gray-700">
              <div className="flex items-center gap-3">
                {(() => {
                  const config = severityConfig[selected.severity || 'info'] || severityConfig.info
                  const Icon = config.icon
                  return <Icon className={clsx('w-6 h-6', config.text)} />
                })()}
                <span className={clsx(
                  'px-2.5 py-1 text-xs font-semibold rounded uppercase',
                  (severityConfig[selected.severity || 'info'] || severityConfig.info).badge
                )}>
                  {selected.severity || 'info'}
                </span>
                <span className="flex items-center gap-1.5 text-sm">
                  <span className={clsx('w-2 h-2 rounded-full', statusConfig[selected.status]?.color || 'bg-gray-500')} />
                  {statusConfig[selected.status]?.label || selected.status}
                </span>
                {(selected.reopen_count ?? 0) > 0 && (
                  <span
                    title="해결 후 재발하여 자동 재오픈된 횟수"
                    className="flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300"
                  >
                    <RotateCcw className="w-3 h-3" />
                    {selected.reopen_count}회 재발
                  </span>
                )}
              </div>
              <button
                onClick={() => setSelected(null)}
                className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                aria-label="닫기"
              >
                <X className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Title + tags */}
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">{selected.title}</h2>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  {selected.product && (
                    <span className="px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                      {selected.product}
                    </span>
                  )}
                  {selected.source && sourceConfig[selected.source] && (
                    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', sourceConfig[selected.source].color)}>
                      {sourceConfig[selected.source].label}
                    </span>
                  )}
                  {selected.finding_type && (
                    <span className="px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">
                      {selected.finding_type}
                    </span>
                  )}
                </div>
              </div>

              {/* Description */}
              {selected.description && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">설명</h4>
                  <p className="text-gray-700 dark:text-gray-300">{selected.description}</p>
                </div>
              )}

              {/* Affected resource */}
              {(selected.resource_id || selected.resource_arn) && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">영향 받은 리소스</h4>
                  <div className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <Server className="w-4 h-4 mt-0.5 flex-shrink-0 text-gray-400" />
                    <span className="break-all">{selected.resource_arn || selected.resource_id}</span>
                  </div>
                </div>
              )}

              {/* Account / Region */}
              {(selected.account_id || selected.region) && (
                <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                  <MapPin className="w-4 h-4" />
                  <span>{selected.account_id}{selected.account_id && selected.region ? ' / ' : ''}{selected.region}</span>
                </div>
              )}

              {/* MITRE */}
              {selected.mitre_tactics && (
                <div>
                  <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">MITRE ATT&amp;CK</h4>
                  <p className="text-gray-700 dark:text-gray-300">{selected.mitre_tactics}</p>
                </div>
              )}

              {/* Recommendation */}
              {selected.recommendation && (
                <div className="flex items-start gap-2 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">권장 조치</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{selected.recommendation}</p>
                  </div>
                </div>
              )}

              {/* Evidence (raw) */}
              {selected.evidence && Object.keys(selected.evidence).length > 0 && (
                <details className="group">
                  <summary className="text-sm font-medium text-gray-500 dark:text-gray-400 cursor-pointer">
                    원본 증거 (Evidence)
                  </summary>
                  <pre className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg text-xs text-gray-600 dark:text-gray-400 overflow-x-auto max-h-64">
                    {JSON.stringify(selected.evidence, null, 2)}
                  </pre>
                </details>
              )}

              {/* Timestamps */}
              <div className="space-y-2">
                {selected.created_at && (
                  <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                    <Clock className="w-4 h-4" />
                    <span>생성: {formatDate(selected.created_at)}</span>
                  </div>
                )}
                {selected.updated_at && selected.updated_at !== selected.created_at && (
                  <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
                    <Clock className="w-4 h-4" />
                    <span>갱신: {formatDate(selected.updated_at)}</span>
                  </div>
                )}
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-3 pt-4 border-t dark:border-gray-700">
                <button
                  onClick={() => investigateFinding(selected)}
                  aria-label="이 finding 조사"
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium text-primary-700 bg-primary-100 rounded-lg hover:bg-primary-200 transition-colors dark:bg-primary-900/30 dark:text-primary-300 dark:hover:bg-primary-900/50"
                >
                  <Search className="w-4 h-4" />
                  조사
                </button>
                <button
                  onClick={() => proposeResponse(selected)}
                  aria-label="이 finding에 대한 대응 제안"
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium text-orange-700 bg-orange-100 rounded-lg hover:bg-orange-200 transition-colors dark:bg-orange-900/30 dark:text-orange-300 dark:hover:bg-orange-900/50"
                >
                  <Zap className="w-4 h-4" />
                  대응 제안
                </button>
                {selected.status === 'active' && (
                  <button
                    onClick={() => handleAcknowledge(selected.finding_id)}
                    disabled={acknowledge.isPending}
                    aria-label="finding 확인"
                    className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium text-yellow-700 bg-yellow-100 rounded-lg hover:bg-yellow-200 transition-colors disabled:opacity-50 dark:bg-yellow-900/30 dark:text-yellow-300 dark:hover:bg-yellow-900/50"
                  >
                    <Eye className="w-4 h-4" />
                    확인
                  </button>
                )}
                {(selected.status === 'active' || selected.status === 'acknowledged') && (
                  <button
                    onClick={() => handleResolve(selected.finding_id)}
                    disabled={resolve.isPending}
                    aria-label="finding 해결"
                    className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium text-green-700 bg-green-100 rounded-lg hover:bg-green-200 transition-colors disabled:opacity-50 dark:bg-green-900/30 dark:text-green-300 dark:hover:bg-green-900/50"
                  >
                    <CheckCheck className="w-4 h-4" />
                    해결
                  </button>
                )}
                {(selected.status === 'resolved' || selected.status === 'acknowledged') && (
                  <button
                    onClick={() => handleReopen(selected.finding_id)}
                    disabled={reopen.isPending}
                    aria-label="finding 다시 열기"
                    className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 dark:bg-gray-700/50 dark:text-gray-300 dark:hover:bg-gray-700"
                  >
                    <RotateCcw className="w-4 h-4" />
                    다시 열기
                  </button>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
