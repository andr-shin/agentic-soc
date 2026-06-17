import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  ShieldAlert,
  Check,
  X,
  Clock,
  Server,
  RefreshCw,
  Loader2,
  AlertTriangle,
  Sparkles,
  CheckCheck,
} from 'lucide-react'
import clsx from 'clsx'
import { useTasks, useTaskActions, type SocTask } from '../hooks/useApi'

const statusConfig: Record<string, { label: string; color: string; badge: string }> = {
  pending_approval: { label: '승인 대기', color: 'bg-yellow-500', badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' },
  open: { label: '진행 중', color: 'bg-blue-500', badge: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' },
  executed: { label: '실행됨', color: 'bg-green-500', badge: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
  done: { label: '완료', color: 'bg-green-600', badge: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
  rejected: { label: '거부됨', color: 'bg-gray-400', badge: 'bg-gray-100 text-gray-700 dark:bg-gray-700/40 dark:text-gray-300' },
  failed: { label: '실패', color: 'bg-red-500', badge: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' },
}

const FILTERS = [
  { key: 'pending_approval', label: '승인 대기' },
  { key: 'open', label: '진행 중' },
  { key: 'executed', label: '실행됨' },
  { key: 'done', label: '완료' },
  { key: 'rejected', label: '거부됨' },
  { key: 'failed', label: '실패' },
  { key: 'all', label: '전체' },
]

export default function TaskBoard() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState('pending_approval')
  const { data: tasksData, isLoading, refetch, isRefetching } = useTasks(filter)
  const { approve, reject, complete } = useTaskActions()

  const tasks: SocTask[] = (tasksData as SocTask[]) || []

  const formatDate = (s?: string) => {
    if (!s) return ''
    try { return new Date(s).toLocaleString('ko-KR') } catch { return s }
  }

  // 'AI로 처리' — task를 채팅으로 넘겨 AI가 처리를 돕는다. 고위험(proposed_action)은 실행 제안(승인 게이트),
  // 일반 작업 티켓은 단계별 가이드+CLI. (Chat은 q를 입력만 채우므로 분석가가 검토 후 전송)
  const handleProcess = (task: SocTask) => {
    // task 설명 원문(마크다운 구조)을 보존해 전달 — AI가 전체 맥락을 받도록. URL 안전 상한 2000자.
    const desc = (task.description || '').trim().slice(0, 2000)
    const ctx = [
      task.finding_id && `finding_id ${task.finding_id}`,
      task.proposed_action && `제안된 조치 ${task.proposed_action}`,
    ].filter(Boolean).join(', ')
    // 앞의 의도 접두어가 classifier에서 결정적으로 라우팅됨(Haiku 판단 우회).
    const q = task.proposed_action
      ? `(대응 실행 제안) 이 대응을 실행 제안해줘 (승인 게이트 경유): ${task.title}${ctx ? ` [${ctx}]` : ''}\n\n[작업 내용]\n${desc}`
      : `(작업 가이드 요청) 다음 보안 작업의 수행 가이드를 작성해줘 — 단계별 절차와 복사해서 쓸 수 있는 정확한 CLI/코드 블록을 포함해서(실제 실행은 분석가가 함, 조치를 실행하지는 마): ${task.title}${ctx ? ` [${ctx}]` : ''}\n\n[작업 내용]\n${desc}`
    navigate('/chat?q=' + encodeURIComponent(q))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-primary-600" />
            대응 (SOAR)
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            자동 대응 승인 워크플로우 — 고위험 조치는 분석가 승인 후 실행됩니다
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

      {/* Filter tabs */}
      <div className="flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={clsx(
              'px-4 py-2 rounded-lg border-2 text-sm font-medium transition-colors',
              filter === f.key
                ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                : 'border-gray-200 bg-white hover:border-gray-300 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300'
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-28 bg-gray-100 dark:bg-gray-700/50 rounded-xl animate-pulse" />
          ))}
        </div>
      )}

      {/* Task list */}
      {!isLoading && (
        <div className="space-y-3">
          {tasks.length > 0 ? (
            tasks.map((task) => {
              const cfg = statusConfig[task.status] || statusConfig.open
              const isHighRisk = !!task.proposed_action
              const isPending = task.status === 'pending_approval'
              return (
                <div
                  key={task.task_id}
                  className="p-5 rounded-xl border-2 border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {isHighRisk ? (
                          <ShieldAlert className="w-5 h-5 text-red-500 flex-shrink-0" />
                        ) : (
                          <ShieldCheck className="w-5 h-5 text-blue-500 flex-shrink-0" />
                        )}
                        <h3 className="font-semibold text-gray-900 dark:text-white">{task.title}</h3>
                        {/* 작업 유형: 고위험 자동조치(승인 필요) vs 분석가 작업 티켓 */}
                        <span className={clsx('px-2 py-0.5 text-xs font-medium rounded',
                          isHighRisk
                            ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                            : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300')}>
                          {isHighRisk ? '자동 조치' : '작업 티켓'}
                        </span>
                        <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', cfg.badge)}>
                          {/* 일반 작업 티켓의 executed는 '조치 실행'이 아니라 '완료'를 뜻함 */}
                          {!isHighRisk && task.status === 'executed' ? '완료' : cfg.label}
                        </span>
                        {task.proposed_action && (
                          <span className="px-2 py-0.5 text-xs font-mono font-medium rounded bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300">
                            {task.proposed_action}
                          </span>
                        )}
                      </div>

                      {task.description && (
                        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400 whitespace-pre-wrap">{task.description}</p>
                      )}

                      {/* Action params */}
                      {task.action_params && Object.keys(task.action_params).length > 0 && (
                        <div className="mt-2 flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                          <Server className="w-3.5 h-3.5" />
                          <code className="font-mono">{JSON.stringify(task.action_params)}</code>
                        </div>
                      )}

                      {/* Impact */}
                      {task.impact && (
                        <div className="mt-2 flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-400">
                          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                          <span>영향: {task.impact}</span>
                        </div>
                      )}

                      <div className="mt-2 flex items-center gap-3 text-xs text-gray-400 dark:text-gray-500">
                        <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{formatDate(task.created_at)}</span>
                        {task.approved_by && <span>승인자: {task.approved_by}</span>}
                        {task.finding_id && (
                          <button
                            onClick={(e) => { e.stopPropagation(); navigate('/findings?focus=' + encodeURIComponent(task.finding_id!)) }}
                            className="font-mono text-primary-600 dark:text-primary-400 hover:underline"
                            title="원본 finding 보기"
                          >
                            🔗 {task.finding_id.length > 32 ? task.finding_id.slice(0, 32) + '…' : task.finding_id}
                          </button>
                        )}
                      </div>

                      {/* Execution result */}
                      {task.execution_result && (
                        <details className="mt-2">
                          <summary className="text-xs text-gray-500 dark:text-gray-400 cursor-pointer">실행 결과</summary>
                          <pre className="mt-1 p-2 bg-gray-50 dark:bg-gray-900 rounded text-xs overflow-x-auto text-gray-600 dark:text-gray-400">{task.execution_result}</pre>
                        </details>
                      )}
                    </div>

                    {/* Approve / Reject (only for pending_approval) */}
                    {isPending && (
                      <div className="flex flex-col gap-2 flex-shrink-0">
                        <button
                          onClick={() => approve.mutate(task.task_id)}
                          disabled={approve.isPending}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-green-700 bg-green-100 rounded-lg hover:bg-green-200 transition-colors disabled:opacity-50 dark:bg-green-900/30 dark:text-green-300"
                        >
                          {approve.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                          승인·실행
                        </button>
                        <button
                          onClick={() => reject.mutate(task.task_id)}
                          disabled={reject.isPending}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 dark:bg-gray-700 dark:text-gray-300"
                        >
                          <X className="w-4 h-4" />
                          거부
                        </button>
                      </div>
                    )}

                    {/* 작업 티켓 처리 (open) — AI로 처리 + 완료 */}
                    {task.status === 'open' && (
                      <div className="flex flex-col gap-2 flex-shrink-0">
                        <button
                          onClick={() => handleProcess(task)}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-purple-700 bg-purple-100 rounded-lg hover:bg-purple-200 transition-colors dark:bg-purple-900/30 dark:text-purple-300"
                        >
                          <Sparkles className="w-4 h-4" />
                          AI로 처리
                        </button>
                        <button
                          onClick={() => complete.mutate(task.task_id)}
                          disabled={complete.isPending}
                          className="flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-green-700 bg-green-100 rounded-lg hover:bg-green-200 transition-colors disabled:opacity-50 dark:bg-green-900/30 dark:text-green-300"
                        >
                          {complete.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCheck className="w-4 h-4" />}
                          완료
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )
            })
          ) : (
            <div className="flex flex-col items-center justify-center py-16 bg-white dark:bg-gray-800 rounded-xl">
              <ShieldCheck className="w-16 h-16 text-gray-300 dark:text-gray-600 mb-4" />
              <p className="text-lg font-medium text-gray-500 dark:text-gray-400">태스크가 없습니다</p>
              <p className="text-sm text-gray-400 dark:text-gray-500">
                {filter === 'pending_approval' ? '승인 대기 중인 조치가 없습니다' : '해당 상태의 태스크가 없습니다'}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
