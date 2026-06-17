import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../contexts/AuthContext'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

// Types
// SOC health summary — 백엔드 get_health()가 findings 테이블을 GROUP BY로 전체 집계해 반환.
// (useFindings는 최근 100건만 받으므로, 대시보드 통계는 반드시 이 전체 집계를 사용)
interface HealthCheckResponse {
  overall_status: 'healthy' | 'warning' | 'critical' | 'unknown'
  open_findings: number
  by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  timestamp: string
  error?: string
}

// Chat types removed in v7.0 — chat now goes directly to AgentCore

export interface Finding {
  finding_id: string
  title: string
  description?: string
  finding_type?: string
  product?: string
  service?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'active' | 'acknowledged' | 'resolved'
  source?: string
  resource_id?: string
  resource_arn?: string
  account_id?: string
  region?: string
  recommendation?: string
  evidence?: Record<string, unknown>
  mitre_tactics?: string
  created_at?: string
  updated_at?: string
  resolved_at?: string | null
  reopen_count?: number
}

interface Conversation {
  conversation_id: string
  title: string
  updated_at: string
  message_count: number
}

interface ConversationDetail {
  conversation_id: string
  title?: string
  messages: Array<{
    role: 'user' | 'assistant'
    content: string
    timestamp: string
  }>
}

// Hook to get auth token
function useAuthToken() {
  const { getAuthToken, isAuthEnabled } = useAuth()
  return { getAuthToken, isAuthEnabled }
}

// API Functions with Auth
async function fetchApiWithAuth<T>(
  endpoint: string,
  getAuthToken: () => Promise<string | null>,
  options?: RequestInit
): Promise<T> {
  const token = await getAuthToken()

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options?.headers as Record<string, string>) || {}),
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    throw new Error(`API Error: ${response.status} ${response.statusText}`)
  }

  return response.json()
}

// Health Check Hook
export function useHealthCheck() {
  const { getAuthToken } = useAuthToken()

  return useQuery<HealthCheckResponse>({
    queryKey: ['health-check'],
    queryFn: () => fetchApiWithAuth<HealthCheckResponse>('/health', getAuthToken),
    refetchInterval: 60000,
    retry: 3,
    staleTime: 30000,
  })
}

// Conversations List Hook
export function useConversations() {
  const { getAuthToken, isAuthEnabled } = useAuthToken()

  return useQuery<Conversation[]>({
    queryKey: ['conversations'],
    queryFn: () => fetchApiWithAuth<Conversation[]>('/conversations', getAuthToken),
    enabled: isAuthEnabled,
    staleTime: 30000,
  })
}

// Single Conversation Hook
export function useConversation(conversationId: string | null) {
  const { getAuthToken, isAuthEnabled } = useAuthToken()

  return useQuery<ConversationDetail>({
    queryKey: ['conversation', conversationId],
    queryFn: () =>
      fetchApiWithAuth<ConversationDetail>(`/conversations/${conversationId}`, getAuthToken),
    enabled: isAuthEnabled && !!conversationId,
    staleTime: 10000,
  })
}

// Delete Conversation Hook
export function useDeleteConversation() {
  const queryClient = useQueryClient()
  const { getAuthToken } = useAuthToken()

  return useMutation<void, Error, string>({
    mutationFn: (conversationId) =>
      fetchApiWithAuth(`/conversations/${conversationId}`, getAuthToken, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
    },
  })
}

// Findings Hook
// enabled로 마운트만 하고 fetch는 보류 가능 — CommandPalette처럼 항상 마운트되지만
// 열렸을 때만 데이터가 필요한 경우 앱 전역 15초 폴링을 막는다.
export function useFindings(status?: string, severity?: string, source?: string, enabled = true) {
  const { getAuthToken } = useAuthToken()

  return useQuery<Finding[]>({
    queryKey: ['findings', status, severity, source],
    queryFn: () => {
      const qs = new URLSearchParams()
      if (status && status !== 'all') qs.set('status', status)
      if (severity && severity !== 'all') qs.set('severity', severity)
      if (source && source !== 'all') qs.set('source', source)
      const params = qs.toString() ? `?${qs.toString()}` : ''
      return fetchApiWithAuth<Finding[]>(`/findings${params}`, getAuthToken)
    },
    enabled,
    refetchInterval: 15000,
    staleTime: 5000,
  })
}

// 단건 finding 조회 (Task Board → Finding 링크의 focus 대상). findingId 없으면 비활성.
export function useFinding(findingId: string | null) {
  const { getAuthToken } = useAuthToken()
  return useQuery<Finding>({
    queryKey: ['finding', findingId],
    queryFn: () => fetchApiWithAuth<Finding>(`/findings?finding_id=${encodeURIComponent(findingId!)}`, getAuthToken),
    enabled: !!findingId,
    staleTime: 10000,
  })
}

// 페이지네이션 응답 — Findings 페이지 전용. page 파라미터를 보내면 백엔드가 {items,total,...} 반환.
export interface PagedFindings {
  items: Finding[]
  total: number
  page: number
  page_size: number
}

// Findings 페이지 전용 페이지네이션 훅 (기존 useFindings는 배열 반환 — 무영향)
// poll=false면 15초 자동 폴링을 끈다 — status 탭 카운트(page_size=1)는 매번 서버 COUNT를
// 돌리므로, 목록만 폴링하고 카운트는 사용자가 갱신할 때(쿼리 무효화)만 다시 받게 한다.
export function useFindingsPaged(
  page: number, pageSize: number, status?: string, severity?: string, source?: string,
  poll = true,
) {
  const { getAuthToken } = useAuthToken()

  return useQuery<PagedFindings>({
    queryKey: ['findings-paged', page, pageSize, status, severity, source],
    queryFn: () => {
      const qs = new URLSearchParams()
      qs.set('page', String(page))
      qs.set('page_size', String(pageSize))
      if (status && status !== 'all') qs.set('status', status)
      if (severity && severity !== 'all') qs.set('severity', severity)
      if (source && source !== 'all') qs.set('source', source)
      return fetchApiWithAuth<PagedFindings>(`/findings?${qs.toString()}`, getAuthToken)
    },
    refetchInterval: poll ? 15000 : false,
    staleTime: poll ? 5000 : 30000,
  })
}

// Finding Actions Hook
export function useFindingActions() {
  const queryClient = useQueryClient()
  const { getAuthToken } = useAuthToken()

  // finding_id contains slashes/colons (e.g. sh-arn:aws:...:finding/uuid),
  // so it is passed in the request body, not the URL path.
  const acknowledge = useMutation<void, Error, string>({
    mutationFn: (findingId) =>
      fetchApiWithAuth(`/findings/acknowledge`, getAuthToken, {
        method: 'POST', body: JSON.stringify({ finding_id: findingId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const resolve = useMutation<void, Error, string>({
    mutationFn: (findingId) =>
      fetchApiWithAuth(`/findings/resolve`, getAuthToken, {
        method: 'POST', body: JSON.stringify({ finding_id: findingId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  // 다시 열기 — resolved/acknowledged를 active로 되돌림(오조치 복구)
  const reopen = useMutation<void, Error, string>({
    mutationFn: (findingId) =>
      fetchApiWithAuth(`/findings/reopen`, getAuthToken, {
        method: 'POST', body: JSON.stringify({ finding_id: findingId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  return { acknowledge, resolve, reopen }
}

// App Config Hook (v7.0 — returns host_agent_url for direct AgentCore access)
interface ActiveAgent {
  id: string
  name: string
  description: string
  icon: string
}

interface AppConfig {
  host_agent_url: string
  active_agents?: ActiveAgent[]
}

export function useConfig() {
  const { getAuthToken } = useAuthToken()
  return useQuery<AppConfig>({
    queryKey: ['app-config'],
    queryFn: () => fetchApiWithAuth<AppConfig>('/config', getAuthToken),
    staleTime: 300000,
    retry: 1,
  })
}

// ============================================================
// Log Explorer (CloudWatch Unified Data Store)
// ============================================================
export interface LogSource {
  source: string
  log_group: string
  schema: string
  is_searchable?: boolean
  status_detail?: string
}

interface LogSourcesResponse {
  sources: LogSource[]
}

export interface LogQueryResult {
  source: string
  log_group: string
  query: string
  minutes: number
  rows: Record<string, string>[]
  count: number
  records_scanned?: number
  error?: string
}

export function useLogSources() {
  const { getAuthToken } = useAuthToken()
  return useQuery<LogSourcesResponse>({
    queryKey: ['log-sources'],
    queryFn: () => fetchApiWithAuth<LogSourcesResponse>('/logs/sources', getAuthToken),
    staleTime: 300000,
  })
}

export function useRunLogQuery() {
  const { getAuthToken } = useAuthToken()
  return useMutation<LogQueryResult, Error, { source: string; query: string; minutes: number; limit?: number }>({
    mutationFn: (body) =>
      fetchApiWithAuth<LogQueryResult>('/logs/query', getAuthToken, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

export function useGenerateLogQuery() {
  const { getAuthToken } = useAuthToken()
  return useMutation<{ query: string; raw?: string; error?: string }, Error, { source: string; natural_language: string; finding_context?: unknown }>({
    mutationFn: (body) =>
      fetchApiWithAuth('/logs/generate', getAuthToken, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  })
}

// 저장된 LogsQL 쿼리 (사용자별)
export interface SavedLogQuery {
  query_id: string
  name: string
  source: string
  query: string
  minutes: number
  created_at: string
}

export function useSavedLogQueries() {
  const { getAuthToken } = useAuthToken()
  return useQuery<SavedLogQuery[]>({
    queryKey: ['log-queries'],
    queryFn: () => fetchApiWithAuth<SavedLogQuery[]>('/logs/queries', getAuthToken),
    staleTime: 30000,
  })
}

export function useSaveLogQuery() {
  const queryClient = useQueryClient()
  const { getAuthToken } = useAuthToken()
  return useMutation<{ query_id: string; created_at: string }, Error,
    { name: string; source: string; query: string; minutes?: number }>({
    mutationFn: (body) =>
      fetchApiWithAuth('/logs/queries', getAuthToken, {
        method: 'POST', body: JSON.stringify(body),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['log-queries'] }),
  })
}

export function useDeleteLogQuery() {
  const queryClient = useQueryClient()
  const { getAuthToken } = useAuthToken()
  return useMutation<void, Error, string>({
    mutationFn: (queryId) =>
      fetchApiWithAuth(`/logs/queries/${queryId}`, getAuthToken, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['log-queries'] }),
  })
}

// ============================================================
// Task Board (SOAR approval workflow)
// ============================================================
export interface SocTask {
  task_id: string
  title: string
  description?: string
  status: 'open' | 'pending_approval' | 'executed' | 'rejected' | 'failed' | 'done'
  severity?: string
  finding_id?: string
  proposed_action?: string
  action_params?: Record<string, unknown>
  impact?: string
  approved_by?: string
  completed_by?: string
  execution_result?: string
  created_at?: string
  updated_at?: string
}

export function useTasks(status?: string) {
  const { getAuthToken } = useAuthToken()
  return useQuery<SocTask[]>({
    queryKey: ['tasks', status],
    queryFn: () => {
      const params = status && status !== 'all' ? `?status=${status}` : ''
      return fetchApiWithAuth<SocTask[]>(`/tasks${params}`, getAuthToken)
    },
    refetchInterval: 15000,
    staleTime: 5000,
  })
}

export function useTaskActions() {
  const queryClient = useQueryClient()
  const { getAuthToken } = useAuthToken()

  const approve = useMutation<unknown, Error, string>({
    mutationFn: (taskId) =>
      fetchApiWithAuth(`/tasks/${taskId}/approve`, getAuthToken, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }),
  })

  const reject = useMutation<unknown, Error, string>({
    mutationFn: (taskId) =>
      fetchApiWithAuth(`/tasks/${taskId}/reject`, getAuthToken, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }),
  })

  // 분석가 작업 티켓 완료 처리(done) — 실제 조치 실행이 아니라 추적 종결
  const complete = useMutation<unknown, Error, string>({
    mutationFn: (taskId) =>
      fetchApiWithAuth(`/tasks/${taskId}/complete`, getAuthToken, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }),
  })

  return { approve, reject, complete }
}

// ============================================================
// SOC Readiness (onboarding/prerequisite checks)
// ============================================================
export interface ReadinessItem {
  id: string
  category: 'detection' | 'logs' | 'agents' | 'observability'
  label: string
  status: 'ok' | 'warn' | 'missing' | 'error'
  detail?: string
  remediation?: string
}

export interface ReadinessResponse {
  items: ReadinessItem[]
  summary: { ok: number; total: number; pct: number; warn: number; missing: number; error: number }
}

export function useReadiness() {
  const { getAuthToken } = useAuthToken()
  return useQuery<ReadinessResponse>({
    queryKey: ['readiness'],
    queryFn: () => fetchApiWithAuth<ReadinessResponse>('/readiness', getAuthToken),
    staleTime: 60000,
    refetchInterval: 120000,
  })
}
