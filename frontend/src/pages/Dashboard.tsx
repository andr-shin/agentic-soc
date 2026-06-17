import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Shield,
  Crosshair,
  XCircle,
  Bell,
  FileText,
} from 'lucide-react'
import { useFindings, useHealthCheck, type Finding } from '../hooks/useApi'
import clsx from 'clsx'

interface StatCardProps {
  title: string
  value: string | number
  icon: React.ElementType
  tone: 'critical' | 'high' | 'medium' | 'low' | 'neutral'
}

const toneColors: Record<string, { card: string; icon: string }> = {
  critical: { card: 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20', icon: 'text-red-600' },
  high: { card: 'border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-900/20', icon: 'text-orange-600' },
  medium: { card: 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-900/20', icon: 'text-yellow-600' },
  low: { card: 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-900/20', icon: 'text-blue-600' },
  neutral: { card: 'border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800', icon: 'text-gray-500' },
}

function StatCard({ title, value, icon: Icon, tone }: StatCardProps) {
  const c = toneColors[tone]
  return (
    <div className={clsx('p-6 rounded-xl border-2 transition-all duration-200 hover:shadow-md', c.card)}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{value}</p>
        </div>
        <Icon className={clsx('w-8 h-8', c.icon)} />
      </div>
    </div>
  )
}

const severityBadge: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  info: 'bg-gray-100 text-gray-800 dark:bg-gray-700/40 dark:text-gray-300',
}

export default function Dashboard() {
  const navigate = useNavigate()
  // 최근 Finding 목록용 (최근 100건) — 목록 표시 전용
  const { data: findingsData, isLoading, refetch } = useFindings()
  // severity 통계/미해결 합계용 — 전체 DB GROUP BY 집계(get_health). useFindings(100건)로 세면
  // 실제 수천 건과 크게 어긋나므로 통계는 반드시 이 전체 집계를 사용.
  const { data: health, refetch: refetchHealth } = useHealthCheck()
  const [lastUpdate, setLastUpdate] = useState(new Date())

  useEffect(() => {
    const interval = setInterval(() => {
      refetch()
      refetchHealth()
      setLastUpdate(new Date())
    }, 60000)
    return () => clearInterval(interval)
  }, [refetch, refetchHealth])

  const handleRefresh = () => {
    refetch()
    refetchHealth()
    setLastUpdate(new Date())
  }

  const findings: Finding[] = (findingsData as Finding[]) || []
  // 통계는 전체 집계(get_health)에서 — active+acknowledged severity별 카운트
  const sev = health?.by_severity
  const bySeverity = (s: 'critical' | 'high' | 'medium' | 'low' | 'info') => sev?.[s] ?? 0
  const openTotal = health?.open_findings ?? 0

  // 미해결(open)의 정식 정의 = active + acknowledged (get_health와 동일). resolved 제외만으로는
  // 향후 다른 status가 섞일 수 있어 헤드라인 지표와 어긋남.
  const recent = [...findings]
    .filter((f) => f.status === 'active' || f.status === 'acknowledged')
    .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
    .slice(0, 6)

  const formatDate = (s?: string) => {
    if (!s) return ''
    try {
      return new Date(s).toLocaleString('ko-KR', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    } catch {
      return s
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">SOC 대시보드</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            보안 finding 현황 및 실시간 위협 탐지
          </p>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-500 dark:text-gray-400">
            마지막 업데이트: {lastUpdate.toLocaleTimeString('ko-KR')}
          </span>
          <button
            onClick={handleRefresh}
            aria-label="새로고침"
            className="flex-shrink-0 flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 rounded-lg hover:bg-primary-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            새로고침
          </button>
        </div>
      </div>

      {/* Severity Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        <StatCard title="Critical" value={bySeverity('critical')} icon={XCircle} tone="critical" />
        <StatCard title="High" value={bySeverity('high')} icon={AlertTriangle} tone="high" />
        <StatCard title="Medium" value={bySeverity('medium')} icon={AlertTriangle} tone="medium" />
        <StatCard title="미해결 합계" value={openTotal} icon={Shield} tone={openTotal > 0 ? 'high' : 'neutral'} />
      </div>

      {/* Recent Findings */}
      <div className="p-6 bg-white rounded-xl shadow-sm border border-gray-100 dark:border-gray-700/50 dark:bg-gray-800">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">최근 Finding</h2>
          <button
            onClick={() => navigate('/findings')}
            className="text-sm text-primary-600 hover:text-primary-700"
          >
            전체 보기 &rarr;
          </button>
        </div>
        {isLoading ? (
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-12 bg-gray-100 dark:bg-gray-700/50 rounded-lg animate-pulse" />
            ))}
          </div>
        ) : recent.length > 0 ? (
          <div className="space-y-2">
            {recent.map((f) => (
              <button
                key={f.finding_id}
                onClick={() => navigate('/findings')}
                className="w-full flex items-center gap-3 p-3 rounded-lg border border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors text-left"
              >
                <span className={clsx('px-2 py-0.5 text-xs font-medium rounded uppercase flex-shrink-0', severityBadge[f.severity || 'info'])}>
                  {f.severity || 'info'}
                </span>
                <span className="flex-1 min-w-0 truncate text-sm text-gray-800 dark:text-gray-200">{f.title}</span>
                {f.product && (
                  <span className="text-xs text-gray-400 dark:text-gray-500 flex-shrink-0">{f.product}</span>
                )}
                <span className="text-xs text-gray-400 dark:text-gray-500 flex-shrink-0">{formatDate(f.created_at)}</span>
              </button>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-gray-400 dark:text-gray-500">
            <CheckCircle className="w-12 h-12 mb-3" />
            <p>미해결 finding이 없습니다</p>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="p-6 bg-white rounded-xl shadow-sm border border-gray-100 dark:border-gray-700/50 dark:bg-gray-800">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 dark:text-white">빠른 작업</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button
            onClick={() => navigate('/findings?severity=critical')}
            className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:bg-gray-50 hover:border-primary-200 hover:shadow-sm transition-all duration-200 dark:border-gray-700 dark:hover:bg-gray-700 dark:hover:border-primary-800"
          >
            <XCircle className="w-6 h-6 text-red-600" />
            <span className="text-sm font-medium dark:text-gray-300">Critical Findings</span>
          </button>
          <button
            onClick={() => navigate('/chat?q=' + encodeURIComponent('현재 보안 태세 기반으로 컴플라이언스 리포트를 작성해줘'))}
            className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:bg-gray-50 hover:border-primary-200 hover:shadow-sm transition-all duration-200 dark:border-gray-700 dark:hover:bg-gray-700 dark:hover:border-primary-800"
          >
            <FileText className="w-6 h-6 text-primary-600" />
            <span className="text-sm font-medium dark:text-gray-300">보안 리포트</span>
          </button>
          <button
            onClick={() => navigate('/chat?q=' + encodeURIComponent('인터넷에 노출된 리소스 중 과다 권한 IAM 역할이 붙어있거나 미암호화·공개 데이터에 접근 가능한 복합 위험 경로를 교차 분석해줘 (CSPM 단건 점검 말고 조합된 공격 경로 중심)'))}
            className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:bg-gray-50 hover:border-primary-200 hover:shadow-sm transition-all duration-200 dark:border-gray-700 dark:hover:bg-gray-700 dark:hover:border-primary-800"
          >
            <Crosshair className="w-6 h-6 text-purple-600" />
            <span className="text-sm font-medium dark:text-gray-300">Posture 분석</span>
          </button>
          <button
            onClick={() => navigate('/chat?q=' + encodeURIComponent('최근 실패 로그인 폭주나 신규 자격증명 생성 후 비정상 AssumeRole·권한 상승·대용량 egress·희귀 DNS 조회로 이어지는 침입 흔적을 CloudTrail·VPC Flow·DNS 로그 교차로 헌팅해줘'))}
            className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:bg-gray-50 hover:border-primary-200 hover:shadow-sm transition-all duration-200 dark:border-gray-700 dark:hover:bg-gray-700 dark:hover:border-primary-800"
          >
            <Crosshair className="w-6 h-6 text-red-500" />
            <span className="text-sm font-medium dark:text-gray-300">Threat Hunting</span>
          </button>
        </div>
      </div>
    </div>
  )
}
