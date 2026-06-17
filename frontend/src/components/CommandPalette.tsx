import { useState, useEffect, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  Command,
  LayoutDashboard,
  MessageSquare,
  Shield,
  Zap,
  ArrowRight,
} from 'lucide-react'
import { useFindings } from '../hooks/useApi'

interface CommandItem {
  id: string
  name: string
  category: string
  icon: React.ElementType
  action: () => void
  subtitle?: string
}

export default function CommandPalette() {
  const [isOpen, setIsOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  // 팔레트가 열렸을 때만 findings를 로드 — 닫힌 상태에서 앱 전역 15초 폴링 방지.
  const { data: findings } = useFindings(undefined, undefined, undefined, isOpen)

  // Cmd+K / Ctrl+K listener
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setIsOpen(prev => !prev)
        setSearch('')
        setSelectedIndex(0)
      }
      if (e.key === 'Escape') setIsOpen(false)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Auto-focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  const go = (path: string) => {
    navigate(path)
    setIsOpen(false)
  }

  const allItems = useMemo<CommandItem[]>(() => {
    const pages: CommandItem[] = [
      { id: 'page-dashboard', name: '대시보드', category: '페이지', icon: LayoutDashboard, action: () => go('/') },
      { id: 'page-findings', name: 'Findings', category: '페이지', icon: Shield, action: () => go('/findings') },
      { id: 'page-chat', name: '채팅', category: '페이지', icon: MessageSquare, action: () => go('/chat') },
    ]

    const quickActions: CommandItem[] = [
      {
        id: 'action-report',
        name: '보안 리포트',
        category: '빠른 작업',
        icon: Zap,
        action: () => go('/chat?q=현재 보안 태세 기반으로 컴플라이언스 리포트를 작성해줘'),
      },
      {
        id: 'action-posture',
        name: 'Posture 분석',
        category: '빠른 작업',
        icon: Zap,
        action: () => go('/chat?q=인터넷에 노출된 리소스 중 과다 권한 IAM 역할이 붙어있거나 미암호화·공개 데이터에 접근 가능한 복합 위험 경로를 교차 분석해줘 (CSPM 단건 점검 말고 조합된 공격 경로 중심)'),
      },
      {
        id: 'action-threat-hunt',
        name: 'Threat Hunting',
        category: '빠른 작업',
        icon: Zap,
        action: () => go('/chat?q=최근 실패 로그인 폭주나 신규 자격증명 생성 후 비정상 AssumeRole·권한 상승·대용량 egress·희귀 DNS 조회로 이어지는 침입 흔적을 CloudTrail·VPC Flow·DNS 로그 교차로 헌팅해줘'),
      },
      {
        id: 'action-critical',
        name: 'Critical Findings',
        category: '빠른 작업',
        icon: Zap,
        action: () => go('/findings?severity=critical'),
      },
    ]

    const findingItems: CommandItem[] = ((findings as any[]) || [])
      .filter((f: any) => f.status === 'active')
      .slice(0, 20)
      .map((f: any) => ({
        id: `finding-${f.finding_id}`,
        name: f.title,
        category: 'Findings',
        icon: Shield,
        subtitle: f.severity,
        action: () => go('/findings'),
      }))

    return [...pages, ...quickActions, ...findingItems]
  }, [findings])

  const filtered = useMemo(() => {
    if (!search.trim()) return allItems
    const q = search.toLowerCase()
    return allItems.filter(
      item =>
        item.name.toLowerCase().includes(q) ||
        (item.subtitle && item.subtitle.toLowerCase().includes(q))
    )
  }, [search, allItems])

  // Group filtered results by category
  const grouped = useMemo(() => {
    const map = new Map<string, CommandItem[]>()
    for (const item of filtered) {
      const list = map.get(item.category) || []
      list.push(item)
      map.set(item.category, list)
    }
    return map
  }, [filtered])

  // Reset selectedIndex when filter changes
  useEffect(() => {
    setSelectedIndex(0)
  }, [search])

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex(prev => Math.min(prev + 1, filtered.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex(prev => Math.max(prev - 1, 0))
      } else if (e.key === 'Enter' && filtered[selectedIndex]) {
        e.preventDefault()
        filtered[selectedIndex].action()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, filtered, selectedIndex])

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return
    const el = listRef.current.querySelector(`[data-index="${selectedIndex}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [selectedIndex])

  if (!isOpen) return null

  let flatIndex = -1

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
        onClick={() => setIsOpen(false)}
      />

      {/* Panel */}
      <div
        className="relative w-full max-w-lg mx-4 rounded-2xl shadow-2xl backdrop-blur-xl bg-white/80 dark:bg-gray-800/80 border border-gray-200/50 dark:border-gray-700/50 overflow-hidden animate-in"
        style={{
          animation: 'commandPaletteIn 150ms ease-out',
        }}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-200/50 dark:border-gray-700/50">
          <Search className="w-5 h-5 text-gray-400" />
          <input
            ref={inputRef}
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="검색하거나 명령어를 입력하세요..."
            className="flex-1 bg-transparent text-gray-900 dark:text-white placeholder-gray-400 outline-none text-sm"
          />
          <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 text-xs text-gray-400 bg-gray-100 dark:bg-gray-700 rounded">
            <Command className="w-3 h-3" />K
          </kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-80 overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-gray-400">
              결과가 없습니다
            </div>
          ) : (
            Array.from(grouped.entries()).map(([category, items]) => (
              <div key={category}>
                <div className="px-4 py-1.5 text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                  {category}
                </div>
                {items.map(item => {
                  flatIndex++
                  const idx = flatIndex
                  const isSelected = idx === selectedIndex
                  return (
                    <button
                      key={item.id}
                      data-index={idx}
                      onClick={() => item.action()}
                      onMouseEnter={() => setSelectedIndex(idx)}
                      className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                        isSelected
                          ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                          : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'
                      }`}
                    >
                      <item.icon className="w-4 h-4 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <span className="text-sm truncate block">{item.name}</span>
                        {item.subtitle && (
                          <span className="text-xs text-gray-400 dark:text-gray-500 truncate block">
                            {item.subtitle}
                          </span>
                        )}
                      </div>
                      {isSelected && <ArrowRight className="w-4 h-4 flex-shrink-0 opacity-50" />}
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hints */}
        <div className="flex items-center gap-4 px-4 py-2 border-t border-gray-200/50 dark:border-gray-700/50 text-xs text-gray-400">
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">↑↓</kbd> 이동
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">↵</kbd> 선택
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">esc</kbd> 닫기
          </span>
        </div>
      </div>

      <style>{`
        @keyframes commandPaletteIn {
          from {
            opacity: 0;
            transform: scale(0.95);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }
      `}</style>
    </div>
  )
}
