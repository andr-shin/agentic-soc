import { ReactNode, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  MessageSquare,
  Shield,
  ShieldCheck,
  ClipboardCheck,
  Terminal,
  LogOut,
  User,
  Moon,
  Sun,
  Menu,
  X,
} from 'lucide-react'
import clsx from 'clsx'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'
import { useHealthCheck, useTasks } from '../hooks/useApi'
import CommandPalette from './CommandPalette'
import FloatingChat from './FloatingChat'

interface LayoutProps {
  children: ReactNode
}

const navigationGroups = [
  {
    label: '모니터링',
    items: [
      { name: '대시보드', href: '/', icon: LayoutDashboard },
      { name: 'Findings', href: '/findings', icon: Shield },
      { name: 'Log Explorer', href: '/logs', icon: Terminal },
    ],
  },
  {
    label: '대응',
    items: [
      { name: '대응 (Tasks)', href: '/tasks', icon: ShieldCheck },
    ],
  },
  {
    label: '인텔리전스',
    items: [
      { name: '채팅', href: '/chat', icon: MessageSquare },
    ],
  },
  {
    label: '온보딩',
    items: [
      { name: '온보딩 Status', href: '/readiness', icon: ClipboardCheck },
    ],
  },
]

export default function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout, isAuthEnabled } = useAuth()
  const { isDark, toggleTheme } = useTheme()
  // 미해결 finding 수는 /api/health 전체 집계(GROUP BY) — useFindings는 100건 제한이라 99에 갇힘(대시보드와 동일 이유).
  const { data: healthData } = useHealthCheck()
  const activeFindingCount = (healthData as any)?.open_findings ?? 0
  const { data: tasksData } = useTasks('pending_approval')
  const pendingTaskCount = ((tasksData as any[]) || []).length

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      {/* Mobile header */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-40 flex items-center gap-3 px-4 py-3 bg-white dark:bg-gray-800 shadow-sm">
        <button onClick={() => setSidebarOpen(true)} className="p-1">
          <Menu className="w-6 h-6 text-gray-700 dark:text-gray-300" />
        </button>
        <Shield className="w-6 h-6 text-primary-600" />
        <h1 className="text-lg font-bold text-gray-900 dark:text-white">Agentic SOC</h1>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-black/50"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={clsx(
        'fixed inset-y-0 left-0 w-64 bg-white dark:bg-gradient-to-b dark:from-gray-800 dark:to-gray-900 shadow-lg z-50 transition-transform duration-200',
        'lg:translate-x-0',
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      )}>
        {/* Logo + Close button */}
        <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 dark:border-gray-700" style={{ borderImage: 'linear-gradient(to right, transparent, rgba(107,114,128,0.3), transparent) 1' }}>
          <Shield className="w-8 h-8 text-primary-600" />
          <div className="flex-1">
            <h1 className="text-xl font-bold text-gray-900 dark:text-white">Agentic SOC</h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">Powered by AgentCore</p>
          </div>
          <button onClick={() => setSidebarOpen(false)} className="lg:hidden p-1">
            <X className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="px-4 py-6 space-y-4">
          {navigationGroups.map((group) => (
            <div key={group.label}>
              <p className="px-4 mb-1 text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = location.pathname === item.href
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      onClick={() => setSidebarOpen(false)}
                      className={clsx(
                        'relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                        isActive
                          ? 'bg-primary-50 text-primary-700 font-medium dark:bg-primary-700/20 dark:text-primary-100'
                          : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white'
                      )}
                    >
                      {isActive && (
                        <span className="absolute left-0 top-2 bottom-2 w-[3px] bg-primary-500 rounded-r" />
                      )}
                      <item.icon className="w-5 h-5" />
                      {item.name}
                      {item.name === 'Findings' && activeFindingCount > 0 && (
                        <span className="ml-auto inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 text-xs font-bold text-white bg-red-500 rounded-full">
                          {activeFindingCount > 999 ? '999+' : activeFindingCount}
                        </span>
                      )}
                      {item.name === '대응 (Tasks)' && pendingTaskCount > 0 && (
                        <span className="ml-auto inline-flex items-center justify-center w-5 h-5 text-xs font-bold text-white bg-yellow-500 rounded-full">
                          {pendingTaskCount}
                        </span>
                      )}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Theme Toggle + User Info & Logout */}
        <div className="absolute bottom-0 left-0 right-0 border-t dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
          {/* Keyboard shortcut hint */}
          <div className="px-4 py-2">
            <kbd className="text-xs text-gray-400 dark:text-gray-500">&#8984;K</kbd>
            <span className="text-xs text-gray-400 dark:text-gray-500 ml-1">빠른 검색</span>
          </div>
          {/* Theme Toggle */}
          <div className="px-4 pt-1">
            <button
              onClick={toggleTheme}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              {isDark ? '라이트 모드' : '다크 모드'}
            </button>
          </div>
          {isAuthEnabled && user ? (
            <div className="p-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center">
                  <User className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {user.email}
                  </p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                <LogOut className="w-4 h-4" />
                로그아웃
              </button>
            </div>
          ) : (
            <div className="p-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-500 rounded-full status-pulse" />
                <span className="text-sm text-gray-600 dark:text-gray-400">시스템 정상</span>
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main className="lg:pl-64 pt-14 lg:pt-0">
        <div className="p-4 lg:p-8">
          {children}
        </div>
      </main>

      <CommandPalette />
      {location.pathname !== '/chat' && <FloatingChat />}
    </div>
  )
}
