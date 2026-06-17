import { Routes, Route, Navigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Chat from './pages/Chat'
import Findings from './pages/Findings'
import LogExplorer from './pages/LogExplorer'
import TaskBoard from './pages/TaskBoard'
import Readiness from './pages/Readiness'
import Login from './pages/Login'
import { useAuth } from './contexts/AuthContext'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, isAuthEnabled } = useAuth()

  // If auth is disabled, allow access
  if (!isAuthEnabled) {
    return <>{children}</>
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-12 h-12 text-primary-600 animate-spin" />
          <p className="text-gray-500 dark:text-gray-400">로딩 중...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  const { isAuthenticated, isAuthEnabled } = useAuth()

  return (
    <Routes>
      <Route
        path="/login"
        element={
          isAuthEnabled && isAuthenticated ? (
            <Navigate to="/" replace />
          ) : (
            <Login />
          )
        }
      />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/chat" element={<Chat />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/readiness" element={<Readiness />} />
                <Route path="/logs" element={<LogExplorer />} />
                <Route path="/tasks" element={<TaskBoard />} />
                {/* 알 수 없는 경로는 대시보드로 — 빈 화면 방지 */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
