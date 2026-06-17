import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, Mail, Lock, AlertCircle, Shield, KeyRound, ArrowLeft, CheckCircle } from 'lucide-react'
import clsx from 'clsx'
import { useAuth } from '../contexts/AuthContext'

type View = 'login' | 'forgotPassword' | 'resetPassword'

export default function Login() {
  const [view, setView] = useState<View>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const { login, forgotPassword, confirmForgotPassword } = useAuth()
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      const message = err instanceof Error ? err.message : '오류가 발생했습니다'

      if (message.includes('Incorrect username or password')) {
        setError('이메일 또는 비밀번호가 올바르지 않습니다')
      } else if (message.includes('Password attempts exceeded')) {
        setError('로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.')
      } else {
        setError(message)
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      await forgotPassword(email)
      setSuccess('인증 코드가 이메일로 전송되었습니다.')
      setView('resetPassword')
    } catch (err) {
      const message = err instanceof Error ? err.message : '오류가 발생했습니다'
      if (message.includes('LimitExceededException')) {
        setError('요청 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.')
      } else if (message.includes('UserNotFoundException')) {
        setError('등록되지 않은 이메일입니다.')
      } else {
        setError(message)
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      await confirmForgotPassword(email, code, newPassword)
      setSuccess('비밀번호가 변경되었습니다. 새 비밀번호로 로그인하세요.')
      setPassword('')
      setCode('')
      setNewPassword('')
      setView('login')
    } catch (err) {
      const message = err instanceof Error ? err.message : '오류가 발생했습니다'
      if (message.includes('CodeMismatchException') || message.includes('code')) {
        setError('인증 코드가 올바르지 않습니다.')
      } else if (message.includes('ExpiredCodeException')) {
        setError('인증 코드가 만료되었습니다. 다시 요청해주세요.')
      } else if (message.includes('InvalidPasswordException') || message.includes('password')) {
        setError('비밀번호는 8자 이상, 대/소문자, 숫자, 특수문자를 포함해야 합니다.')
      } else {
        setError(message)
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const goToForgotPassword = () => {
    setError('')
    setSuccess('')
    setView('forgotPassword')
  }

  const goToLogin = () => {
    setError('')
    setSuccess('')
    setCode('')
    setNewPassword('')
    setView('login')
  }

  return (
    <div className="relative min-h-screen bg-gradient-to-br from-primary-50 via-white to-teal-50 dark:from-gray-900 dark:via-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      {/* Decorative background pattern */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-primary-200/30 dark:bg-primary-900/20 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-teal-200/20 dark:bg-teal-900/10 rounded-full blur-3xl" />
      </div>
      <div className="relative w-full max-w-md">
        {/* Logo & Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-primary-500 to-primary-700 rounded-2xl mb-4 shadow-lg shadow-primary-500/25">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Agentic SOC</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">Amazon Bedrock AgentCore 기반 보안 운영</p>
        </div>

        {/* Auth Card */}
        <div className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-xl rounded-2xl shadow-xl border border-white/20 dark:border-gray-700/50 p-8">
          {/* Header */}
          <div className="flex items-center gap-2 mb-6">
            {view === 'login' ? (
              <>
                <Shield className="w-5 h-5 text-primary-600" />
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">로그인</h2>
              </>
            ) : (
              <>
                <button onClick={goToLogin} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors">
                  <ArrowLeft className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                </button>
                <KeyRound className="w-5 h-5 text-primary-600" />
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                  {view === 'forgotPassword' ? '비밀번호 찾기' : '비밀번호 재설정'}
                </h2>
              </>
            )}
          </div>

          {/* Success Message */}
          {success && (
            <div className="mb-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg flex items-start gap-2">
              <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-green-700">{success}</p>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          {/* Login Form */}
          {view === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">이메일</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white/50 dark:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white dark:placeholder-gray-400 transition-all duration-200"
                    placeholder="email@example.com"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">비밀번호</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white/50 dark:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white dark:placeholder-gray-400 transition-all duration-200"
                    placeholder="********"
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={isSubmitting}
                className={clsx(
                  'w-full py-2.5 rounded-xl font-medium transition-all duration-200 flex items-center justify-center gap-2',
                  isSubmitting
                    ? 'bg-primary-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white shadow-lg shadow-primary-600/25 hover:shadow-primary-700/30'
                )}
              >
                {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
                로그인
              </button>
              <button
                type="button"
                onClick={goToForgotPassword}
                className="w-full text-sm text-primary-600 hover:text-primary-700 hover:underline"
              >
                비밀번호를 잊으셨나요?
              </button>
            </form>
          )}

          {/* Forgot Password Form — request code */}
          {view === 'forgotPassword' && (
            <form onSubmit={handleForgotPassword} className="space-y-4">
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                가입한 이메일을 입력하면 인증 코드가 전송됩니다.
              </p>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">이메일</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white/50 dark:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white dark:placeholder-gray-400 transition-all duration-200"
                    placeholder="email@example.com"
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={isSubmitting}
                className={clsx(
                  'w-full py-2.5 rounded-xl font-medium transition-all duration-200 flex items-center justify-center gap-2',
                  isSubmitting
                    ? 'bg-primary-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white shadow-lg shadow-primary-600/25 hover:shadow-primary-700/30'
                )}
              >
                {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
                인증 코드 전송
              </button>
            </form>
          )}

          {/* Reset Password Form — code + new password */}
          {view === 'resetPassword' && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
                <strong>{email}</strong>로 전송된 인증 코드와 새 비밀번호를 입력하세요.
              </p>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">인증 코드</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
                  <input
                    type="text"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white/50 dark:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white dark:placeholder-gray-400 transition-all duration-200"
                    placeholder="123456"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">새 비밀번호</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400 dark:text-gray-500" />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 dark:border-gray-600 rounded-xl bg-white/50 dark:bg-gray-700/50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent dark:text-white dark:placeholder-gray-400 transition-all duration-200"
                    placeholder="새 비밀번호 (8자 이상)"
                    required
                    minLength={8}
                  />
                </div>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">대/소문자, 숫자, 특수문자 포함 8자 이상</p>
              </div>
              <button
                type="submit"
                disabled={isSubmitting}
                className={clsx(
                  'w-full py-2.5 rounded-xl font-medium transition-all duration-200 flex items-center justify-center gap-2',
                  isSubmitting
                    ? 'bg-primary-400 cursor-not-allowed'
                    : 'bg-gradient-to-r from-primary-600 to-primary-700 hover:from-primary-700 hover:to-primary-800 text-white shadow-lg shadow-primary-600/25 hover:shadow-primary-700/30'
                )}
              >
                {isSubmitting && <Loader2 className="w-4 h-4 animate-spin" />}
                비밀번호 변경
              </button>
              <button
                type="button"
                onClick={() => { setError(''); setSuccess(''); setView('forgotPassword') }}
                className="w-full text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:underline"
              >
                인증 코드 다시 받기
              </button>
            </form>
          )}

          <div className="mt-6 pt-6 border-t dark:border-gray-700">
            <p className="text-center text-sm text-gray-500 dark:text-gray-400">
              계정은 관리자에게 문의하세요
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-gray-400 dark:text-gray-500 mt-6">
          Powered by Amazon Bedrock AgentCore
        </p>
      </div>
    </div>
  )
}
