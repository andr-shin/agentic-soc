import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import {
  signIn,
  signUp,
  signOut,
  confirmSignUp,
  resetPassword,
  confirmResetPassword,
  getCurrentUser,
  fetchAuthSession,
  AuthUser,
} from 'aws-amplify/auth'

interface User {
  userId: string
  email: string
}

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  isAuthEnabled: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<{ needsConfirmation: boolean }>
  confirmRegistration: (email: string, code: string) => Promise<void>
  forgotPassword: (email: string) => Promise<void>
  confirmForgotPassword: (email: string, code: string, newPassword: string) => Promise<void>
  logout: () => Promise<void>
  getAuthToken: () => Promise<string | null>
  getAccessToken: () => Promise<string | null>
}

const AuthContext = createContext<AuthContextType | null>(null)

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
  isAuthEnabled?: boolean
}

export function AuthProvider({ children, isAuthEnabled = true }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    if (!isAuthEnabled) {
      setIsLoading(false)
      return
    }
    checkUser()
  }, [isAuthEnabled])

  async function checkUser() {
    try {
      const currentUser: AuthUser = await getCurrentUser()
      const session = await fetchAuthSession()
      const email = session.tokens?.idToken?.payload?.email as string || ''

      setUser({
        userId: currentUser.userId,
        email: email,
      })
    } catch {
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }

  async function login(email: string, password: string) {
    const result = await signIn({ username: email, password })

    if (result.isSignedIn) {
      await checkUser()
    } else if (result.nextStep.signInStep === 'CONFIRM_SIGN_UP') {
      throw new Error('CONFIRM_SIGN_UP')
    }
  }

  async function register(email: string, password: string) {
    const result = await signUp({
      username: email,
      password,
      options: {
        userAttributes: {
          email,
        },
      },
    })

    return {
      needsConfirmation: !result.isSignUpComplete,
    }
  }

  async function confirmRegistration(email: string, code: string) {
    await confirmSignUp({
      username: email,
      confirmationCode: code,
    })
  }

  async function forgotPassword(email: string) {
    await resetPassword({ username: email })
  }

  async function confirmForgotPassword(email: string, code: string, newPassword: string) {
    await confirmResetPassword({ username: email, confirmationCode: code, newPassword })
  }

  async function logout() {
    await signOut()
    setUser(null)
  }

  async function getAuthToken(): Promise<string | null> {
    if (!isAuthEnabled) return null

    try {
      const session = await fetchAuthSession()
      return session.tokens?.idToken?.toString() || null
    } catch {
      return null
    }
  }

  async function getAccessToken(): Promise<string | null> {
    if (!isAuthEnabled) return null

    try {
      const session = await fetchAuthSession()
      return session.tokens?.accessToken?.toString() || null
    } catch {
      return null
    }
  }

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated: !!user,
    isAuthEnabled,
    login,
    register,
    confirmRegistration,
    forgotPassword,
    confirmForgotPassword,
    logout,
    getAuthToken,
    getAccessToken,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
