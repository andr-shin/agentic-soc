/**
 * AgentCore Streaming Chat Hook (v7.0)
 *
 * Direct browser → AgentCore Runtime SSE streaming.
 * Uses accessToken (Cognito) for CustomJWTAuthorizer (allowedClients = client_id).
 * Includes warm-up ping for microVM pre-allocation.
 */

import { useCallback, useRef } from 'react'
import { useConfig } from './useApi'
import { useAuth } from '../contexts/AuthContext'
import { streamChatFromAgentCore, StreamCallbacks } from '../services/agentCoreService'

function extractSubFromJwt(token: string): string | null {
  try {
    const payload = token.split('.')[1]
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
    return decoded.sub || null
  } catch {
    return null
  }
}

export function useAgentCoreChat() {
  const { data: config } = useConfig()
  const { getAccessToken } = useAuth()
  const abortRef = useRef<AbortController | null>(null)

  const isAvailable = !!(config?.host_agent_url)

  // Warm-up ping — call on Chat tab entry to pre-allocate microVM
  const warmUp = useCallback(async () => {
    if (!config?.host_agent_url) return
    try {
      const token = await getAccessToken()
      if (!token) return
      await fetch(config.host_agent_url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ type: 'ping' }),
      }).catch(() => {})  // Fire-and-forget
    } catch {
      // Warm-up failure is not critical
    }
  }, [config?.host_agent_url, getAccessToken])

  const streamChat = useCallback(async (
    message: string,
    conversationId: string | null,
    modelId: string,
    sessionId: string,
    callbacks: StreamCallbacks,
    signal?: AbortSignal
  ) => {
    if (!config?.host_agent_url) throw new Error('AgentCore not configured')
    const token = await getAccessToken()
    if (!token) throw new Error('No access token available')

    const userId = extractSubFromJwt(token)

    abortRef.current = new AbortController()
    const effectiveSignal = signal || abortRef.current.signal

    return streamChatFromAgentCore(
      config.host_agent_url,
      token,
      message,
      conversationId,
      modelId,
      sessionId,
      callbacks,
      effectiveSignal,
      userId
    )
  }, [config?.host_agent_url, getAccessToken])

  const abort = useCallback(() => {
    abortRef.current?.abort()
  }, [])

  return { streamChat, isAvailable, abort, warmUp }
}
