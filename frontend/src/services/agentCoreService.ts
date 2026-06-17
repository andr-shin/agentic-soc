/**
 * AgentCore Direct SSE Streaming Service (v7.0)
 *
 * Browser connects directly to AgentCore Runtime endpoint via JWT auth.
 * SSE format: "data: {json}\n\n" from BedrockAgentCoreApp.
 * No Lambda intermediary for chat requests.
 */

export interface StreamCallbacks {
  onStart?: (conversationId: string) => void
  onText?: (chunk: string) => void
  onTool?: (toolName: string) => void
  onThinking?: (content: string) => void
  onMetadata?: (data: { tool_count: number; tool_names?: string[]; thinking: string }) => void
  onDone?: (conversationId: string) => void
  onError?: (error: string) => void
}

export async function streamChatFromAgentCore(
  endpointUrl: string,
  accessToken: string,
  message: string,
  conversationId: string | null,
  modelId: string,
  sessionId: string,
  callbacks: StreamCallbacks,
  signal?: AbortSignal,
  userId?: string | null
): Promise<void> {
  const response = await fetch(endpointUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
    },
    body: JSON.stringify({
      message,
      conversation_id: conversationId,
      model_id: modelId,
      ...(userId ? { user_id: userId } : {}),
    }),
    signal,
  })

  if (!response.ok) {
    const errText = await response.text().catch(() => '')
    throw new Error(`AgentCore error: ${response.status} ${errText}`)
  }

  const reader = response.body?.getReader()
  if (!reader) throw new Error('No response body')

  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })

    // Parse SSE format: "data: {json}\n\n"
    const parts = buffer.split('\n\n')
    buffer = parts.pop() || ''

    for (const part of parts) {
      const trimmed = part.trim()
      if (!trimmed) continue

      // Extract data from "data: {json}" format
      let jsonStr = trimmed
      if (trimmed.startsWith('data: ')) {
        jsonStr = trimmed.slice(6)
      }

      try {
        // BedrockAgentCoreApp wraps yields in safe_serialize,
        // which double-encodes strings — so the outer parse gives a string
        let event = JSON.parse(jsonStr)
        if (typeof event === 'string') {
          event = JSON.parse(event)
        }

        switch (event.event) {
          case 'pong':
            // Warm-up response, ignore
            break
          case 'start':
            callbacks.onStart?.(event.data?.conversation_id || '')
            break
          case 'text':
            callbacks.onText?.(event.data?.content || '')
            break
          case 'tool':
            callbacks.onTool?.(event.data?.name || '')
            break
          case 'thinking':
            callbacks.onThinking?.(event.data?.content || '')
            break
          case 'metadata':
            callbacks.onMetadata?.(event.data)
            break
          case 'done':
            callbacks.onDone?.(event.data?.conversation_id || '')
            break
          case 'error':
            callbacks.onError?.(event.data?.message || 'Unknown error')
            break
        }
      } catch {
        // JSON parse failure — partial data, ignore
      }
    }
  }

  // Process remaining buffer
  if (buffer.trim()) {
    let jsonStr = buffer.trim()
    if (jsonStr.startsWith('data: ')) {
      jsonStr = jsonStr.slice(6)
    }
    try {
      let event = JSON.parse(jsonStr)
      if (typeof event === 'string') {
        event = JSON.parse(event)
      }
      switch (event.event) {
        case 'done':
          callbacks.onDone?.(event.data?.conversation_id || '')
          break
        case 'error':
          callbacks.onError?.(event.data?.message || '')
          break
        case 'text':
          callbacks.onText?.(event.data?.content || '')
          break
      }
    } catch {
      // ignore
    }
  }
}
