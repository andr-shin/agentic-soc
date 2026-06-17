import { useState, useRef, useEffect, useCallback } from 'react'
import { MessageSquare, X, Send, Loader2, StopCircle } from 'lucide-react'
import { useAgentCoreChat } from '../hooks/useAgentCoreChat'
import { useAuth } from '../contexts/AuthContext'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
}

export default function FloatingChat() {
  const [isOpen, setIsOpen] = useState(false)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [hasUnread, setHasUnread] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const { streamChat, isAvailable, abort } = useAgentCoreChat()
  const { isAuthEnabled } = useAuth()
  const [sessionId] = useState(() => crypto.randomUUID())

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 100) + 'px'
    }
  }, [input])

  const handleSend = useCallback(async () => {
    const trimmed = input.trim()
    if (!trimmed || isStreaming) return

    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: trimmed,
    }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setIsStreaming(true)

    const assistantId = crypto.randomUUID()
    let accumulated = ''

    setMessages(prev => [
      ...prev,
      { id: assistantId, role: 'assistant', content: '' },
    ])

    try {
      await streamChat(trimmed, null, 'global.anthropic.claude-sonnet-4-6', sessionId, {
        onText: (chunk: string) => {
          accumulated += chunk
          setMessages(prev =>
            prev.map(m => (m.id === assistantId ? { ...m, content: accumulated } : m))
          )
        },
        onDone: () => {
          setIsStreaming(false)
          if (!isOpen) setHasUnread(true)
        },
        onError: (err: string) => {
          setMessages(prev =>
            prev.map(m =>
              m.id === assistantId
                ? { ...m, content: accumulated || `오류가 발생했습니다: ${err}` }
                : m
            )
          )
          setIsStreaming(false)
        },
        onStart: () => {},
        onTool: () => {},
        onThinking: () => {},
        onMetadata: () => {},
      })
    } catch (err) {
      setMessages(prev =>
        prev.map(m =>
          m.id === assistantId
            ? { ...m, content: '연결에 실패했습니다. 다시 시도해주세요.' }
            : m
        )
      )
      setIsStreaming(false)
    }
  }, [input, isStreaming, streamChat, sessionId, isOpen])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const toggleOpen = () => {
    setIsOpen(prev => !prev)
    setHasUnread(false)
  }

  return (
    <>
      {/* Chat Panel */}
      <div
        className={`fixed bottom-20 right-6 z-30 w-96 h-[500px] rounded-2xl shadow-2xl overflow-hidden flex flex-col
          backdrop-blur-xl bg-white/90 dark:bg-gray-800/90 border border-gray-200/50 dark:border-gray-700/50
          transition-all duration-300 ease-out origin-bottom-right
          ${isOpen ? 'scale-100 opacity-100 pointer-events-auto' : 'scale-95 opacity-0 pointer-events-none translate-y-4'}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-primary-600 to-primary-700 text-white flex-shrink-0">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-5 h-5" />
            <span className="font-medium text-sm">AI 어시스턴트</span>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="p-1 hover:bg-white/20 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <div className="w-12 h-12 bg-primary-100 dark:bg-primary-900/30 rounded-full flex items-center justify-center mb-3">
                <MessageSquare className="w-6 h-6 text-primary-600 dark:text-primary-400" />
              </div>
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                무엇을 도와드릴까요?
              </p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                보안 finding, 위협 헌팅, 대응에 대해 질문하세요
              </p>
            </div>
          )}

          {messages.map(msg => (
            <div
              key={msg.id}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-2xl px-3 py-2 text-sm whitespace-pre-wrap break-words ${
                  msg.role === 'user'
                    ? 'bg-primary-600 text-white rounded-br-md'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-bl-md'
                }`}
              >
                {msg.content || (
                  <span className="flex items-center gap-1.5 text-gray-400">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    생각 중...
                  </span>
                )}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="flex-shrink-0 border-t border-gray-200/50 dark:border-gray-700/50 px-3 py-2">
          {!isAvailable && isAuthEnabled ? (
            <div className="text-xs text-center text-gray-400 py-2">
              AI 서비스에 연결할 수 없습니다
            </div>
          ) : (
            <div className="flex items-end gap-2">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="메시지를 입력하세요..."
                rows={1}
                className="flex-1 resize-none bg-gray-100 dark:bg-gray-700 text-sm text-gray-900 dark:text-white rounded-xl px-3 py-2 outline-none focus:ring-2 focus:ring-primary-500/50 placeholder-gray-400 max-h-[100px]"
              />
              {isStreaming ? (
                <button
                  onClick={abort}
                  className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-xl transition-colors flex-shrink-0"
                >
                  <StopCircle className="w-5 h-5" />
                </button>
              ) : (
                <button
                  onClick={handleSend}
                  disabled={!input.trim()}
                  className="p-2 text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-xl transition-colors disabled:opacity-30 flex-shrink-0"
                >
                  <Send className="w-5 h-5" />
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* FAB */}
      <button
        onClick={toggleOpen}
        className={`fixed bottom-6 right-6 z-30 w-14 h-14 rounded-full bg-primary-600 hover:bg-primary-700 text-white shadow-lg hover:shadow-xl
          flex items-center justify-center transition-all duration-200 hover:scale-105 active:scale-95
          ${isOpen ? 'rotate-0' : ''}`}
      >
        {isOpen ? (
          <X className="w-6 h-6" />
        ) : (
          <>
            <MessageSquare className="w-6 h-6" />
            {hasUnread && (
              <span className="absolute top-1 right-1 w-3 h-3 bg-red-500 rounded-full border-2 border-white dark:border-gray-900" />
            )}
          </>
        )}
      </button>
    </>
  )
}
