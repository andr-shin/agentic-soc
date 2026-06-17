import { useState, useRef, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Send, Bot, User, Loader2, Sparkles, Plus, MessageSquare, Trash2, Clock, ChevronDown, Brain, Search, Crosshair, Terminal, Shield, ShieldCheck, FileText, Menu, X, Copy, Check, Download } from 'lucide-react'
import clsx from 'clsx'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { marked } from 'marked'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import sql from 'react-syntax-highlighter/dist/esm/languages/hljs/sql'
import bash from 'react-syntax-highlighter/dist/esm/languages/hljs/bash'
import python from 'react-syntax-highlighter/dist/esm/languages/hljs/python'
import { githubGist } from 'react-syntax-highlighter/dist/esm/styles/hljs'
import { atomOneDark } from 'react-syntax-highlighter/dist/esm/styles/hljs'

SyntaxHighlighter.registerLanguage('json', json)
SyntaxHighlighter.registerLanguage('sql', sql)
SyntaxHighlighter.registerLanguage('bash', bash)
SyntaxHighlighter.registerLanguage('python', python)
import { useConversations, useConversation, useDeleteConversation, useConfig } from '../hooks/useApi'
import { useAgentCoreChat } from '../hooks/useAgentCoreChat'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
  isProcessing?: boolean  // For loading state (spinner + text)
  isStreaming?: boolean   // For partial text streaming (show content + typing indicator)
  thinking?: string
  toolCallCount?: number
  toolNames?: string[]
}

interface LocalConversation {
  id: string
  title: string
  messages: Message[]
  createdAt: Date
  updatedAt: Date
}

const STORAGE_KEY = 'agentic-soc-chat-conversations'

const AVAILABLE_MODELS = [
  { id: 'global.anthropic.claude-sonnet-4-6', label: 'Sonnet 4.6', description: '기본' },
  { id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0', label: 'Sonnet 4.5', description: '' },
  { id: 'global.anthropic.claude-haiku-4-5-20251001-v1:0', label: 'Haiku 4.5', description: '빠름' },
  { id: 'global.anthropic.claude-opus-4-5-20251101-v1:0', label: 'Opus 4.5', description: '' },
  { id: 'global.anthropic.claude-opus-4-6-v1', label: 'Opus 4.6', description: '고성능' },
]

const DEFAULT_MODEL_ID = AVAILABLE_MODELS[0].id

const suggestedQuestions = [
  'Critical finding을 조사해줘',
  'MFA 미설정 IAM 사용자를 헌팅해줘',
  '최근 REJECT된 VPC Flow 로그를 분석해줘',
  '보안 컴플라이언스 리포트를 작성해줘',
]

// Keyed by the `icon` string returned from /api/config
const AGENT_ICONS: Record<string, React.ComponentType<any>> = {
  search: Search, crosshair: Crosshair, terminal: Terminal,
  shield: ShieldCheck, 'file-text': FileText,
}

// Keyed by agent `id` from /api/config (security sub-agents)
const AGENT_COLORS: Record<string, string> = {
  investigation: 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/20 dark:text-blue-300 dark:border-blue-800',
  hunting: 'bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-900/20 dark:text-purple-300 dark:border-purple-800',
  logquery: 'bg-cyan-50 text-cyan-700 border-cyan-200 dark:bg-cyan-900/20 dark:text-cyan-300 dark:border-cyan-800',
  response: 'bg-red-50 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-300 dark:border-red-800',
  report: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-300 dark:border-emerald-800',
}

function loadConversations(): LocalConversation[] {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) {
      const parsed = JSON.parse(saved)
      return parsed.map((conv: LocalConversation) => ({
        ...conv,
        createdAt: new Date(conv.createdAt),
        updatedAt: new Date(conv.updatedAt),
        messages: conv.messages.map(msg => ({
          ...msg,
          timestamp: new Date(msg.timestamp)
        }))
      }))
    }
  } catch (e) {
    console.error('Failed to load conversations:', e)
  }
  return []
}

function saveConversations(conversations: LocalConversation[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(conversations))
  } catch (e) {
    console.error('Failed to save conversations:', e)
  }
}

function generateTitle(message: string): string {
  const maxLength = 30
  const title = message.trim()
  if (title.length <= maxLength) return title
  return title.substring(0, maxLength) + '...'
}

function createNewConversation(): LocalConversation {
  return {
    id: Date.now().toString(),
    title: '새 대화',
    messages: [{
      id: '1',
      role: 'assistant',
      content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
      timestamp: new Date(),
    }],
    createdAt: new Date(),
    updatedAt: new Date(),
  }
}

export default function Chat() {
  const { isAuthEnabled } = useAuth()
  const { isDark } = useTheme()
  const { data: config } = useConfig()
  const [searchParams, setSearchParams] = useSearchParams()

  // Server-side conversation data (when auth is enabled)
  const { data: serverConversations, refetch: refetchConversations } = useConversations()
  const deleteConversationMutation = useDeleteConversation()

  // Current active conversation
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null)
  const [isNewConversation, setIsNewConversation] = useState(true)

  // Fetch conversation detail from server
  const { data: conversationDetail, isLoading: isLoadingDetail } = useConversation(isAuthEnabled ? activeConversationId : null)

  // Local conversations (fallback when auth is disabled)
  const [localConversations, setLocalConversations] = useState<LocalConversation[]>(() => {
    return loadConversations()
  })

  const [currentMessages, setCurrentMessages] = useState<Message[]>([{
    id: '1',
    role: 'assistant',
    content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
    timestamp: new Date(),
  }])
  const [currentTitle, setCurrentTitle] = useState<string>('새 대화')

  // Model selection
  const [selectedModel, setSelectedModel] = useState(DEFAULT_MODEL_ID)
  const [isModelDropdownOpen, setIsModelDropdownOpen] = useState(false)

  // Input and loading state
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const isUserNearBottomRef = useRef(true)

  // Processing state
  const [processingMessageId, setProcessingMessageId] = useState<string | null>(null)

  // Ref to prevent message-loading useEffect from overwriting messages
  // during/after async task processing
  const skipMessageReloadRef = useRef(false)

  // Session ID for AgentCore (persists across messages in the same tab)
  const [sessionId] = useState(() => crypto.randomUUID())

  // Mobile sidebar toggle
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const { streamChat: agentCoreStreamChat, isAvailable: isAgentCoreAvailable, abort: abortChat, warmUp } = useAgentCoreChat()

  // Parse server timestamp (UTC ISO string without 'Z') to proper Date
  const parseServerTime = (ts: string | undefined | null) => {
    if (!ts) return null
    return ts.endsWith('Z') || ts.includes('+') ? new Date(ts) : new Date(ts + 'Z')
  }

  // Get conversation list based on auth status, sorted by most recent first
  const conversations = isAuthEnabled
    ? (serverConversations || []).map(c => ({
        id: c.conversation_id,
        title: c.title,
        updatedAt: parseServerTime(c.updated_at),
      })).sort((a, b) => (b.updatedAt?.getTime() ?? 0) - (a.updatedAt?.getTime() ?? 0))
    : localConversations.map(c => ({
        id: c.id,
        title: c.title,
        updatedAt: c.updatedAt,
      })).sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())

  // Initialize with first conversation (only if not creating a new one)
  useEffect(() => {
    if (!activeConversationId && !isNewConversation && conversations.length > 0) {
      setActiveConversationId(conversations[0].id)
    }
  }, [conversations, activeConversationId, isNewConversation])

  // Track which conversation's messages have been successfully loaded
  const loadedConversationIdRef = useRef<string | null>(null)

  // Warm-up ping on Chat tab mount (pre-allocate AgentCore microVM)
  useEffect(() => {
    warmUp()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Load messages when conversation changes or conversationDetail arrives
  useEffect(() => {
    // Skip if flagged (e.g., right after streaming completion)
    if (skipMessageReloadRef.current) {
      skipMessageReloadRef.current = false
      return
    }

    // Don't override messages while processing
    if (processingMessageId) return

    if (!activeConversationId) {
      loadedConversationIdRef.current = null
      setCurrentMessages([{
        id: '1',
        role: 'assistant',
        content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
        timestamp: new Date(),
      }])
      setCurrentTitle('새 대화')
      return
    }

    // Already loaded this conversation's messages — skip
    if (loadedConversationIdRef.current === activeConversationId) return

    if (isAuthEnabled) {
      const conv = conversations.find(c => c.id === activeConversationId)
      setCurrentTitle(conv?.title || '새 대화')

      if (isLoadingDetail) {
        // Still loading - show loading placeholder (don't mark as loaded yet)
        setCurrentMessages([{
          id: 'loading',
          role: 'assistant',
          content: '대화 이력을 불러오는 중...',
          timestamp: new Date(),
        }])
      } else if (conversationDetail && conversationDetail.conversation_id === activeConversationId && conversationDetail.messages && conversationDetail.messages.length > 0) {
        // Data arrived and matches — load messages and mark as loaded
        const msgs: Message[] = conversationDetail.messages.map((m, idx) => ({
          id: `server-${idx}`,
          role: m.role,
          content: m.content,
          timestamp: parseServerTime(m.timestamp) || new Date(),
        }))
        setCurrentMessages(msgs)
        if (conversationDetail.title) {
          setCurrentTitle(conversationDetail.title)
        }
        loadedConversationIdRef.current = activeConversationId
      } else if (!isLoadingDetail && (!conversationDetail || conversationDetail.conversation_id !== activeConversationId)) {
        // Not loading and no matching data yet — show loading placeholder
        setCurrentMessages([{
          id: 'loading',
          role: 'assistant',
          content: '대화 이력을 불러오는 중...',
          timestamp: new Date(),
        }])
      } else {
        // Empty conversation
        setCurrentMessages([{
          id: '1',
          role: 'assistant',
          content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?',
          timestamp: new Date(),
        }])
        loadedConversationIdRef.current = activeConversationId
      }
    } else {
      // Local storage mode
      const conv = localConversations.find(c => c.id === activeConversationId)
      if (conv) {
        setCurrentMessages(conv.messages)
        setCurrentTitle(conv.title)
      }
      loadedConversationIdRef.current = activeConversationId
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeConversationId, isAuthEnabled, conversationDetail, isLoadingDetail, processingMessageId])

  // Save local conversations whenever they change
  useEffect(() => {
    if (!isAuthEnabled) {
      saveConversations(localConversations)
    }
  }, [localConversations, isAuthEnabled])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  // Track whether user is near the bottom of the messages container
  const handleMessagesScroll = () => {
    const el = messagesContainerRef.current
    if (!el) return
    const threshold = 100
    isUserNearBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < threshold
  }

  // Only auto-scroll if user is already near the bottom
  useEffect(() => {
    if (isUserNearBottomRef.current) {
      scrollToBottom()
    }
  }, [currentMessages])

  // Handle URL query parameter for auto-input (e.g., from Dashboard Quick Actions)
  useEffect(() => {
    const q = searchParams.get('q')
    if (q) {
      setInput(q)
      // Clear the query param so it doesn't persist on refresh
      setSearchParams({}, { replace: true })
      // Focus the input
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }, [searchParams, setSearchParams])

  const handleNewConversation = () => {
    // Just show welcome state without creating a conversation entry
    // Conversation entry will be created when user sends the first message
    setSidebarOpen(false)
    setIsNewConversation(true)
    loadedConversationIdRef.current = null
    setActiveConversationId(null)
    setCurrentMessages([{
      id: '1',
      role: 'assistant',
      content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
      timestamp: new Date(),
    }])
    setCurrentTitle('새 대화')
  }

  const handleSelectConversation = (id: string) => {
    setSidebarOpen(false)
    setIsNewConversation(false)
    // Reset loaded ref so the useEffect will load the new conversation's messages
    if (id !== activeConversationId) {
      loadedConversationIdRef.current = null
    }
    setActiveConversationId(id)
  }

  const handleDeleteConversation = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()

    if (isAuthEnabled) {
      try {
        await deleteConversationMutation.mutateAsync(id)
        if (activeConversationId === id) {
          // Show welcome state instead of loading another conversation
          setIsNewConversation(true)
          setActiveConversationId(null)
          setCurrentMessages([{
            id: '1',
            role: 'assistant',
            content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
            timestamp: new Date(),
          }])
          setCurrentTitle('새 대화')
        }
        refetchConversations()
      } catch (error) {
        console.error('Failed to delete conversation:', error)
      }
    } else {
      setLocalConversations(prev => {
        const filtered = prev.filter(c => c.id !== id)
        if (filtered.length === 0 || activeConversationId === id) {
          // Show welcome state
          setIsNewConversation(true)
          setActiveConversationId(null)
          setCurrentMessages([{
            id: '1',
            role: 'assistant',
            content: '안녕하세요! Agentic SOC 보안 어시스턴트입니다. 무엇을 도와드릴까요?\n\n다음과 같은 질문을 하실 수 있습니다:\n- 보안 finding 조사 (GuardDuty/Security Hub)\n- 위협 헌팅 (IAM/네트워크/암호화 태세)\n- 로그 분석 (VPC Flow/CloudTrail)\n- 대응 조치 제안 (격리/차단/revoke)',
            timestamp: new Date(),
          }])
          setCurrentTitle('새 대화')
        }
        return filtered
      })
    }
  }

  // 메시지 본문 클립보드 복사 (마크다운 원문)
  const handleCopy = async (id: string, content: string) => {
    try {
      await navigator.clipboard.writeText(content)
      setCopiedId(id)
      setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1500)
    } catch (err) {
      console.error('클립보드 복사 실패:', err)
    }
  }

  // 리포트성 출력 감지 — 마크다운 제목(##) 다수 또는 리포트 키워드 + 표/섹션 구조
  const looksLikeReport = (content: string): boolean => {
    if (!content) return false
    const headingCount = (content.match(/^#{1,3}\s/gm) || []).length
    const hasTable = content.includes('|') && /\|.*\|/.test(content)
    const hasReportWord = /(리포트|보고서|Report|Executive Summary|요약|Findings|컴플라이언스)/i.test(content)
    return (headingCount >= 2 && content.length > 400) || (hasReportWord && (hasTable || headingCount >= 1))
  }

  // 리포트를 마크다운 파일로 다운로드
  const handleDownload = (content: string) => {
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
    const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-report-${ts}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // 리포트를 PDF로 — 마크다운을 스타일된 HTML로 렌더해 새 창에서 인쇄(브라우저의 'PDF로 저장').
  // 라이브러리 없이 OS 폰트로 한글까지 정상 렌더. 사용자가 인쇄 대화상자에서 PDF 선택.
  const handleDownloadPdf = (content: string) => {
    const html = marked.parse(content, { async: false }) as string
    const win = window.open('', '_blank')
    if (!win) { alert('팝업이 차단되었습니다. 팝업을 허용해 주세요.'); return }
    const dateStr = new Date().toLocaleString('ko-KR')
    win.document.write(`<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<title>Security Report</title>
<style>
  @page { margin: 18mm; }
  body { font-family: -apple-system, "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif;
         line-height: 1.6; color: #1a1a1a; max-width: 800px; margin: 0 auto; padding: 24px; }
  h1,h2,h3 { color: #111; margin-top: 1.4em; }
  h1 { border-bottom: 2px solid #ddd; padding-bottom: .3em; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: .9em; }
  th,td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background: #f4f4f4; }
  code { background: #f4f4f4; padding: 1px 5px; border-radius: 3px; font-size: .9em; }
  pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto; }
  pre code { background: none; padding: 0; }
  .footer { margin-top: 2em; padding-top: 1em; border-top: 1px solid #eee; color: #888; font-size: .8em; }
</style></head><body>
${html}
<div class="footer">Agentic SOC — 생성: ${dateStr}</div>
<script>window.onload = () => { window.print(); }</script>
</body></html>`)
    win.document.close()
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isLoading) return
    // Reset to auto-scroll when user sends a new message
    isUserNearBottomRef.current = true

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    }

    const isFirstMessage = currentMessages.filter(m => m.role === 'user').length === 0
    const newTitle = isFirstMessage ? generateTitle(input.trim()) : currentTitle

    const assistantMessageId = (Date.now() + 1).toString()
    const processingMessage: Message = {
      id: assistantMessageId,
      role: 'assistant',
      content: '분석 중...',
      timestamp: new Date(),
      isProcessing: true,
    }

    setCurrentMessages(prev => [...prev, userMessage, processingMessage])
    setCurrentTitle(newTitle)
    setInput('')
    // 전송 후 입력창 높이 초기화(auto-grow 리셋)
    if (inputRef.current) inputRef.current.style.height = 'auto'
    setIsLoading(true)
    setProcessingMessageId(assistantMessageId)

    let effectiveConversationId = activeConversationId

    if (!isAuthEnabled) {
      if (isNewConversation || !activeConversationId) {
        const newConvId = Date.now().toString()
        effectiveConversationId = newConvId
        const newConv: LocalConversation = {
          id: newConvId,
          title: newTitle,
          messages: [...currentMessages, userMessage, processingMessage],
          createdAt: new Date(),
          updatedAt: new Date(),
        }
        setLocalConversations(prev => [newConv, ...prev])
        setIsNewConversation(false)
        skipMessageReloadRef.current = true
        setActiveConversationId(newConvId)
      } else {
        setLocalConversations(prev => prev.map(conv => {
          if (conv.id !== activeConversationId) return conv
          return {
            ...conv,
            title: newTitle,
            messages: [...conv.messages, userMessage, processingMessage],
            updatedAt: new Date(),
          }
        }))
      }
    }

    // AgentCore direct SSE streaming (v7.0 — the only chat path)
    if (!isAgentCoreAvailable) {
      setCurrentMessages(prev => prev.map(msg =>
        msg.id === assistantMessageId
          ? { ...msg, content: 'AgentCore가 아직 설정되지 않았습니다. /api/config를 확인하세요.', isProcessing: false }
          : msg
      ))
      setIsLoading(false)
      setProcessingMessageId(null)
      return
    }

    let accumulatedText = ''
    let thinkingContent = ''
    let toolCallsMade = 0
    let toolNamesUsed: string[] = []
    let streamConversationId = activeConversationId || ''
    let currentToolName = ''

    try {
      await agentCoreStreamChat(
        userMessage.content,
        isAuthEnabled ? activeConversationId : null,
        selectedModel,
        sessionId,
        {
          onStart: (convId) => {
            streamConversationId = convId
          },
          onText: (chunk) => {
            accumulatedText += chunk
            setCurrentMessages(prev => prev.map(msg =>
              msg.id === assistantMessageId
                ? { ...msg, content: accumulatedText, isProcessing: false, isStreaming: true, toolCallCount: toolCallsMade || undefined }
                : msg
            ))
          },
          onTool: (toolName) => {
            currentToolName = toolName
            toolCallsMade += 1
            if (toolName && !toolNamesUsed.includes(toolName)) {
              toolNamesUsed = [...toolNamesUsed, toolName]
            }
            setCurrentMessages(prev => prev.map(msg =>
              msg.id === assistantMessageId && (msg.isProcessing || msg.isStreaming)
                ? { ...msg, content: accumulatedText || `${toolName} 실행 중...`, isProcessing: !accumulatedText, isStreaming: !!accumulatedText, toolCallCount: toolCallsMade, toolNames: toolNamesUsed }
                : msg
            ))
          },
          onThinking: (content) => {
            thinkingContent = content
            setCurrentMessages(prev => prev.map(msg =>
              msg.id === assistantMessageId
                ? { ...msg, thinking: content }
                : msg
            ))
          },
          onMetadata: (data) => {
            if (data.tool_count) toolCallsMade = data.tool_count
            if (data.tool_names && data.tool_names.length > 0) toolNamesUsed = data.tool_names
          },
          onDone: (convId) => {
            streamConversationId = convId || streamConversationId

            // Final update with all collected data
            setCurrentMessages(prev => prev.map(msg =>
              msg.id === assistantMessageId
                ? { ...msg, content: accumulatedText || '응답 없음.', thinking: thinkingContent, toolCallCount: toolCallsMade, toolNames: toolNamesUsed.length > 0 ? toolNamesUsed : undefined, isProcessing: false, isStreaming: false }
                : msg
            ))

            if (!isAuthEnabled) {
              setLocalConversations(prev => prev.map(conv => {
                if (conv.id !== effectiveConversationId) return conv
                return {
                  ...conv,
                  messages: conv.messages.map(msg =>
                    msg.id === assistantMessageId
                      ? { ...msg, content: accumulatedText, thinking: thinkingContent, toolCallCount: toolCallsMade, isProcessing: false, isStreaming: false }
                      : msg
                  ),
                  updatedAt: new Date(),
                }
              }))
            }

            skipMessageReloadRef.current = true
            setProcessingMessageId(null)
            setIsLoading(false)

            if (isAuthEnabled) {
              if (streamConversationId && !activeConversationId) {
                // Mark as loaded BEFORE setting activeConversationId
                // to prevent the message-loading useEffect from overwriting
                loadedConversationIdRef.current = streamConversationId
                skipMessageReloadRef.current = true
                setIsNewConversation(false)
                setActiveConversationId(streamConversationId)
              } else {
                // Existing conversation — also mark loaded to prevent reset
                loadedConversationIdRef.current = activeConversationId
              }
              refetchConversations()
            }
          },
          onError: (err) => {
            // Keep partial text if available, show error
            const errorContent = accumulatedText || `오류: ${err}`
            setCurrentMessages(prev => prev.map(msg =>
              msg.id === assistantMessageId
                ? { ...msg, content: errorContent, isProcessing: false, isStreaming: false }
                : msg
            ))
            skipMessageReloadRef.current = true
            setProcessingMessageId(null)
            setIsLoading(false)
          },
        }
      )
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e)
      const errorContent = accumulatedText || `오류: ${errorMsg}`
      setCurrentMessages(prev => prev.map(msg =>
        msg.id === assistantMessageId
          ? { ...msg, content: errorContent, isProcessing: false, isStreaming: false }
          : msg
      ))
      skipMessageReloadRef.current = true
      setProcessingMessageId(null)
      setIsLoading(false)
    }
  }

  const handleSuggestedQuestion = (question: string) => {
    setInput(question)
    inputRef.current?.focus()
  }

  const formatDate = (date: Date) => {
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))

    if (days === 0) {
      return date.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' })
    } else if (days === 1) {
      return '어제'
    } else if (days < 7) {
      return `${days}일 전`
    } else {
      return date.toLocaleDateString('ko-KR', { month: 'short', day: 'numeric' })
    }
  }

  return (
    <div className="flex flex-col lg:flex-row h-[calc(100vh-7.5rem)] lg:h-[calc(100vh-8rem)]">
      {/* Mobile Header Bar */}
      <div className="lg:hidden flex items-center gap-3 px-4 py-2 bg-white dark:bg-gray-800 border-b dark:border-gray-700">
        <button
          onClick={() => setSidebarOpen(true)}
          className="p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          aria-label="대화 목록 열기"
        >
          <Menu className="w-5 h-5 text-gray-600 dark:text-gray-300" />
        </button>
        <span className="text-sm font-medium text-gray-900 dark:text-white truncate">{currentTitle}</span>
      </div>

      {/* Mobile Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Conversation Sidebar */}
      <div className={clsx(
        'fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 border-r dark:border-gray-700 flex flex-col transition-transform duration-200 lg:static lg:translate-x-0',
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      )}>
        <div className="p-4 border-b dark:border-gray-700 flex items-center gap-2">
          <button
            onClick={handleNewConversation}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            새 대화
          </button>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-1.5 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            aria-label="사이드바 닫기"
          >
            <X className="w-5 h-5 text-gray-600 dark:text-gray-300" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {conversations.length > 0 ? (
            conversations.map((conv) => (
              <div
                key={conv.id}
                onClick={() => handleSelectConversation(conv.id)}
                className={clsx(
                  'p-3 cursor-pointer border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors group',
                  activeConversationId === conv.id && 'bg-primary-50 dark:bg-primary-900/20 border-l-2 border-l-primary-600'
                )}
              >
                <div className="flex items-start gap-2">
                  <MessageSquare className="w-4 h-4 text-gray-400 dark:text-gray-500 mt-1 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                      {conv.title}
                    </p>
                    <div className="flex items-center gap-1 mt-1">
                      <Clock className="w-3 h-3 text-gray-400 dark:text-gray-500" />
                      <p className="text-xs text-gray-400 dark:text-gray-500">
                        {conv.updatedAt ? formatDate(conv.updatedAt) : ''}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={(e) => handleDeleteConversation(conv.id, e)}
                    className="p-1 opacity-0 group-hover:opacity-100 hover:bg-red-100 dark:hover:bg-red-900/30 rounded transition-all"
                  >
                    <Trash2 className="w-3 h-3 text-red-500" />
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="p-4 text-center text-sm text-gray-400 dark:text-gray-500">
              대화가 없습니다
            </div>
          )}
        </div>

        <div className="p-3 border-t dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
          <p className="text-xs text-gray-400 dark:text-gray-500 text-center">
            {conversations.length}개의 대화
            {isAuthEnabled && <span className="block mt-1">서버 동기화 활성화</span>}
          </p>
        </div>
      </div>

      {/* Chat Area — min-w-0로 긴 콘텐츠가 채팅 영역을 넓혀 사이드바를 밀어내는 것 방지 */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b dark:border-gray-700 bg-white dark:bg-gray-800">
          <div>
            <h1 className="text-lg font-bold text-gray-900 dark:text-white">AI 어시스턴트</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              자연어로 보안 위협을 조사·헌팅·대응하세요
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Model Selector */}
            <div className="relative">
              <button
                onClick={() => setIsModelDropdownOpen(!isModelDropdownOpen)}
                className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-300 transition-colors"
              >
                {AVAILABLE_MODELS.find(m => m.id === selectedModel)?.label || 'Model'}
                <ChevronDown className={clsx('w-4 h-4 transition-transform', isModelDropdownOpen && 'rotate-180')} />
              </button>
              {isModelDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setIsModelDropdownOpen(false)} />
                  <div className="absolute right-0 top-full mt-1 z-20 bg-white dark:bg-gray-800 border dark:border-gray-700 rounded-lg shadow-lg py-1 min-w-[200px]">
                    {AVAILABLE_MODELS.map((model) => (
                      <button
                        key={model.id}
                        onClick={() => { setSelectedModel(model.id); setIsModelDropdownOpen(false) }}
                        className={clsx(
                          'w-full text-left px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-700 flex items-center justify-between dark:text-gray-300',
                          selectedModel === model.id && 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                        )}
                      >
                        <span>{model.label}</span>
                        {model.description && (
                          <span className="text-xs text-gray-400 dark:text-gray-500 ml-2">{model.description}</span>
                        )}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
            <div className={clsx(
              'flex items-center gap-2 px-3 py-1.5 rounded-full',
              isAgentCoreAvailable ? 'bg-green-50 dark:bg-green-900/20' : 'bg-yellow-50 dark:bg-yellow-900/20'
            )}>
              <span className={clsx('w-2 h-2 rounded-full', isAgentCoreAvailable ? 'bg-green-500' : 'bg-yellow-500')} />
              <span className={clsx('text-sm', isAgentCoreAvailable ? 'text-green-700 dark:text-green-300' : 'text-yellow-700 dark:text-yellow-300')}>
                {isAgentCoreAvailable ? '연결됨' : '연결 중...'}
              </span>
            </div>
          </div>
        </div>

        {/* Active Agents */}
        {config?.active_agents && config.active_agents.length > 0 && (
          <div className="px-4 py-2 border-b dark:border-gray-700 bg-white dark:bg-gray-800">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-400 dark:text-gray-500 mr-1">활성 에이전트</span>
              {config.active_agents.map((agent) => {
                const Icon = AGENT_ICONS[agent.icon]
                return (
                  <div
                    key={agent.id}
                    className={clsx(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium',
                      AGENT_COLORS[agent.id] || 'bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600'
                    )}
                    title={agent.description}
                  >
                    {Icon && <Icon className="w-3 h-3" />}
                    {agent.name}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Messages */}
        <div ref={messagesContainerRef} onScroll={handleMessagesScroll} className="flex-1 overflow-y-auto overflow-x-hidden p-6 space-y-6 bg-gray-50 dark:bg-gray-900">
          {currentMessages.map((message) => (
            <div
              key={message.id}
              className={clsx(
                'flex gap-4 min-w-0 message-enter',
                message.role === 'user' ? 'flex-row-reverse' : ''
              )}
            >
              {/* Avatar */}
              <div
                className={clsx(
                  'flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center',
                  message.role === 'user'
                    ? 'bg-primary-600'
                    : 'bg-gradient-to-br from-purple-500 to-blue-500'
                )}
              >
                {message.role === 'user' ? (
                  <User className="w-5 h-5 text-white" />
                ) : (
                  <Bot className="w-5 h-5 text-white" />
                )}
              </div>

              {/* Message Content — min-w-0+break-words로 긴 코드/ARN이 버블을 밀어내 레이아웃 깨는 것 방지 */}
              <div
                className={clsx(
                  'max-w-[70%] min-w-0 overflow-hidden break-words rounded-2xl px-5 py-3',
                  message.role === 'user'
                    ? 'bg-primary-600 text-white'
                    : 'bg-white dark:bg-gray-800 shadow-sm border dark:border-gray-700'
                )}
              >
                {message.role === 'user' ? (
                  <p className="whitespace-pre-wrap break-words text-white">{message.content}</p>
                ) : message.isProcessing ? (
                  <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>{message.content}</span>
                  </div>
                ) : (
                  <div className="prose prose-sm max-w-none break-words text-gray-700 dark:text-gray-300 prose-headings:text-gray-900 dark:prose-headings:text-white prose-strong:text-gray-900 dark:prose-strong:text-white prose-code:text-pink-600 dark:prose-code:text-pink-400 prose-code:bg-gray-100 dark:prose-code:bg-gray-700 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:before:content-none prose-code:after:content-none dark:prose-invert">
                    {message.thinking && (
                      <details className="mb-2 rounded-lg bg-purple-50 dark:bg-purple-900/20 border border-purple-100 dark:border-purple-800 not-prose">
                        <summary className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-purple-600 dark:text-purple-400 cursor-pointer select-none">
                          <Brain className="w-3.5 h-3.5" /> Thinking
                        </summary>
                        <div className="px-3 pb-2 text-xs text-purple-500 dark:text-purple-400 italic whitespace-pre-wrap">
                          {message.thinking}
                        </div>
                      </details>
                    )}
                    <Markdown
                      remarkPlugins={[remarkGfm]}
                      components={{
                        code({ className, children, ...props }) {
                          const match = /language-(\w+)/.exec(className || '')
                          const isInline = !match && !String(children).includes('\n')
                          return isInline ? (
                            <code className={className} {...props}>{children}</code>
                          ) : (
                            <SyntaxHighlighter
                              style={isDark ? atomOneDark : githubGist}
                              language={match?.[1] || 'text'}
                              PreTag="div"
                              customStyle={{ fontSize: '0.8rem', borderRadius: '0.5rem', padding: '1rem' }}
                            >
                              {String(children).replace(/\n$/, '')}
                            </SyntaxHighlighter>
                          )
                        },
                        table({ children }) {
                          return (
                            <div className="overflow-x-auto my-2">
                              <table className="min-w-full text-xs border-collapse border border-gray-200 dark:border-gray-600 rounded-lg overflow-hidden">
                                {children}
                              </table>
                            </div>
                          )
                        },
                        thead({ children }) {
                          return <thead className="bg-gray-50 dark:bg-gray-700">{children}</thead>
                        },
                        th({ children }) {
                          return <th className="px-3 py-2 text-left font-semibold text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600 whitespace-nowrap">{children}</th>
                        },
                        td({ children }) {
                          return <td className="px-3 py-1.5 text-gray-600 dark:text-gray-400 border border-gray-200 dark:border-gray-600 whitespace-nowrap">{children}</td>
                        },
                      }}
                    >
                      {message.content}
                    </Markdown>
                  </div>
                )}
                {message.role === 'assistant' && message.isStreaming && (
                  <div className="flex items-center gap-1.5 mt-2 text-xs text-blue-500">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    <span>응답 생성 중...</span>
                  </div>
                )}
                {message.role === 'assistant' && !message.isProcessing && !message.isStreaming && message.toolCallCount != null && message.toolCallCount > 0 && (
                  <div className="mt-1.5 text-xs text-gray-400 dark:text-gray-500">
                    {message.toolNames && message.toolNames.length > 0
                      ? `${message.toolNames.join(', ')} (${message.toolCallCount}회)`
                      : `${message.toolCallCount}개 도구 사용`}
                  </div>
                )}
                <div className="mt-2 flex items-center gap-3">
                  <p
                    className={clsx(
                      'text-xs',
                      message.role === 'user' ? 'text-white/70' : 'text-gray-400 dark:text-gray-500'
                    )}
                  >
                    {message.timestamp.toLocaleTimeString('ko-KR', {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </p>
                  {/* assistant 완료 메시지: 복사 + (리포트면) 다운로드 */}
                  {message.role === 'assistant' && !message.isProcessing && !message.isStreaming && message.content && (
                    <>
                      <button
                        onClick={() => handleCopy(message.id, message.content)}
                        className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors"
                        aria-label="메시지 복사"
                      >
                        {copiedId === message.id ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedId === message.id ? '복사됨' : '복사'}
                      </button>
                      {looksLikeReport(message.content) && (
                        <>
                          <button
                            onClick={() => handleDownloadPdf(message.content)}
                            className="flex items-center gap-1 text-xs text-gray-400 hover:text-primary-600 dark:text-gray-500 dark:hover:text-primary-400 transition-colors"
                            aria-label="PDF로 다운로드"
                          >
                            <Download className="w-3.5 h-3.5" />
                            PDF
                          </button>
                          <button
                            onClick={() => handleDownload(message.content)}
                            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 transition-colors"
                            aria-label="마크다운으로 다운로드"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            .md
                          </button>
                        </>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Questions */}
        {currentMessages.length < 3 && (
          <div className="p-4 border-t dark:border-gray-700 bg-white dark:bg-gray-800">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-4 h-4 text-yellow-500" />
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">추천 질문</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {suggestedQuestions.map((question, index) => (
                <button
                  key={index}
                  onClick={() => handleSuggestedQuestion(question)}
                  className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="p-4 border-t dark:border-gray-700 bg-white dark:bg-gray-800">
          <div className="flex gap-4 items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => {
                setInput(e.target.value)
                // 자동 높이 확장 — 내용에 맞춰 늘어나되 최대 320px까지(그 이상은 스크롤)
                const el = e.target
                el.style.height = 'auto'
                el.style.height = Math.min(el.scrollHeight, 320) + 'px'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  if (input.trim() && !isLoading) {
                    handleSubmit(e as any)
                  }
                }
              }}
              placeholder="메시지를 입력하세요... (Shift+Enter로 줄바꿈, 모서리를 드래그해 크기 조절)"
              className="flex-1 px-4 py-3 border dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 rounded-xl focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent resize-y"
              rows={1}
              disabled={isLoading}
              style={{ minHeight: '48px', maxHeight: '320px', overflow: 'auto' }}
            />
            {isLoading ? (
              <button
                type="button"
                onClick={() => abortChat()}
                className="px-6 py-3 rounded-xl flex items-center gap-2 bg-red-500 text-white hover:bg-red-600 transition-colors"
                aria-label="응답 중지"
              >
                <X className="w-5 h-5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={(e) => { if (input.trim()) handleSubmit(e as any) }}
                disabled={!input.trim()}
                className={clsx(
                  'px-6 py-3 rounded-xl flex items-center gap-2 transition-colors',
                  input.trim()
                    ? 'bg-primary-600 text-white hover:bg-primary-700'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 cursor-not-allowed'
                )}
              >
                <Send className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
