/**
 * 安全管控台 · 风险看板数据 composable
 *
 * - 模块级共享状态：HomePage 顶部 KPI 状态条与 DashboardPanel 共用同一份数据
 * - fetchOverview 带节流与并发去重，避免多组件重复请求
 * - useDashboardRealtime() 须在组件 setup 中同步调用：
 *   30s 轮询 + 模块级单例 WebSocket（风险/审批事件即时刷新），组件卸载自动清理
 */
import { ref, onUnmounted } from 'vue'
import axios from 'axios'

export interface DashboardKPI {
  today_blocked: number
  pending_approvals: number
  risk_events_today: number
  blocked_rate_24h: number
}

export interface TrendPoint {
  date: string
  total: number
  blocked: number
}

export interface RiskEvent {
  log_id: string
  timestamp: string
  risk_level: string
  attack_type: string | null
  action_type: string
  is_blocked: boolean
  preview: string
}

export interface DashboardScope {
  scope: 'all' | 'dept' | 'self' | string
  username: string
  display_name: string
  role: string
  department: string
  label: string
  hint: string
}

export interface DashboardOverview {
  success: boolean
  scope?: DashboardScope
  kpi: DashboardKPI
  attack_distribution: Record<string, number>
  risk_level_distribution: Record<string, number>
  trend_7d: TrendPoint[]
  recent_events: RiskEvent[]
}

// ==================== 模块级共享状态 ====================
const overview = ref<DashboardOverview | null>(null)
const loading = ref(false)
const wsConnected = ref(false)

let lastFetch = 0
let inflight: Promise<void> | null = null

async function fetchOverview(force = false): Promise<void> {
  const now = Date.now()
  if (!force && overview.value && now - lastFetch < 8000) return
  if (inflight) return inflight
  loading.value = true
  inflight = axios
    .get('/ai/dashboard/overview')
    .then((res) => {
      if (res.data?.success) {
        overview.value = res.data as DashboardOverview
        lastFetch = Date.now()
      }
    })
    .catch((e) => {
      console.warn('[Dashboard] 概览数据加载失败:', e?.response?.data?.detail || e?.message || e)
    })
    .finally(() => {
      loading.value = false
      inflight = null
    })
  return inflight
}

// ==================== 模块级 WebSocket 单例 ====================
let ws: WebSocket | null = null
let wsReconnectTimer: ReturnType<typeof setTimeout> | null = null
let wsHeartbeatTimer: ReturnType<typeof setInterval> | null = null
let wsRefCount = 0

function connectWs() {
  wsRefCount++
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/ws/events`

  try {
    ws = new WebSocket(url)
  } catch (e) {
    console.warn('[Dashboard] WebSocket 连接失败:', e)
    return
  }

  ws.onopen = () => {
    wsConnected.value = true
    wsHeartbeatTimer = setInterval(() => {
      ws?.send(JSON.stringify({ action: 'ping' }))
    }, 30000)
  }

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'risk_alert' || msg.type === 'approval_update') {
        fetchOverview(true)
      } else if (msg.type === 'detection_event') {
        const lvl = msg.data?.risk_level
        if (lvl === 'medium' || lvl === 'high' || lvl === 'critical') fetchOverview(true)
      }
    } catch {
      /* 忽略非 JSON 消息 */
    }
  }

  ws.onclose = () => {
    wsConnected.value = false
    if (wsHeartbeatTimer) {
      clearInterval(wsHeartbeatTimer)
      wsHeartbeatTimer = null
    }
    // 仍有组件使用时自动重连
    if (wsRefCount > 0) {
      wsReconnectTimer = setTimeout(connectWs, 3000)
    }
  }
}

function disconnectWs() {
  wsRefCount = Math.max(0, wsRefCount - 1)
  if (wsRefCount > 0) return
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer)
    wsReconnectTimer = null
  }
  if (wsHeartbeatTimer) {
    clearInterval(wsHeartbeatTimer)
    wsHeartbeatTimer = null
  }
  if (ws) {
    ws.onclose = null
    ws.close()
    ws = null
  }
  wsConnected.value = false
}

export function useDashboard() {
  return { overview, loading, wsConnected, fetchOverview }
}

/**
 * 实时数据绑定：30s 轮询 + WebSocket 即时刷新。
 * 必须在组件 setup 同步阶段调用（内部依赖 onUnmounted）。
 */
export function useDashboardRealtime() {
  fetchOverview(true)
  const timer = setInterval(() => fetchOverview(true), 30000)
  connectWs()

  onUnmounted(() => {
    clearInterval(timer)
    disconnectWs()
  })

  return { fetchOverview }
}

/** 攻击类型 → 中文标签 */
export const ATTACK_TYPE_LABELS: Record<string, string> = {
  prompt_injection: '提示注入',
  indirect_injection: '间接注入',
  jailbreak: '越狱攻击',
  data_leakage: '数据泄露',
  data_exfiltration: '数据外传',
  data_poisoning: '数据投毒',
  memory_poisoning: '记忆投毒',
  context_poisoning: '上下文污染',
  mcp_poisoning: 'MCP投毒',
  tool_descriptor_poisoning: '工具描述投毒',
  skill_tampering: '技能篡改',
  steganography: '隐写攻击',
  sql_injection: 'SQL注入',
  xss: 'XSS攻击',
  command_execution: '命令执行',
  path_traversal: '路径穿越',
  crlf_injection: 'CRLF注入',
  json_injection: 'JSON注入',
  unauthorized_access: '越权访问',
  content_injection: '内容注入',
  network_attack: '网络攻击',
  combined_attack: '组合攻击',
}

export function attackTypeLabel(key: string | null | undefined): string {
  if (!key) return '未知类型'
  return ATTACK_TYPE_LABELS[key] || key
}

/** 风险等级 → 中文标签 */
export const RISK_LEVEL_LABELS: Record<string, string> = {
  none: '无风险',
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重',
}

export function riskLevelLabel(level: string): string {
  return RISK_LEVEL_LABELS[level] || level
}
