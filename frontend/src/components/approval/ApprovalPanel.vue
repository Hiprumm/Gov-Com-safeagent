<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import { useWebSocket } from '@/composables/useWebSocket'
import { useToast } from '@/composables/useToast'
import { useAuth } from '@/composables/useAuth'

// ==================== 类型 ====================
/** 待审接口返回（approval_engine 的 ApprovalRequest 序列化） */
interface PendingItem {
  request_id: string
  user_id: string
  user_role: string
  agent_id?: string
  action_type: string
  action_details: Record<string, any>
  risk_level: string
  status: string
}

/** 历史接口返回（storage 的 approval_requests 行） */
interface HistoryItem {
  request_id: string
  tool_name: string
  tool_args: Record<string, any>
  risk_level: string
  requester_id: string
  requester_role: string
  required_role: string
  status: string
  reason: string
  approver_id?: string
  approver_role?: string
  created_at: string
  updated_at: string
}

// ==================== 状态 ====================
const activeTab = ref<'pending' | 'history'>('pending')
const pendingList = ref<PendingItem[]>([])
const historyList = ref<HistoryItem[]>([])
const loading = ref(false)
const expandedId = ref<string>('')
const { success, error: toastError } = useToast()

// ==================== 审批者身份视角（职责分离：能批谁由后端角色层级兜底，前端禁用交互避免误导） ====================
const { currentUser } = useAuth()
const myRole = computed(() => currentUser.value?.role || '')
/** 当前账号是否具备审批操作权限 */
const canApprove = computed(() => ['admin', 'operator', 'manager'].includes(myRole.value))
const approverHint = computed(() => {
  const map: Record<string, string> = {
    admin: '系统管理员：可审批全部风险等级',
    operator: '安全运维：可审批中/低风险，高风险由管理员兜底',
    manager: '部门负责人：可审批中等风险操作，高风险由管理员兜底',
  }
  if (map[myRole.value]) return map[myRole.value]
  return '当前账号仅可查看审批队列；审批与驳回需系统管理员、安全运维或部门负责人账号'
})

// ==================== WebSocket 实时刷新 ====================
const { connect: wsConnect, onEvent } = useWebSocket()
onEvent('approval_update', () => {
  fetchAll()
})

// ==================== 数据获取 ====================
const fetchPending = async () => {
  try {
    const res = await axios.get('/ai/security/approval/pending')
    pendingList.value = res.data.pending || []
  } catch {
    // 静默失败，不打断页面
  }
}

const fetchHistory = async () => {
  try {
    const res = await axios.get('/ai/security/approval/history', { params: { limit: 50 } })
    historyList.value = res.data.records || []
  } catch {
    // 静默失败
  }
}

const fetchAll = () => {
  fetchPending()
  fetchHistory()
}

// ==================== 审批操作 ====================
const approve = async (requestId: string) => {
  try {
    const res = await axios.post(`/ai/security/approval/approve/${requestId}`)
    if (res.data.success) {
      const grant = res.data.session_id
        ? ` · 令牌已授予（${res.data.tool_name}）`
        : ''
      success(`已通过：${requestId.slice(0, 16)}…${grant}`)
      fetchAll()
    } else {
      toastError(`操作失败: ${res.data.message || '未知错误'}`)
    }
  } catch (e: any) {
    toastError(`操作失败: ${e.response?.data?.detail || e.message}`)
  }
}

const reject = async (requestId: string) => {
  try {
    const res = await axios.post(`/ai/security/approval/reject/${requestId}`)
    if (res.data.success) {
      success(`已驳回：${requestId}`)
      fetchAll()
    } else {
      toastError(`操作失败: ${res.data.message || '未知错误'}`)
    }
  } catch (e: any) {
    toastError(`操作失败: ${e.response?.data?.detail || e.message}`)
  }
}

// ==================== 展示辅助 ====================
/** 从 action_type / tool_name 提取可读工具名：tool_call_export_data → export_data */
const toolName = (item: PendingItem | HistoryItem) => {
  const raw = 'action_type' in item ? item.action_type : item.tool_name
  if (!raw) return '未知操作'
  for (const prefix of ['tool_call_', 'guard_']) {
    if (raw.startsWith(prefix)) return raw.slice(prefix.length)
  }
  return raw
}

/** 从 action_details / tool_args 提取关键信息（会话/工具/参数） */
const detailRows = (item: PendingItem | HistoryItem): Array<{ label: string; value: string }> => {
  const d: Record<string, any> = ('action_details' in item ? item.action_details : item.tool_args) || {}
  const rows: Array<{ label: string; value: string }> = []
  if (d._session_id) rows.push({ label: '会话 ID', value: d._session_id })
  if (d._tool_name) rows.push({ label: '目标工具', value: d._tool_name })
  else if (d.tool_name) rows.push({ label: '目标工具', value: d.tool_name })
  // 其余字段（排除下划线内部字段），最多展示 6 条
  for (const [k, v] of Object.entries(d)) {
    if (k.startsWith('_') || k === 'tool_name' || rows.length >= 8) continue
    const val = typeof v === 'object' ? JSON.stringify(v) : String(v)
    if (val && val !== '{}') rows.push({ label: k, value: val.length > 120 ? val.slice(0, 120) + '…' : val })
  }
  return rows
}

const riskBadge = (level: string) => {
  const map: Record<string, string> = {
    critical: 'bg-critical/15 text-critical border border-critical/30',
    high: 'bg-high/15 text-high border border-high/30',
    medium: 'bg-medium/15 text-medium border border-medium/30',
    low: 'bg-low/15 text-low border border-low/30',
  }
  return map[level] || 'bg-safe/15 text-safe border border-safe/30'
}

const riskText = (level: string) => {
  const map: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低' }
  return map[level] || '低'
}

const statusBadge = (status: string) => {
  const map: Record<string, { cls: string; text: string }> = {
    approved: { cls: 'bg-safe/15 text-safe border border-safe/30', text: '已通过' },
    auto_approved: { cls: 'bg-low/15 text-low border border-low/30', text: '自动通过' },
    rejected: { cls: 'bg-critical/15 text-critical border border-critical/30', text: '已驳回' },
    pending: { cls: 'bg-medium/15 text-medium border border-medium/30', text: '待审批' },
  }
  return map[status] || { cls: 'bg-elevated text-muted border border-border-default', text: status }
}

const formatTime = (iso?: string) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString('zh-CN', { hour12: false })
}

// 历史统计
const historyStats = computed(() => {
  const s = { approved: 0, auto_approved: 0, rejected: 0, pending: 0 }
  for (const r of historyList.value) {
    if (r.status in s) s[r.status as keyof typeof s]++
  }
  return s
})

const toggleExpand = (id: string) => {
  expandedId.value = expandedId.value === id ? '' : id
}

onMounted(() => {
  wsConnect()
  loading.value = true
  fetchAll()
  setTimeout(() => { loading.value = false }, 600)
})
</script>

<template>
  <div class="h-full">
    <h2 class="text-xl font-bold text-primary mb-1">审批中心</h2>
    <p class="text-xs text-muted mb-3">高危工具调用的人工审批队列 · 批准即授予会话能力令牌并解锁（grant-on-approve）</p>

    <!-- 审批者身份视角 -->
    <div class="flex items-center gap-2 px-3 py-2 rounded-xl border mb-4"
         :class="canApprove ? 'bg-accent/5 border-accent/20 text-accent' : 'bg-elevated/50 border-border-default text-secondary'">
      <span class="w-1.5 h-1.5 rounded-full flex-shrink-0" :class="canApprove ? 'bg-accent' : 'bg-disabled'"></span>
      <span class="text-xs">{{ approverHint }}</span>
    </div>

    <!-- 统计条 -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
      <div class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-elevated/50 border border-border-default">
        <div class="w-9 h-9 rounded-lg bg-medium/10 flex items-center justify-center flex-shrink-0">
          <svg class="w-5 h-5 text-medium" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <div class="text-xl font-bold tabular-nums text-medium leading-tight">{{ pendingList.length }}</div>
          <div class="text-xs text-muted">待审批</div>
        </div>
      </div>
      <div class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-elevated/50 border border-border-default">
        <div class="w-9 h-9 rounded-lg bg-safe/10 flex items-center justify-center flex-shrink-0">
          <svg class="w-5 h-5 text-safe" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <div class="text-xl font-bold tabular-nums text-safe leading-tight">{{ historyStats.approved }}</div>
          <div class="text-xs text-muted">已通过</div>
        </div>
      </div>
      <div class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-elevated/50 border border-border-default">
        <div class="w-9 h-9 rounded-lg bg-critical/10 flex items-center justify-center flex-shrink-0">
          <svg class="w-5 h-5 text-critical" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <div class="text-xl font-bold tabular-nums text-critical leading-tight">{{ historyStats.rejected }}</div>
          <div class="text-xs text-muted">已驳回</div>
        </div>
      </div>
      <div class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-elevated/50 border border-border-default">
        <div class="w-9 h-9 rounded-lg bg-low/10 flex items-center justify-center flex-shrink-0">
          <svg class="w-5 h-5 text-low" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
        </div>
        <div>
          <div class="text-xl font-bold tabular-nums text-low leading-tight">{{ historyStats.auto_approved }}</div>
          <div class="text-xs text-muted">低风险自动通过</div>
        </div>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="flex gap-1 bg-elevated p-1 rounded-xl mb-4">
      <button
        @click="activeTab = 'pending'"
        :class="[
          'flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-all active:scale-95',
          activeTab === 'pending' ? 'bg-surface text-accent shadow-md' : 'text-muted hover:text-secondary'
        ]"
      >
        待审批
        <span v-if="pendingList.length" class="ml-1 px-1.5 py-0.5 bg-critical text-white text-xs rounded-full">{{ pendingList.length }}</span>
      </button>
      <button
        @click="activeTab = 'history'"
        :class="[
          'flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-all active:scale-95',
          activeTab === 'history' ? 'bg-surface text-accent shadow-md' : 'text-muted hover:text-secondary'
        ]"
      >
        已处理（{{ historyList.length }}）
      </button>
    </div>

    <!-- ========== 待审批 Tab ========== -->
    <div v-if="activeTab === 'pending'">
      <div v-if="pendingList.length === 0" class="text-center py-16">
        <div class="w-16 h-16 bg-elevated rounded-full flex items-center justify-center mx-auto mb-4">
          <svg class="w-8 h-8 text-disabled" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <p class="text-muted">暂无待审批请求</p>
        <p class="text-xs text-disabled mt-1">高危工具调用被拦截后自动生成审批单，WebSocket 实时推送到此队列</p>
      </div>

      <div v-else class="space-y-3">
        <div
          v-for="req in pendingList"
          :key="req.request_id"
          class="bg-elevated border border-border-default rounded-xl p-4 shadow-sm animate-card-in"
        >
          <!-- 头部：工具 + 风险 -->
          <div class="flex items-start justify-between mb-2">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="font-medium text-primary font-mono">{{ toolName(req) }}</span>
                <span :class="['px-2 py-0.5 text-xs font-medium rounded-full', riskBadge(req.risk_level)]">{{ riskText(req.risk_level) }}风险</span>
              </div>
              <p class="text-xs text-muted mt-1">
                请求人: {{ req.user_id }}（{{ req.user_role }}）· 单号 {{ req.request_id }}
              </p>
            </div>
            <button
              @click="toggleExpand(req.request_id)"
              class="text-xs text-muted hover:text-accent transition-colors flex-shrink-0 px-2 py-1"
            >
              {{ expandedId === req.request_id ? '收起' : '详情' }}
            </button>
          </div>

          <!-- 展开详情 -->
          <div v-if="expandedId === req.request_id" class="bg-canvas rounded-lg p-3 mb-3 space-y-1.5">
            <div v-for="row in detailRows(req)" :key="row.label" class="flex gap-2 text-xs">
              <span class="text-muted flex-shrink-0 w-20 text-right">{{ row.label }}</span>
              <span class="text-secondary font-mono break-all">{{ row.value }}</span>
            </div>
            <div v-if="detailRows(req).length === 0" class="text-xs text-disabled">无附加参数</div>
          </div>

          <!-- 操作按钮（按审批者身份：无权限账号仅展示，防误导） -->
          <div v-if="canApprove" class="flex gap-2">
            <button
              @click="approve(req.request_id)"
              class="flex-1 py-2 text-sm bg-gradient-to-r from-safe to-low text-white rounded-lg hover:opacity-90 transition-all active:scale-95 font-medium"
            >
              通过并授予令牌
            </button>
            <button
              @click="reject(req.request_id)"
              class="flex-1 py-2 text-sm bg-gradient-to-r from-critical to-high text-white rounded-lg hover:opacity-90 transition-all active:scale-95 font-medium"
            >
              驳回
            </button>
          </div>
          <p v-else class="text-[11px] text-muted text-center py-2 border border-dashed border-border-default rounded-lg">当前账号无审批操作权限（仅可查看队列）</p>
        </div>
      </div>
    </div>

    <!-- ========== 已处理 Tab ========== -->
    <div v-else>
      <div v-if="historyList.length === 0" class="text-center py-16">
        <div class="w-16 h-16 bg-elevated rounded-full flex items-center justify-center mx-auto mb-4">
          <svg class="w-8 h-8 text-disabled" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <p class="text-muted">暂无审批历史</p>
      </div>

      <div v-else class="space-y-2">
        <div
          v-for="rec in historyList"
          :key="rec.request_id"
          class="bg-elevated border border-border-default rounded-xl px-4 py-3 flex items-center gap-3 animate-card-in"
        >
          <!-- 状态徽章 -->
          <span :class="['px-2 py-0.5 text-xs font-medium rounded-full flex-shrink-0', statusBadge(rec.status).cls]">
            {{ statusBadge(rec.status).text }}
          </span>
          <!-- 主体 -->
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-sm font-medium text-primary font-mono">{{ toolName(rec) }}</span>
              <span :class="['px-1.5 py-0.5 text-[10px] rounded-full', riskBadge(rec.risk_level)]">{{ riskText(rec.risk_level) }}风险</span>
            </div>
            <p class="text-xs text-muted mt-0.5 truncate">
              {{ rec.requester_id }}（{{ rec.requester_role }}）→
              {{ rec.approver_id ? `${rec.approver_id}${rec.approver_role ? '（' + rec.approver_role + '）' : ''}` : '—' }}
            </p>
          </div>
          <!-- 时间 + 驳回原因 -->
          <div class="text-right flex-shrink-0">
            <p class="text-xs text-disabled">{{ formatTime(rec.updated_at) }}</p>
            <p v-if="rec.status === 'rejected' && rec.reason" class="text-[10px] text-critical mt-0.5 max-w-[160px] truncate" :title="rec.reason">
              原因: {{ rec.reason }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
