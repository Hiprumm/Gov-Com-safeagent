<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'

interface AuditLog {
  log_id: string
  user_id: string
  user_role: string
  agent_id: string
  action_type: string
  action_details: any
  risk_level: string
  is_blocked: boolean
  approval_status: string | null
  blocking_reason: string | null
  timestamp: string
  session_id: string
  think_text: string
  return_value: string
  detection_result: any
  tool_call_result: any
}

const logs = ref<AuditLog[]>([])
const isLoading = ref(false)
const detailVisible = ref(false)
const currentLog = ref<AuditLog | null>(null)
const total = ref(0)
const totalPages = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const retentionDays = ref<number | null>(null)

const loadLogs = async () => {
  isLoading.value = true
  try {
    const response = await axios.get('/ai/audit/logs/page', {
      params: {
        page: currentPage.value,
        page_size: pageSize.value
      }
    })
    logs.value = response.data.logs || []
    total.value = response.data.total || 0
    totalPages.value = response.data.total_pages || 0
  } catch (error) {
    console.error('Failed to load logs:', error)
  } finally {
    isLoading.value = false
  }
}

const loadAuditConfig = async () => {
  try {
    const response = await axios.get('/ai/audit/config')
    retentionDays.value = response.data.retention_days
  } catch (error) {
    console.error('Failed to load audit config:', error)
  }
}

const changePage = (page: number) => {
  if (page < 1 || page > totalPages.value || page === currentPage.value) return
  currentPage.value = page
  loadLogs()
}

const changePageSize = (size: number) => {
  if (size === pageSize.value) return
  pageSize.value = size
  currentPage.value = 1
  loadLogs()
}

const pageNumbers = computed(() => {
  const pages: number[] = []
  const maxShown = 5
  let start = Math.max(1, currentPage.value - 2)
  let end = Math.min(totalPages.value, start + maxShown - 1)
  start = Math.max(1, end - maxShown + 1)
  for (let i = start; i <= end; i++) pages.push(i)
  return pages
})

const retentionText = computed(() => {
  if (!retentionDays.value) return ''
  const days = retentionDays.value
  if (days >= 180) return `${days}天（6个月）`
  if (days >= 90) return `${days}天（3个月）`
  return `${days}天（1个月）`
})

const openDetail = (log: AuditLog) => {
  currentLog.value = log
  detailVisible.value = true
}

const closeDetail = () => {
  detailVisible.value = false
  currentLog.value = null
}

const formatDetails = (obj: any): string => {
  if (obj === null || obj === undefined) return '-'
  if (typeof obj === 'string') return obj
  try {
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(obj)
  }
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'text-critical bg-critical/15'
    case 'medium':
      return 'text-medium bg-medium/15'
    case 'low':
      return 'text-low bg-low/15'
    default:
      return 'text-safe bg-safe/15'
  }
}

const getRiskText = (riskLevel: string) => {
  switch (riskLevel) {
    case 'critical':
      return '严重风险'
    case 'high':
      return '高风险'
    case 'medium':
      return '中风险'
    case 'low':
      return '低风险'
    default:
      return '安全'
  }
}

const getActionTypeText = (actionType: string) => {
  const map: Record<string, string> = {
    'input_detection': '输入检测',
    'tool_risk_evaluation': '工具风险评估',
    'tool_execution': '工具执行',
    'tool_call': '工具调用',
    'response_generation': '响应生成',
    'approval_request': '审批请求',
    'operation_guard_blocked': '操作守卫拦截',
    'operation_guard_approval': '操作守卫审批',
    'runtime_termination': '运行时终止',
    'chain_detection': '链路检测',
    'blocked': '被拦截',
  }
  return map[actionType] || actionType
}

onMounted(() => {
  loadLogs()
  loadAuditConfig()
})
</script>

<template>
  <div class="h-full">
    <div class="flex items-center justify-between mb-4">
      <div class="flex items-center gap-3">
        <h2 class="text-xl font-bold text-primary">审计日志</h2>
        <span v-if="retentionDays" class="px-2 py-1 text-xs text-muted bg-elevated rounded-full">
          日志留存：{{ retentionText }}
        </span>
      </div>
      <button
        @click="loadLogs"
        :disabled="isLoading"
        class="px-4 py-2 bg-gradient-to-r from-accent to-low text-white rounded-lg hover:opacity-90 transition-all active:scale-95 disabled:opacity-40"
      >
        <span v-if="isLoading">刷新中...</span>
        <span v-else>刷新</span>
      </button>
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-elevated">
            <th class="text-left px-4 py-3 font-semibold text-secondary">时间</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">用户</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">动作</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">风险等级</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">状态</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">会话ID</th>
            <th class="text-left px-4 py-3 font-semibold text-secondary">详情</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.log_id" class="border-b border-border-default hover:bg-elevated/50 animate-list-in">
            <td class="px-4 py-3 text-secondary whitespace-nowrap">
              {{ new Date(log.timestamp).toLocaleString() }}
            </td>
            <td class="px-4 py-3">
              <span class="font-medium">{{ log.user_id }}</span>
              <span class="text-xs text-disabled ml-1">{{ log.user_role }}</span>
            </td>
            <td class="px-4 py-3">
              <span class="text-accent">{{ getActionTypeText(log.action_type) }}</span>
            </td>
            <td class="px-4 py-3">
              <span :class="['px-2 py-1 rounded-full text-xs font-medium', getRiskColor(log.risk_level)]">
                {{ getRiskText(log.risk_level) }}
              </span>
            </td>
            <td class="px-4 py-3">
              <span :class="log.is_blocked ? 'text-critical' : 'text-safe'">
                {{ log.is_blocked ? '已拦截' : '正常' }}
              </span>
            </td>
            <td class="px-4 py-3 text-muted">
              {{ log.session_id || '-' }}
            </td>
            <td class="px-4 py-3">
              <button
                @click="openDetail(log)"
                class="px-2 py-1 text-xs text-accent bg-accent/10 rounded hover:bg-accent/20 transition-all active:scale-95"
              >
                查看详情
              </button>
            </td>
          </tr>
          <tr v-if="logs.length === 0">
            <td colspan="7" class="text-center py-8 text-muted">
              <div v-if="isLoading">加载中...</div>
              <div v-else>暂无审计日志</div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <!-- 分页控件 -->
    <div class="mt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
      <div class="flex items-center gap-2 text-sm text-muted">
        <span>共 {{ total }} 条日志</span>
        <span class="mx-2 text-disabled">|</span>
        <span>每页</span>
        <select
          :value="pageSize"
          @change="changePageSize(Number(($event.target as HTMLSelectElement).value))"
          class="px-2 py-1 border border-border-default rounded-lg text-sm text-primary focus:outline-none focus:ring-2 focus:ring-accent/20"
        >
          <option :value="20">20 条</option>
          <option :value="50">50 条</option>
        </select>
      </div>
      <div class="flex items-center gap-1" v-if="totalPages > 1">
        <button
          @click="changePage(currentPage - 1)"
          :disabled="currentPage <= 1"
          class="px-3 py-1 text-sm text-secondary bg-elevated border border-border-default rounded-lg hover:bg-hover transition-all active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
        >上一页</button>
        <button
          v-for="p in pageNumbers"
          :key="p"
          @click="changePage(p)"
          :class="[
            'px-3 py-1 text-sm rounded-lg border transition-all active:scale-95',
            p === currentPage
              ? 'bg-accent text-white border-accent'
              : 'text-secondary bg-elevated border-border-default hover:bg-hover'
          ]"
        >{{ p }}</button>
        <button
          @click="changePage(currentPage + 1)"
          :disabled="currentPage >= totalPages"
          class="px-3 py-1 text-sm text-secondary bg-elevated border border-border-default rounded-lg hover:bg-hover transition-all active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed"
        >下一页</button>
        <span class="ml-2 text-sm text-muted">{{ currentPage }} / {{ totalPages }} 页</span>
      </div>
    </div>

    <div v-if="logs.length > 0" class="mt-6 grid grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="bg-elevated/50 rounded-xl p-4">
        <div class="text-2xl font-bold text-primary">{{ total }}</div>
        <div class="text-sm text-muted">总日志数</div>
      </div>
      <div class="bg-critical/10 rounded-xl p-4">
        <div class="text-2xl font-bold text-critical">
          {{ logs.filter(l => l.risk_level === 'high' || l.risk_level === 'critical').length }}
        </div>
        <div class="text-sm text-critical">本页高风险</div>
      </div>
      <div class="bg-medium/10 rounded-xl p-4">
        <div class="text-2xl font-bold text-medium">
          {{ logs.filter(l => l.risk_level === 'medium').length }}
        </div>
        <div class="text-sm text-medium">本页中风险</div>
      </div>
      <div class="bg-critical/10 rounded-xl p-4">
        <div class="text-2xl font-bold text-critical">
          {{ logs.filter(l => l.is_blocked).length }}
        </div>
        <div class="text-sm text-critical">本页已拦截</div>
      </div>
    </div>

    <!-- 审计详情弹窗：完整展示所有字段 -->
    <div v-if="detailVisible && currentLog" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" @click.self="closeDetail">
      <div class="bg-surface rounded-2xl shadow-2xl border border-border-default max-w-3xl w-full max-h-[85vh] overflow-y-auto">
        <div class="sticky top-0 bg-surface border-b border-border-default px-6 py-4 flex items-center justify-between">
          <h3 class="text-lg font-bold text-primary">审计日志详情</h3>
          <button @click="closeDetail" class="text-muted hover:text-primary text-xl leading-none transition-all active:scale-95">&times;</button>
        </div>
        <div class="p-6 space-y-5">
          <!-- 基本信息 -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div>
              <div class="text-xs text-muted mb-1">日志ID</div>
              <div class="text-primary break-all font-mono">{{ currentLog.log_id }}</div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">时间戳</div>
              <div class="text-primary">{{ new Date(currentLog.timestamp).toLocaleString() }}</div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">会话ID</div>
              <div class="text-primary break-all">{{ currentLog.session_id || '-' }}</div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">用户 / 角色</div>
              <div class="text-primary">{{ currentLog.user_id }} / {{ currentLog.user_role }}</div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">动作类型</div>
              <div class="text-primary">{{ getActionTypeText(currentLog.action_type) }}</div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">风险等级</div>
              <span :class="['px-2 py-0.5 rounded-full text-xs font-medium', getRiskColor(currentLog.risk_level)]">
                {{ getRiskText(currentLog.risk_level) }}
              </span>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">状态</div>
              <div :class="currentLog.is_blocked ? 'text-critical' : 'text-safe'">
                {{ currentLog.is_blocked ? '已拦截' : '正常' }}
              </div>
            </div>
            <div>
              <div class="text-xs text-muted mb-1">审批状态</div>
              <div class="text-primary">{{ currentLog.approval_status || '-' }}</div>
            </div>
          </div>

          <!-- Think 原文（推理阶段内容不丢失） -->
          <div>
            <div class="text-xs text-muted mb-1 font-semibold">Think 推理原文</div>
            <div class="bg-elevated/50 rounded-lg p-3 text-primary text-sm whitespace-pre-wrap">
              {{ currentLog.think_text || '（无）' }}
            </div>
          </div>

          <!-- 操作详情 -->
          <div>
            <div class="text-xs text-muted mb-1 font-semibold">操作详情（入参等）</div>
            <pre class="bg-elevated/50 rounded-lg p-3 text-primary text-xs whitespace-pre-wrap overflow-x-auto">{{ formatDetails(currentLog.action_details) }}</pre>
          </div>

          <!-- 返回值 -->
          <div>
            <div class="text-xs text-muted mb-1 font-semibold">返回值</div>
            <pre class="bg-elevated/50 rounded-lg p-3 text-primary text-xs whitespace-pre-wrap overflow-x-auto">{{ currentLog.return_value || '-' }}</pre>
          </div>

          <!-- 阻断原因 -->
          <div>
            <div class="text-xs text-muted mb-1 font-semibold">阻断原因</div>
            <div class="bg-critical/10 rounded-lg p-3 text-critical text-sm whitespace-pre-wrap">
              {{ currentLog.blocking_reason || '（无）' }}
            </div>
          </div>

          <!-- 检测结果 / 工具风险评估 -->
          <div v-if="currentLog.detection_result || currentLog.tool_call_result">
            <div class="text-xs text-muted mb-1 font-semibold">检测结果 / 工具风险评估</div>
            <pre class="bg-elevated/50 rounded-lg p-3 text-primary text-xs whitespace-pre-wrap overflow-x-auto">{{ formatDetails(currentLog.detection_result || currentLog.tool_call_result) }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
