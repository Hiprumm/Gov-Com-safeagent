<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'

interface AuditLog {
  log_id: string
  user_id: string
  user_name: string
  agent_id: string
  action_type: string
  action_details: any
  risk_level: string
  is_blocked: boolean
  source: string
  timestamp: string
}

const logs = ref<AuditLog[]>([])
const isLoading = ref(false)

const loadLogs = async () => {
  isLoading.value = true
  try {
    const response = await axios.get('/ai/audit/logs/recent', {
      params: {
        limit: 50
      }
    })
    logs.value = response.data.logs || []
  } catch (error) {
    console.error('Failed to load logs:', error)
  } finally {
    isLoading.value = false
  }
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'text-red-600 bg-red-100'
    case 'medium':
      return 'text-yellow-600 bg-yellow-100'
    case 'low':
      return 'text-blue-600 bg-blue-100'
    default:
      return 'text-green-600 bg-green-100'
  }
}

const getRiskText = (riskLevel: string) => {
  switch (riskLevel) {
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
    'tool_call': '工具调用',
    'response_generation': '响应生成',
    'approval_request': '审批请求',
    'blocked': '被拦截',
  }
  return map[actionType] || actionType
}

onMounted(() => {
  loadLogs()
})
</script>

<template>
  <div class="h-full">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-xl font-bold text-gray-900">审计日志</h2>
      <button
        @click="loadLogs"
        :disabled="isLoading"
        class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-300"
      >
        <span v-if="isLoading">刷新中...</span>
        <span v-else>刷新</span>
      </button>
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-gray-50">
            <th class="text-left px-4 py-3 font-semibold text-gray-600">时间</th>
            <th class="text-left px-4 py-3 font-semibold text-gray-600">用户</th>
            <th class="text-left px-4 py-3 font-semibold text-gray-600">动作</th>
            <th class="text-left px-4 py-3 font-semibold text-gray-600">风险等级</th>
            <th class="text-left px-4 py-3 font-semibold text-gray-600">状态</th>
            <th class="text-left px-4 py-3 font-semibold text-gray-600">详情</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.log_id" class="border-b border-gray-100 hover:bg-gray-50">
            <td class="px-4 py-3 text-gray-600">
              {{ new Date(log.timestamp).toLocaleString() }}
            </td>
            <td class="px-4 py-3">
              <span class="font-medium">{{ log.user_name || log.user_id }}</span>
            </td>
            <td class="px-4 py-3">
              <span class="text-blue-600">{{ getActionTypeText(log.action_type) }}</span>
            </td>
            <td class="px-4 py-3">
              <span :class="['px-2 py-1 rounded-full text-xs font-medium', getRiskColor(log.risk_level)]">
                {{ getRiskText(log.risk_level) }}
              </span>
            </td>
            <td class="px-4 py-3">
              <span :class="log.is_blocked ? 'text-red-600' : 'text-green-600'">
                {{ log.is_blocked ? '已拦截' : '正常' }}
              </span>
            </td>
            <td class="px-4 py-3 text-gray-500 max-w-xs truncate">
              {{ typeof log.action_details === 'object' ? JSON.stringify(log.action_details).slice(0, 50) + '...' : (log.action_details || '-') }}
            </td>
          </tr>
          <tr v-if="logs.length === 0">
            <td colspan="6" class="text-center py-8 text-gray-500">
              <div v-if="isLoading">加载中...</div>
              <div v-else>暂无审计日志</div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="logs.length > 0" class="mt-6 grid grid-cols-4 gap-4">
      <div class="bg-gray-50 rounded-xl p-4">
        <div class="text-2xl font-bold text-gray-900">{{ logs.length }}</div>
        <div class="text-sm text-gray-500">总日志数</div>
      </div>
      <div class="bg-red-50 rounded-xl p-4">
        <div class="text-2xl font-bold text-red-600">
          {{ logs.filter(l => l.risk_level === 'high' || l.risk_level === 'critical').length }}
        </div>
        <div class="text-sm text-red-600">高风险</div>
      </div>
      <div class="bg-yellow-50 rounded-xl p-4">
        <div class="text-2xl font-bold text-yellow-600">
          {{ logs.filter(l => l.risk_level === 'medium').length }}
        </div>
        <div class="text-sm text-yellow-600">中风险</div>
      </div>
      <div class="bg-green-50 rounded-xl p-4">
        <div class="text-2xl font-bold text-green-600">
          {{ logs.filter(l => l.is_blocked).length }}
        </div>
        <div class="text-sm text-green-600">已拦截</div>
      </div>
    </div>
  </div>
</template>