<script setup lang="ts">
import { ref } from 'vue'
import axios from 'axios'

interface ToolRiskResult {
  risk_level: string
  risk_score: number
  risk_details: string[]
  requires_approval: boolean
  approval_level: string | null
}

const toolName = ref('')
const toolArgs = ref('')
const riskResult = ref<ToolRiskResult | null>(null)
const isLoading = ref(false)

const tools = [
  { name: 'read_file', desc: '读取文件' },
  { name: 'write_file', desc: '写入文件' },
  { name: 'execute_command', desc: '执行命令' },
  { name: 'export_data', desc: '导出数据' },
  { name: 'search_knowledge', desc: '搜索知识库' },
]

const evaluateTool = async () => {
  if (!toolName.value) return
  isLoading.value = true
  riskResult.value = null
  try {
    const args = toolArgs.value ? JSON.parse(toolArgs.value) : {}
    const response = await axios.post('/ai/security/tool_risk', {
      tool_name: toolName.value,
      tool_args: args,
      user_role: 'user',
      agent_id: 'gov_agent'
    })
    riskResult.value = response.data
  } catch (error) {
    console.error('Tool evaluation failed:', error)
  } finally {
    isLoading.value = false
  }
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'text-red-600'
    case 'medium':
      return 'text-yellow-600'
    case 'low':
      return 'text-blue-600'
    default:
      return 'text-green-600'
  }
}

const getRiskBgColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'bg-red-50 border-red-200'
    case 'medium':
      return 'bg-yellow-50 border-yellow-200'
    case 'low':
      return 'bg-blue-50 border-blue-200'
    default:
      return 'bg-green-50 border-green-200'
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
</script>

<template>
  <div class="h-full">
    <h2 class="text-xl font-bold text-gray-900 mb-4">工具调用风险评估</h2>
    <div class="bg-gray-50 rounded-xl p-4 mb-6">
      <div class="grid grid-cols-5 gap-3 mb-4">
        <button
          v-for="tool in tools"
          :key="tool.name"
          @click="toolName = tool.name"
          :class="[
            'p-4 rounded-xl border-2 transition-all duration-200 text-center',
            toolName === tool.name
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-200 hover:border-gray-300'
          ]"
        >
          <div class="text-2xl mb-2">🔧</div>
          <div class="text-sm font-medium">{{ tool.desc }}</div>
        </button>
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">工具参数 (JSON格式)</label>
        <textarea
          v-model="toolArgs"
          placeholder='{"file_path": "/data/docs/gov_doc.txt"}'
          class="w-full px-4 py-3 border border-gray-200 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows="3"
        ></textarea>
      </div>
      <button
        @click="evaluateTool"
        :disabled="isLoading || !toolName"
        :class="[
          'mt-4 px-6 py-2 rounded-xl font-medium transition-all duration-200',
          isLoading || !toolName
            ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
            : 'bg-blue-600 text-white hover:bg-blue-700'
        ]"
      >
        <span v-if="isLoading">评估中...</span>
        <span v-else>评估风险</span>
      </button>
    </div>
    <div v-if="riskResult" class="space-y-4">
      <h3 class="text-lg font-semibold text-gray-800">评估结果</h3>
      <div :class="['p-4 rounded-xl border', getRiskBgColor(riskResult.risk_level)]">
        <div class="flex items-center justify-between mb-4">
          <span class="font-medium text-gray-800">工具: {{ toolName }}</span>
          <span :class="['px-3 py-1 rounded-full text-sm font-medium', getRiskBgColor(riskResult.risk_level)]" :style="{ color: getRiskColor(riskResult.risk_level) }">
            {{ getRiskText(riskResult.risk_level) }}
          </span>
        </div>
        <div class="mb-4">
          <label class="text-sm text-gray-600 mb-2 block">风险分数</label>
          <div class="h-3 bg-gray-200 rounded-full overflow-hidden">
            <div
              class="h-full rounded-full transition-all duration-500"
              :class="[
                riskResult.risk_score >= 0.7 ? 'bg-red-500' :
                riskResult.risk_score >= 0.4 ? 'bg-yellow-500' : 'bg-green-500'
              ]"
              :style="{ width: (riskResult.risk_score * 100) + '%' }"
            ></div>
          </div>
          <p class="text-right text-sm font-medium mt-1">{{ (riskResult.risk_score * 100).toFixed(0) }}/100</p>
        </div>
        <div class="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label class="text-xs text-gray-500">风险详情</label>
            <ul class="mt-2 space-y-1">
              <li v-for="(detail, index) in riskResult.risk_details" :key="index" class="text-sm text-gray-700">
                • {{ detail }}
              </li>
            </ul>
          </div>
          <div>
            <label class="text-xs text-gray-500">审批要求</label>
            <div class="mt-2 space-y-2">
              <div class="flex items-center gap-2">
                <span :class="riskResult.requires_approval ? 'text-yellow-500' : 'text-green-500'">
                  {{ riskResult.requires_approval ? '!' : '✓' }}
                </span>
                <span class="text-sm">{{ riskResult.requires_approval ? '需要审批' : '无需审批' }}</span>
              </div>
              <div v-if="riskResult.approval_level" class="flex items-center gap-2">
                <span class="text-blue-500">→</span>
                <span class="text-sm">审批级别: {{ riskResult.approval_level }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="text-center py-12">
      <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
        <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
        </svg>
      </div>
      <p class="text-gray-500">选择工具并点击评估按钮查看风险评估结果</p>
    </div>
  </div>
</template>