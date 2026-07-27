<script setup lang="ts">
import { ref, onMounted } from 'vue'
import ChatPanel from '@/components/chat/ChatPanel.vue'
import SecurityPanel from '@/components/security/SecurityPanel.vue'
import AuditPanel from '@/components/audit/AuditPanel.vue'
import ToolPanel from '@/components/tools/ToolPanel.vue'
import 'element-plus/dist/index.css'

const activeTab = ref('chat')
const tabs = [
  { name: 'chat', label: '智能问答' },
  { name: 'security', label: '安全检测' },
  { name: 'tools', label: '工具调用' },
  { name: 'audit', label: '审计日志' },
]

onMounted(() => {
  console.log('HomePage mounted')
})
</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
    <header class="bg-white shadow-sm border-b border-gray-100">
      <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
            <span class="text-white text-xl font-bold">智</span>
          </div>
          <div>
            <h1 class="text-xl font-bold text-gray-900">政企大模型智能体安全平台</h1>
            <p class="text-sm text-gray-500">面向政企场景的大模型智能体安全关键技术研究</p>
          </div>
        </div>
        <span class="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium">系统运行中</span>
      </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-6">
      <div class="bg-white rounded-xl shadow-sm p-1 flex gap-1 mb-6">
        <button
          v-for="tab in tabs"
          :key="tab.name"
          @click="activeTab = tab.name"
          :class="[
            'flex-1 py-3 px-4 rounded-lg font-medium transition-all duration-200',
            activeTab === tab.name
              ? 'bg-blue-600 text-white shadow-md'
              : 'text-gray-600 hover:bg-gray-50'
          ]"
        >
          {{ tab.label }}
        </button>
      </div>

      <div class="bg-white rounded-xl shadow-sm p-6 min-h-[600px]">
        <ChatPanel v-if="activeTab === 'chat'" />
        <SecurityPanel v-else-if="activeTab === 'security'" />
        <ToolPanel v-else-if="activeTab === 'tools'" />
        <AuditPanel v-else-if="activeTab === 'audit'" />
      </div>
    </main>

    <footer class="bg-white border-t border-gray-100 mt-8">
      <div class="max-w-7xl mx-auto px-4 py-4 text-center text-sm text-gray-500">
        <p>面向政企场景的大模型智能体安全关键技术研究</p>
      </div>
    </footer>
  </div>
</template>