<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  Menu, Search, BarChart3, Zap,
  ShieldX, Clock, AlertTriangle, ShieldCheck,
  MessageSquare, Shield, Settings, FileText, ClipboardCheck,
  Sun, Moon,
} from 'lucide-vue-next'
import ChatPanel from '@/components/chat/ChatPanel.vue'
import SecurityPanel from '@/components/security/SecurityPanel.vue'
import ApprovalPanel from '@/components/approval/ApprovalPanel.vue'
import AuditPanel from '@/components/audit/AuditPanel.vue'
import ToolPanel from '@/components/tools/ToolPanel.vue'
import { useToast } from '@/composables/useToast'
import { useTheme } from '@/composables/useTheme'

const { isDark, toggleTheme } = useTheme()

// 图标映射 — 统一图标系统，避免内联 SVG 重复
const tabIconMap: Record<string, any> = {
  chat: MessageSquare,
  security: Shield,
  approval: ClipboardCheck,
  tools: Settings,
  audit: FileText,
}
const kpiIconMap: Record<string, any> = {
  block: ShieldX,
  pending: Clock,
  warning: AlertTriangle,
  health: ShieldCheck,
}

const activeTab = ref('chat')
const sidebarCollapsed = ref(false)
const mobileSidebarOpen = ref(false)
const isMobile = ref(false)
const showCommandPalette = ref(false)
const commandQuery = ref('')
const { success, info } = useToast()

const tabs = [
  { name: 'chat', label: '智能问答', sub: '全链路安全执行', icon: 'chat', group: '日常操作' },
  { name: 'security', label: '安全检测', sub: '输入 + 供应链', icon: 'security', group: '安全运营' },
  { name: 'approval', label: '审批中心', sub: '人工审批 · 令牌授予', icon: 'approval', group: '安全运营' },
  { name: 'tools', label: '工具管控', sub: '风险评估 + 能力矩阵', icon: 'tools', group: '安全运营' },
  { name: 'audit', label: '审计追溯', sub: '过程可审计·责任可追溯', icon: 'audit', group: '合规审计' },
]

const currentTab = computed(() => tabs.find(t => t.name === activeTab.value))

// 面包屑
const breadcrumbs = computed(() => [
  { label: 'SafeAgent', icon: true },
  { label: currentTab.value?.group || '' },
  { label: currentTab.value?.label || '' },
])

// 状态总览KPI（模拟数据，实际可从API获取）
const statusKPIs = ref([
  { label: '今日拦截', value: 47, color: 'critical', icon: 'block' },
  { label: '待审批', value: 3, color: 'medium', icon: 'pending' },
  { label: '风险事件', value: 12, color: 'high', icon: 'warning' },
  { label: '系统健康', value: '99.8%', color: 'safe', icon: 'health' },
])

// 命令面板
const commandItems = computed(() => {
  const allItems = [
    ...tabs.map(t => ({ label: t.label, sub: t.sub, action: () => switchTab(t.name), type: '导航' })),
    { label: '评测报告', sub: '查看检测评测结果', action: () => window.open('/evaluation', '_self'), type: '导航' },
    { label: '刷新数据', sub: '重新加载当前面板', action: () => { success('数据已刷新') }, type: '操作' },
    { label: '折叠侧边栏', sub: '切换侧边栏显示', action: () => toggleSidebar(), type: '操作' },
  ]
  if (!commandQuery.value) return allItems
  return allItems.filter(i => i.label.includes(commandQuery.value) || i.sub.includes(commandQuery.value))
})

function switchTab(name: string) {
  activeTab.value = name
  if (isMobile.value) mobileSidebarOpen.value = false
  showCommandPalette.value = false
  commandQuery.value = ''
}

function toggleSidebar() {
  if (isMobile.value) {
    mobileSidebarOpen.value = !mobileSidebarOpen.value
  } else {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }
}

function checkMobile() {
  isMobile.value = window.innerWidth < 768
  if (!isMobile.value) mobileSidebarOpen.value = false
}

function handleKeydown(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault()
    showCommandPalette.value = !showCommandPalette.value
    if (!showCommandPalette.value) commandQuery.value = ''
  }
  if (e.key === 'Escape' && showCommandPalette.value) {
    showCommandPalette.value = false
    commandQuery.value = ''
  }
}

onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)
  window.addEventListener('keydown', handleKeydown)
})
onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
  window.removeEventListener('keydown', handleKeydown)
})
</script>

<template>
  <div class="min-h-screen flex flex-col bg-canvas text-primary">
    <!-- ========== 顶栏 ========== -->
    <header class="h-14 bg-surface border-b border-border-default flex items-center justify-between px-3 sm:px-4 flex-shrink-0 z-20">
      <div class="flex items-center gap-2 sm:gap-3 min-w-0">
        <button
          @click="toggleSidebar"
          class="p-1.5 rounded-lg hover:bg-hover transition-colors flex-shrink-0 active:scale-95"
          title="切换侧边栏"
        >
          <Menu class="w-5 h-5 text-secondary" />
        </button>

        <div class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 transition-transform hover:scale-105" style="background: linear-gradient(135deg, #06B6D4 0%, #3B82F6 100%)">
          <span class="text-white text-lg font-bold">智</span>
        </div>
        <div class="min-w-0">
          <h1 class="text-sm sm:text-base font-bold text-primary leading-tight truncate">政企大模型智能体安全平台</h1>
          <p class="text-xs text-muted leading-tight hidden sm:block">SafeAgent · 面向政企场景的安全关键技术</p>
        </div>
      </div>

      <div class="flex items-center gap-2 sm:gap-3 flex-shrink-0">
        <!-- 命令面板快捷键提示 -->
        <button
          @click="showCommandPalette = true"
          class="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-elevated border border-border-default text-muted text-sm hover:border-hover hover:text-secondary transition-colors"
          title="命令面板 (Ctrl+K)"
        >
          <Search class="w-4 h-4" />
          <span>搜索...</span>
          <kbd class="px-1.5 py-0.5 text-xs bg-canvas rounded border border-border-default font-mono">⌘K</kbd>
        </button>

        <!-- 主题切换按钮 -->
        <button
          @click="toggleTheme"
          class="p-1.5 rounded-lg hover:bg-hover transition-colors flex-shrink-0 active:scale-95"
          :title="isDark ? '切换到浅色主题' : '切换到深色主题'"
        >
          <Sun v-if="isDark" class="w-5 h-5 text-secondary" />
          <Moon v-else class="w-5 h-5 text-secondary" />
        </button>

        <div class="flex items-center gap-1.5 px-2 sm:px-2.5 py-1 rounded-full bg-safe/10 border border-safe/20">
          <span class="w-2 h-2 rounded-full bg-safe animate-pulse"></span>
          <span class="text-xs text-safe font-medium hidden sm:inline">系统运行中</span>
        </div>

        <router-link
          to="/evaluation"
          class="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95"
        >
          <BarChart3 class="w-4 h-4 flex-shrink-0" />
          <span class="hidden sm:inline">评测报告</span>
        </router-link>
      </div>
    </header>

    <!-- ========== 面包屑 + 状态总览 ========== -->
    <div class="bg-surface/50 border-b border-border-default px-4 sm:px-6 py-3">
      <!-- 面包屑 -->
      <div class="flex items-center gap-2 text-sm mb-3">
        <template v-for="(crumb, idx) in breadcrumbs" :key="idx">
          <div v-if="idx > 0" class="text-disabled">/</div>
          <span :class="idx === breadcrumbs.length - 1 ? 'text-accent font-medium' : 'text-muted'">
            {{ crumb.label }}
          </span>
        </template>
      </div>
      <!-- KPI 状态条 -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div
          v-for="kpi in statusKPIs"
          :key="kpi.label"
          class="flex items-center gap-3 px-3 py-2 rounded-lg bg-elevated/50 border border-border-default animate-card-in"
          :style="{ animationDelay: `${statusKPIs.indexOf(kpi) * 50}ms` }"
        >
          <div :class="['w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0', `bg-${kpi.color}/10`]">
            <component :is="kpiIconMap[kpi.icon]" class="w-4 h-4" :class="`text-${kpi.color}`" />
          </div>
          <div class="min-w-0">
            <div :class="['text-lg font-bold tabular-nums leading-tight', `text-${kpi.color}`]">{{ kpi.value }}</div>
            <div class="text-xs text-muted leading-tight truncate">{{ kpi.label }}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ========== 移动端侧边栏遮罩 ========== -->
    <div
      v-if="mobileSidebarOpen"
      @click="mobileSidebarOpen = false"
      class="fixed inset-0 top-28 bottom-8 bg-black/50 backdrop-blur-sm z-30 md:hidden"
    ></div>

    <!-- ========== 主体：侧边栏 + 内容区 ========== -->
    <div class="flex flex-1 overflow-hidden">
      <nav
        :class="[
          'bg-surface border-r border-border-default flex flex-col transition-all duration-300 overflow-hidden flex-shrink-0',
          isMobile
            ? mobileSidebarOpen
              ? 'fixed top-28 bottom-8 left-0 w-64 z-40'
              : 'w-0 border-r-0'
            : sidebarCollapsed
              ? 'w-14'
              : 'w-56'
        ]"
      >
        <div class="flex-1 py-3 overflow-y-auto">
          <button
            v-for="(tab, idx) in tabs"
            :key="tab.name"
            @click="switchTab(tab.name)"
            :class="[
              'w-full flex items-center gap-3 px-4 py-3 transition-all duration-200 border-l-2 animate-list-in',
              activeTab === tab.name
                ? 'bg-accent/10 text-accent border-accent'
                : 'text-secondary border-transparent hover:bg-hover hover:text-primary'
            ]"
            :style="{ animationDelay: `${idx * 40}ms` }"
            :title="tab.label"
          >
            <component :is="tabIconMap[tab.icon]" class="w-5 h-5 flex-shrink-0" />
            <div v-if="isMobile || !sidebarCollapsed" class="text-left overflow-hidden">
              <div class="text-sm font-medium">{{ tab.label }}</div>
              <div class="text-xs text-muted truncate">{{ tab.sub }}</div>
            </div>
          </button>
        </div>
      </nav>

      <main class="flex-1 overflow-hidden p-3 sm:p-6">
        <div class="bg-surface rounded-2xl border border-border-default p-4 sm:p-6 h-full overflow-y-auto animate-card-in" :key="activeTab">
          <ChatPanel v-if="activeTab === 'chat'" />
          <SecurityPanel v-else-if="activeTab === 'security'" />
          <ApprovalPanel v-else-if="activeTab === 'approval'" />
          <ToolPanel v-else-if="activeTab === 'tools'" />
          <AuditPanel v-else-if="activeTab === 'audit'" />
        </div>
      </main>
    </div>

    <!-- ========== 命令面板 ========== -->
    <Teleport to="body">
      <Transition name="fade">
        <div
          v-if="showCommandPalette"
          @click.self="showCommandPalette = false"
          class="fixed inset-0 z-[90] flex items-start justify-center pt-[15vh] bg-black/60 backdrop-blur-sm"
        >
          <div class="w-full max-w-xl mx-4 bg-surface rounded-2xl border border-border-default shadow-2xl overflow-hidden">
            <!-- 搜索输入 -->
            <div class="flex items-center gap-3 px-4 py-3 border-b border-border-default">
              <Search class="w-5 h-5 text-muted flex-shrink-0" />
              <input
                v-model="commandQuery"
                ref="commandInput"
                type="text"
                placeholder="搜索功能或操作..."
                class="flex-1 bg-transparent text-primary placeholder:text-disabled outline-none text-sm"
                autofocus
              />
              <kbd class="px-1.5 py-0.5 text-xs bg-canvas rounded border border-border-default font-mono text-muted">ESC</kbd>
            </div>
            <!-- 命令列表 -->
            <div class="max-h-[400px] overflow-y-auto p-2">
              <button
                v-for="(item, idx) in commandItems"
                :key="idx"
                @click="item.action()"
                class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-hover transition-colors text-left group"
              >
                <div class="w-8 h-8 rounded-lg bg-elevated flex items-center justify-center flex-shrink-0">
                  <Zap class="w-4 h-4 text-secondary group-hover:text-accent transition-colors" />
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-sm font-medium text-primary">{{ item.label }}</div>
                  <div class="text-xs text-muted truncate">{{ item.sub }}</div>
                </div>
                <span class="text-xs text-muted bg-elevated px-2 py-0.5 rounded-full flex-shrink-0">{{ item.type }}</span>
              </button>
              <div v-if="commandItems.length === 0" class="py-8 text-center text-muted text-sm">
                未找到匹配项
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- ========== 底栏 ========== -->
    <footer class="h-8 bg-surface border-t border-border-default flex items-center justify-center flex-shrink-0">
      <p class="text-xs text-muted truncate px-2">面向政企场景的大模型智能体安全关键技术研究 · SafeAgent v5.0</p>
    </footer>
  </div>
</template>
