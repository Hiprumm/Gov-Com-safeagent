<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import {
  Menu, Search, BarChart3, Zap,
  ShieldX, Clock, AlertTriangle, ShieldCheck,
  MessageSquare, Shield, Settings, FileText, ClipboardCheck,
  Sun, Moon, LayoutDashboard, Swords, SlidersHorizontal, Activity, Server, LogIn, LogOut,
} from 'lucide-vue-next'
import ChatPanel from '@/components/chat/ChatPanel.vue'
import DashboardPanel from '@/components/dashboard/DashboardPanel.vue'
import RedTeamPanel from '@/components/redteam/RedTeamPanel.vue'
import PolicyPanel from '@/components/policy/PolicyPanel.vue'
import RuntimePanel from '@/components/runtime/RuntimePanel.vue'
import SecurityPanel from '@/components/security/SecurityPanel.vue'
import ApprovalPanel from '@/components/approval/ApprovalPanel.vue'
import AuditPanel from '@/components/audit/AuditPanel.vue'
import ToolPanel from '@/components/tools/ToolPanel.vue'
import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'
import NotificationBell from '@/components/notify/NotificationBell.vue'
import GuideBanner from '@/components/onboarding/GuideBanner.vue'
import AccountSecurityModal from '@/components/account/AccountSecurityModal.vue'
import { useAuth } from '@/composables/useAuth'
import { usePermissions } from '@/composables/usePermissions'
import { useRouter } from 'vue-router'
import { useToast } from '@/composables/useToast'
import { useTheme } from '@/composables/useTheme'
import { useDashboard, useDashboardRealtime } from '@/composables/useDashboard'

const { isDark, toggleTheme } = useTheme()

// 图标映射 — 统一图标系统，避免内联 SVG 重复
const tabIconMap: Record<string, any> = {
  chat: MessageSquare,
  dashboard: LayoutDashboard,
  redteam: Swords,
  runtime: Activity,
  security: Shield,
  tools: Settings,
  approval: ClipboardCheck,
  policy: SlidersHorizontal,
  system: Server,
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
  { name: 'dashboard', label: '风险看板', sub: '安全态势实时总览', icon: 'dashboard', group: '安全运营' },
  { name: 'runtime', label: '运行时监控', sub: '执行链路 · 人工熔断', icon: 'runtime', group: '安全运营' },
  { name: 'security', label: '安全检测', sub: '输入 + 供应链', icon: 'security', group: '安全运营' },
  { name: 'redteam', label: '红队测试', sub: '攻防对抗 · 批量回归', icon: 'redteam', group: '安全运营' },
  { name: 'tools', label: '工具管控', sub: '风险评估 + 能力矩阵', icon: 'tools', group: '安全运营' },
  { name: 'approval', label: '审批中心', sub: '人工审批 · 令牌授予', icon: 'approval', group: '安全运营' },
  { name: 'audit', label: '审计追溯', sub: '过程可审计·责任可追溯', icon: 'audit', group: '合规审计' },
  { name: 'policy', label: '策略配置', sub: '阈值/开关 · 热生效', icon: 'policy', group: '系统配置' },
  { name: 'system', label: '系统状态', sub: '自检 · 数据维护', icon: 'system', group: '系统配置' },
]

const currentTab = computed(() => tabs.find(t => t.name === activeTab.value))

// ---- 账号 / 角色体系（强制登录）：只有登录用户能进入本工作台，导航按角色收敛 ----
const router = useRouter()
const { currentUser, initAuth, logout } = useAuth()
// 统一权限：可见模块/数据范围/操作权限均由后端权限引擎决定
const { modules: permModules, loaded: permLoaded, fetchPermissions, resetPermissions } = usePermissions()

// 本地回退表：仅在后端权限暂未返回时兜底，避免首屏空白；后端返回后以其为准（单一事实来源）
const ROLE_ALLOWED_TABS: Record<string, string[]> = {
  admin: tabs.map(t => t.name),
  operator: ['chat', 'dashboard', 'runtime', 'security', 'tools', 'approval', 'audit'],
  auditor: ['chat', 'dashboard', 'audit', 'approval'],
  manager: ['chat', 'dashboard', 'audit', 'approval'],
  user: ['chat', 'dashboard', 'audit'],
}
const effectiveAllow = computed<string[]>(() => {
  if (permLoaded.value && permModules.value.length) return permModules.value
  const role = currentUser.value?.role || ''
  return ROLE_ALLOWED_TABS[role] || []
})
const visibleTabs = computed(() => {
  const allow = effectiveAllow.value
  return tabs.filter(t => allow.includes(t.name))
})
// 登录角色切换后：拉取后端权限并校验当前模块；权限失效则回落至智能问答
watch(currentUser, async () => {
  if (!currentUser.value) {
    resetPermissions()
    // 登录态丢失（token 被服务端清理/过期）→ 回到登录页
    if (router.currentRoute.value.path !== '/login') router.replace('/login')
    return
  }
  await fetchPermissions()
  if (!effectiveAllow.value.includes(activeTab.value)) activeTab.value = 'chat'
})
const userLogout = () => { logout() }
const showAccountSecurity = ref(false)
const roleLabel = (r?: string) =>
  ({ admin: '管理员', operator: '安全运维', auditor: '合规审计', manager: '部门负责人', user: '业务用户' } as Record<string, string>)[r || ''] || ''

// ---- 首次使用引导（P1-3） ----
const showGuide = ref(true)
try { if (localStorage.getItem('guide_done')) showGuide.value = false } catch { /* ignore */ }
const dismissGuide = () => {
  showGuide.value = false
  try { localStorage.setItem('guide_done', '1') } catch { /* ignore */ }
}
const guideGoto = (tab: string) => { switchTab(tab) }
const showGuideAgain = () => {
  showGuide.value = true
  try { localStorage.removeItem('guide_done') } catch { /* ignore */ }
}

// 面板组件映射：KeepAlive 缓存各面板实例，切换模块不销毁状态
// （会话/选中项/测试历史在 tab 间保留，仅页面刷新时重置）
const panelMap: Record<string, any> = {
  chat: ChatPanel,
  dashboard: DashboardPanel,
  redteam: RedTeamPanel,
  runtime: RuntimePanel,
  security: SecurityPanel,
  approval: ApprovalPanel,
  tools: ToolPanel,
  policy: PolicyPanel,
  system: SystemStatusPanel,
  audit: AuditPanel,
}

// 入场动画交替类名：类名变化才会重新触发 animation（见 style.css animate-card-in-b）
const animFlip = ref(false)
watch(activeTab, () => { animFlip.value = !animFlip.value })

// 面包屑
const breadcrumbs = computed(() => [
  { label: 'SafeAgent', icon: true },
  { label: currentTab.value?.group || '' },
  { label: currentTab.value?.label || '' },
])

// 状态总览KPI — 实时来自 /api/dashboard/overview（30s 轮询 + WebSocket 即时刷新）
const { overview } = useDashboard()
useDashboardRealtime()

const statusKPIs = computed(() => {
  const kpi = overview.value?.kpi
  return [
    { label: '今日拦截', value: kpi?.today_blocked ?? '—', color: 'critical', icon: 'block' },
    { label: '待审批', value: kpi?.pending_approvals ?? '—', color: 'medium', icon: 'pending' },
    { label: '风险事件', value: kpi?.risk_events_today ?? '—', color: 'high', icon: 'warning' },
    { label: '24h拦截率', value: kpi ? `${kpi.blocked_rate_24h}%` : '—', color: 'safe', icon: 'health' },
  ]
})

// 数据收敛视角标签（由后端按当前登录角色返回）
const dataScopeLabel = computed(() => {
  const s = overview.value?.scope
  if (!s) return ''
  if (s.scope === 'all') return '全平台视角'
  if (s.scope === 'self') return '仅本人视角'
  return `本部门视角：${s.department || ''}`.trim()
})

// 命令面板
const commandItems = computed(() => {
  const allItems = [
    ...visibleTabs.value.map(t => ({ label: t.label, sub: t.sub, action: () => switchTab(t.name), type: '导航' })),
    { label: '评测报告', sub: '查看检测评测结果', action: () => window.open('/evaluation', '_self'), type: '导航' },
    { label: '新手引导', sub: '重新查看首次使用引导', action: () => { showGuideAgain() }, type: '操作' },
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

onMounted(async () => {
  checkMobile()
  const ok = await initAuth()
  if (ok) await fetchPermissions()
  window.addEventListener('resize', checkMobile)
  window.addEventListener('keydown', handleKeydown)
})
onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
  window.removeEventListener('keydown', handleKeydown)
})
</script>

<template>
  <div class="h-screen flex flex-col bg-canvas text-primary overflow-hidden">
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

        <!-- 通知中心 -->
        <NotificationBell />

        <!-- 后台管理（仅系统管理员） -->
        <button
          v-if="currentUser?.role === 'admin'"
          @click="router.push('/admin/users')"
          class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-xs sm:text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95 flex-shrink-0"
          title="进入用户与组织管理后台"
        >
          <Settings class="w-4 h-4 flex-shrink-0" />
          <span class="hidden sm:inline">后台管理</span>
        </button>

        <!-- 用户身份 / 登录 -->
        <template v-if="currentUser">
          <div
            class="flex items-center gap-1.5 px-1.5 sm:px-2 py-1 rounded-full bg-elevated/60 border border-border-default"
            :title="`${currentUser.display_name}（${roleLabel(currentUser.role)}）`"
          >
            <span class="w-6 h-6 rounded-full bg-gradient-to-br from-accent to-low flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
              {{ currentUser.display_name.slice(0, 1) }}
            </span>
            <span class="hidden lg:inline text-xs font-medium text-primary max-w-[96px] truncate">{{ currentUser.display_name }}</span>
            <span class="hidden xl:inline text-[10px] px-1.5 py-0.5 rounded-full bg-accent/10 text-accent font-medium">{{ roleLabel(currentUser.role) }}</span>
          </div>
          <button
            @click="showAccountSecurity = true"
            class="p-1.5 rounded-lg hover:bg-hover transition-colors text-muted hover:text-accent flex-shrink-0 active:scale-95"
            title="账号安全（MFA / 改密）"
          >
            <ShieldCheck class="w-4 h-4" />
          </button>
          <button
            @click="userLogout"
            class="p-1.5 rounded-lg hover:bg-hover transition-colors text-muted hover:text-critical flex-shrink-0 active:scale-95"
            title="退出登录"
          >
            <LogOut class="w-4 h-4" />
          </button>
        </template>
        <button
          v-else
          @click="router.push('/login')"
          class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-xs sm:text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95 flex-shrink-0"
          title="重新登录"
        >
          <LogIn class="w-4 h-4 flex-shrink-0" />
          <span class="hidden sm:inline">重新登录</span>
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
    <div class="bg-surface/50 border-b border-border-default px-4 sm:px-6 py-3 flex-shrink-0">
      <!-- 面包屑 + 数据视角 -->
      <div class="flex items-center gap-2 text-sm mb-3">
        <template v-for="(crumb, idx) in breadcrumbs" :key="idx">
          <div v-if="idx > 0" class="text-disabled">/</div>
          <span :class="idx === breadcrumbs.length - 1 ? 'text-accent font-medium' : 'text-muted'">
            {{ crumb.label }}
          </span>
        </template>
        <div class="ml-auto"></div>
        <span
          v-if="dataScopeLabel"
          class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[11px] font-medium bg-accent/10 text-accent border-accent/25"
          title="按当前登录角色收敛：admin/operator/auditor=全平台，manager=本部门，user=仅本人"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-current opacity-70"></span>
          {{ dataScopeLabel }}
        </span>
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

    <!-- ========== 首次使用引导横幅 ========== -->
    <GuideBanner v-if="showGuide" @close="dismissGuide" @goto="guideGoto" />

    <!-- 账号安全（MFA / 改密） -->
    <AccountSecurityModal v-if="showAccountSecurity" @close="showAccountSecurity = false" />

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
            v-for="(tab, idx) in visibleTabs"
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

      <main class="flex-1 overflow-hidden p-3 sm:p-6 min-h-0">
        <div
          class="bg-surface rounded-2xl border border-border-default p-4 sm:p-6 h-full overflow-x-hidden overflow-y-auto"
          :class="animFlip ? 'animate-card-in-b' : 'animate-card-in'"
        >
          <KeepAlive>
            <component :is="panelMap[activeTab]" />
          </KeepAlive>
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
