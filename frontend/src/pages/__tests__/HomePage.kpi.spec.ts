import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import HomePage from '@/pages/HomePage.vue'
import { useStoredBoolean } from '@/composables/useStoredBoolean'

export const HOME_KPI_EXPANDED_KEY = 'safeagent_home_kpi_expanded'

// ---- Mock 外部依赖（与 KPI 收拉逻辑无关的副作用全部打桩） ----
const mocks = vi.hoisted(() => ({
  routerPush: vi.fn(),
  routerReplace: vi.fn(),
  toastSuccess: vi.fn(),
  toastInfo: vi.fn(),
}))

// 仅渲染 ChatPanel 桩：避免 <component :is="panelMap[activeTab]"> 挂载真实面板造成级联
vi.mock('@/components/chat/ChatPanel.vue', () => ({
  default: { name: 'ChatPanelStub', template: '<div class="chat-panel-stub" />' },
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: mocks.routerPush,
    replace: mocks.routerReplace,
    currentRoute: { value: { path: '/' } },
  }),
}))

vi.mock('@/composables/useAuth', async () => {
  const { ref } = await import('vue')
  return {
    useAuth: () => ({
      currentUser: ref({ role: 'admin', username: 'admin', display_name: '测试管理员' }),
      initAuth: vi.fn().mockResolvedValue(true),
      logout: vi.fn(),
    }),
  }
})

vi.mock('@/composables/usePermissions', async () => {
  const { ref } = await import('vue')
  const allTabs = ['chat', 'dashboard', 'redteam', 'runtime', 'security', 'tools', 'approval', 'policy', 'system', 'audit', 'governance']
  return {
    usePermissions: () => ({
      modules: ref(allTabs),
      loaded: ref(true),
      fetchPermissions: vi.fn(),
      resetPermissions: vi.fn(),
    }),
  }
})

vi.mock('@/composables/useToast', () => ({
  useToast: () => ({
    toasts: { value: [] },
    success: mocks.toastSuccess,
    info: mocks.toastInfo,
    error: vi.fn(),
    warning: vi.fn(),
    dismiss: vi.fn(),
  }),
}))

vi.mock('@/composables/useTheme', async () => {
  const { ref } = await import('vue')
  return {
    useTheme: () => ({ isDark: ref(false), toggleTheme: vi.fn() }),
  }
})

vi.mock('@/composables/useDashboard', async () => {
  const { ref } = await import('vue')
  const overview = ref({
    success: true,
    scope: { scope: 'all', username: 'admin', display_name: '测试管理员', role: 'admin', department: '', label: '全平台', hint: '' },
    kpi: { today_blocked: 12, pending_approvals: 3, risk_events_today: 1, blocked_rate_24h: 98.5 },
    attack_distribution: {},
    risk_level_distribution: {},
    trend_7d: [],
    recent_events: [],
  })
  return {
    useDashboard: () => ({
      overview,
      loading: ref(false),
      wsConnected: ref(false),
      fetchOverview: vi.fn(),
    }),
    useDashboardRealtime: () => ({ fetchOverview: vi.fn() }),
  }
})

function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
}

/** 挂载 HomePage：补齐 RouterLink 桩（vue-router 已被 mock，避免解析警告） */
function mountHomePage() {
  return shallowMount(HomePage, {
    global: {
      stubs: { RouterLink: { template: '<a><slot /></a>' } },
    },
  })
}

/** 状态总览收拉控制按钮 */
function toggleBtn(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('button[title^="收起状态总览"], button[title^="展开状态总览"]')
}

/** KPI 收拉容器（grid-rows-[1fr] / grid-rows-[0fr] 所在元素） */
function kpiGridWrapper(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('[class*="grid-rows-"]')
}

/** 状态总览外层 section（按钮 → ml-auto 容器 → 面包屑行 → section） */
function sectionEl(wrapper: ReturnType<typeof shallowMount>): HTMLElement {
  return toggleBtn(wrapper).element.parentElement!.parentElement!.parentElement as HTMLElement
}

/** 面包屑行（按钮 → ml-auto 容器 → 面包屑行） */
function breadcrumbRow(wrapper: ReturnType<typeof shallowMount>): HTMLElement {
  return toggleBtn(wrapper).element.parentElement!.parentElement as HTMLElement
}

describe('HomePage 状态总览KPI 上下收拉功能（组件交互）', () => {
  beforeEach(() => {
    localStorage.clear()
    mocks.routerPush.mockReset()
    mocks.routerReplace.mockReset()
    mocks.toastSuccess.mockReset()
    mocks.toastInfo.mockReset()
    setViewport(1440)
  })

  it('首次使用（无记录）默认展开：KPI 可见、按钮显示"收起"、容器占位完整', async () => {
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[1fr]')
    expect(toggleBtn(wrapper).attributes('title')).toContain('收起状态总览')
    expect(toggleBtn(wrapper).attributes('aria-expanded')).toBe('true')
    expect(sectionEl(wrapper).classList.contains('py-3')).toBe(true)
    expect(breadcrumbRow(wrapper).classList.contains('mb-3')).toBe(true)
    // KPI 数据正常渲染（mock 数据：今日拦截 12）
    expect(wrapper.text()).toContain('今日拦截')
    expect(wrapper.text()).toContain('12')
    wrapper.unmount()
  })

  it('localStorage 记忆 "0" → 刷新后保持收起：容器折叠、按钮显示"展开"', async () => {
    localStorage.setItem(HOME_KPI_EXPANDED_KEY, '0')
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[0fr]')
    expect(toggleBtn(wrapper).attributes('title')).toBe('展开状态总览')
    expect(toggleBtn(wrapper).attributes('aria-expanded')).toBe('false')
    // 收起时布局收紧：section 内边距减小、面包屑行去掉底部间距，为下方内容腾出空间
    expect(sectionEl(wrapper).classList.contains('py-2')).toBe(true)
    expect(breadcrumbRow(wrapper).classList.contains('mb-0')).toBe(true)
    wrapper.unmount()
  })

  it('点击按钮收起：容器折叠 + 写入 "0" + 按钮文案/箭头状态变化', async () => {
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    await toggleBtn(wrapper).trigger('click')
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[0fr]')
    expect(localStorage.getItem(HOME_KPI_EXPANDED_KEY)).toBe('0')
    expect(toggleBtn(wrapper).attributes('title')).toBe('展开状态总览')
    expect(toggleBtn(wrapper).attributes('aria-expanded')).toBe('false')
    expect(sectionEl(wrapper).classList.contains('py-2')).toBe(true)
    wrapper.unmount()
  })

  it('再次点击展开：容器恢复 + 写入 "1" + 按钮显示"收起"', async () => {
    localStorage.setItem(HOME_KPI_EXPANDED_KEY, '0')
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    await toggleBtn(wrapper).trigger('click')
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[1fr]')
    expect(localStorage.getItem(HOME_KPI_EXPANDED_KEY)).toBe('1')
    expect(toggleBtn(wrapper).attributes('title')).toContain('收起状态总览')
    expect(toggleBtn(wrapper).attributes('aria-expanded')).toBe('true')
    wrapper.unmount()
  })

  it('记忆状态经真实 useStoredBoolean 读写（与 HomePage 使用同一实现）', () => {
    localStorage.setItem(HOME_KPI_EXPANDED_KEY, '0')
    const { value, toggle } = useStoredBoolean(HOME_KPI_EXPANDED_KEY)
    expect(value.value).toBe(false)
    toggle()
    expect(localStorage.getItem(HOME_KPI_EXPANDED_KEY)).toBe('1')
  })

  it('移动视口（<768px）下收拉功能正常：默认展开、可收起并记忆', async () => {
    setViewport(375)
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[1fr]')
    await toggleBtn(wrapper).trigger('click')
    expect(kpiGridWrapper(wrapper).classes()).toContain('grid-rows-[0fr]')
    expect(localStorage.getItem(HOME_KPI_EXPANDED_KEY)).toBe('0')
    expect(toggleBtn(wrapper).attributes('title')).toBe('展开状态总览')
    wrapper.unmount()
  })
})

// ---- 主侧边栏收起状态持久化（刷新后保持用户最后一次设置） ----
const HOME_SIDEBAR_KEY = 'safeagent_home_sidebar_collapsed'

/** 顶栏"切换侧边栏"按钮 */
function sidebarToggle(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('button[title="切换侧边栏"]')
}

/** 主侧边栏 nav 元素 */
function navEl(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('nav')
}

describe('HomePage 主侧边栏收起状态持久化（组件交互）', () => {
  beforeEach(() => {
    localStorage.clear()
    mocks.routerPush.mockReset()
    mocks.routerReplace.mockReset()
    mocks.toastSuccess.mockReset()
    mocks.toastInfo.mockReset()
    setViewport(1440)
  })

  it('首次使用（无记录）桌面端默认展开：w-56 全宽导航', async () => {
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    expect(navEl(wrapper).classes()).toContain('w-56')
    expect(navEl(wrapper).classes()).not.toContain('w-14')
    wrapper.unmount()
  })

  it('localStorage 记忆 "1" → 刷新后保持收起：w-14 窄导航', async () => {
    localStorage.setItem(HOME_SIDEBAR_KEY, '1')
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    expect(navEl(wrapper).classes()).toContain('w-14')
    expect(navEl(wrapper).classes()).not.toContain('w-56')
    wrapper.unmount()
  })

  it('点击顶栏按钮收起：宽度切换 + 写入 "1"；再次点击展开写入 "0"', async () => {
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    await sidebarToggle(wrapper).trigger('click')
    expect(navEl(wrapper).classes()).toContain('w-14')
    expect(localStorage.getItem(HOME_SIDEBAR_KEY)).toBe('1')
    await sidebarToggle(wrapper).trigger('click')
    expect(navEl(wrapper).classes()).toContain('w-56')
    expect(localStorage.getItem(HOME_SIDEBAR_KEY)).toBe('0')
    wrapper.unmount()
  })

  it('移动视口下点击顶栏按钮只控制遮罩侧边栏，不写入持久化键', async () => {
    setViewport(375)
    const wrapper = mountHomePage()
    await wrapper.vm.$nextTick()
    await sidebarToggle(wrapper).trigger('click')
    expect(localStorage.getItem(HOME_SIDEBAR_KEY)).toBeNull()
    wrapper.unmount()
  })
})
