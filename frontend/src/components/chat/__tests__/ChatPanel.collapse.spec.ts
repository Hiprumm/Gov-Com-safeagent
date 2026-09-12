import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import ChatPanel from '@/components/chat/ChatPanel.vue'
import { SESSION_SIDEBAR_KEY } from '@/composables/useSessionSidebar'

// ---- Mock 外部依赖（chat 面板与收拉逻辑无关的副作用全部打桩） ----
const mocks = vi.hoisted(() => ({
  axiosGet: vi.fn(),
  axiosPost: vi.fn(),
  axiosDelete: vi.fn(),
  toastSuccess: vi.fn(),
  wsConnect: vi.fn(),
  renderMarkdown: vi.fn(),
}))

vi.mock('axios', () => ({
  default: {
    get: mocks.axiosGet,
    post: mocks.axiosPost,
    delete: mocks.axiosDelete,
  },
}))

vi.mock('@/composables/useToast', () => ({
  toast: {
    success: mocks.toastSuccess,
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  },
}))

vi.mock('@/composables/useWebSocket', async () => {
  const { ref } = await import('vue')
  return {
    useWebSocket: () => ({
      connect: mocks.wsConnect,
      onEvent: vi.fn(),
      subscribe: vi.fn(),
      connectionStatus: ref('disconnected'),
      disconnect: vi.fn(),
    }),
  }
})

vi.mock('@/utils/markdown', () => ({
  renderMarkdown: mocks.renderMarkdown,
}))

function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
}

/** 会话侧边栏容器（h3 → 头部 → 侧边栏容器）的 class 列表 */
function sidebarClasses(wrapper: ReturnType<typeof shallowMount>): string[] {
  const el = wrapper.find('h3').element.parentElement?.parentElement
  return el ? Array.from(el.classList) : []
}

/** 工具栏"历史会话"收拉按钮：按当前 title 前缀匹配（收起/展开两种文案） */
function toolbarToggle(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('button[title^="收起历史会话列表"], button[title^="展开历史会话列表"]')
}

/** 侧边栏头部箭头收拉按钮 */
function headerToggle(wrapper: ReturnType<typeof shallowMount>) {
  return wrapper.find('button[title^="收起会话列表"], button[title="展开会话列表"]')
}

describe('ChatPanel 会话侧边栏收拉功能（组件交互）', () => {
  beforeEach(() => {
    localStorage.clear()
    mocks.axiosGet.mockReset()
    mocks.axiosGet.mockResolvedValue({ data: { sessions: [] } })
    mocks.axiosPost.mockReset()
    mocks.axiosPost.mockResolvedValue({ data: {} })
    mocks.axiosDelete.mockReset()
    mocks.axiosDelete.mockResolvedValue({ data: {} })
    mocks.renderMarkdown.mockImplementation((md: string) => md)
    setViewport(1440)
  })

  it('首次使用（无记录）桌面端默认展开：侧边栏占位、控制按钮显示"收起"', async () => {
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    const cls = sidebarClasses(wrapper)
    expect(cls).toContain('sm:w-72') // 展开宽度
    expect(cls).not.toContain('sm:w-0')
    expect(headerToggle(wrapper).attributes('title')).toContain('收起会话列表')
    expect(toolbarToggle(wrapper).attributes('title')).toContain('收起历史会话列表')
    wrapper.unmount()
  })

  it('localStorage 记忆 "0" → 刷新后保持收起', async () => {
    localStorage.setItem(SESSION_SIDEBAR_KEY, '0')
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    const cls = sidebarClasses(wrapper)
    expect(cls).toContain('sm:w-0') // 收起宽度
    expect(cls).toContain('sm:border-r-0')
    expect(headerToggle(wrapper).attributes('title')).toBe('展开会话列表')
    expect(toolbarToggle(wrapper).attributes('title')).toContain('展开历史会话列表')
    wrapper.unmount()
  })

  it('点击工具栏按钮收起：宽度类切换 + 写入 "0" + 按钮文案变化', async () => {
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    await toolbarToggle(wrapper).trigger('click')
    expect(sidebarClasses(wrapper)).toContain('sm:w-0')
    expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('0')
    expect(toolbarToggle(wrapper).attributes('title')).toContain('展开历史会话列表')
    wrapper.unmount()
  })

  it('再次点击展开：宽度恢复 + 写入 "1" + 按需加载会话列表', async () => {
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    await toolbarToggle(wrapper).trigger('click') // 收起
    expect(mocks.axiosGet).not.toHaveBeenCalledWith('/ai/agent/sessions')
    await toolbarToggle(wrapper).trigger('click') // 展开 → onOpen 触发 loadSessions
    expect(sidebarClasses(wrapper)).toContain('sm:w-72')
    expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('1')
    expect(mocks.axiosGet).toHaveBeenCalledWith('/ai/agent/sessions')
    wrapper.unmount()
  })

  it('侧边栏头部箭头按钮同样可收拉', async () => {
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    await headerToggle(wrapper).trigger('click') // 收起
    expect(sidebarClasses(wrapper)).toContain('sm:w-0')
    expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('0')
    await headerToggle(wrapper).trigger('click') // 展开
    expect(sidebarClasses(wrapper)).toContain('sm:w-72')
    expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('1')
    wrapper.unmount()
  })

  it('移动视口 + 无记录 → 默认收起（遮罩不渲染）', async () => {
    setViewport(375)
    const wrapper = shallowMount(ChatPanel)
    await wrapper.vm.$nextTick()
    expect(sidebarClasses(wrapper)).toContain('sm:w-0')
    expect(toolbarToggle(wrapper).attributes('title')).toContain('展开历史会话列表')
    wrapper.unmount()
  })
})
