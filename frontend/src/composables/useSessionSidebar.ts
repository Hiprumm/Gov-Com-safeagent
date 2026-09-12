import { ref, type Ref } from 'vue'

/** 会话侧边栏收拉状态持久化键：刷新页面后保持用户最后一次设置 */
export const SESSION_SIDEBAR_KEY = 'safeagent_chat_session_sidebar'

export interface SessionSidebarState {
  /** 会话侧边栏是否展开 */
  expanded: Ref<boolean>
  /** 展开/收起切换：展开时触发 onOpen 回调（如按需加载会话列表），并同步记忆状态 */
  toggle: () => void
  /** 收起会话列表（各关闭入口统一走此函数，保证状态记忆一致） */
  close: () => void
}

function readStoredValue(): string | null {
  try {
    return localStorage.getItem(SESSION_SIDEBAR_KEY)
  } catch {
    return null
  }
}

function writeStoredValue(value: string) {
  try {
    localStorage.setItem(SESSION_SIDEBAR_KEY, value)
  } catch {
    /* ignore */
  }
}

/**
 * 计算初始展开状态：
 * - 有历史记录时恢复用户最后一次设置（'1' 展开 / '0' 收起）
 * - 首次使用：桌面端默认展开（直观展示收拉控件），移动端默认收起（避免遮罩遮挡聊天区）
 */
export function defaultSessionSidebarExpanded(): boolean {
  const saved = readStoredValue()
  if (saved !== null) return saved === '1'
  return typeof window !== 'undefined' ? window.innerWidth >= 640 : true
}

/** 会话侧边栏收拉状态（localStorage 记忆 + 平滑切换），onOpen 为展开时触发的副作用回调 */
export function useSessionSidebar(onOpen?: () => void): SessionSidebarState {
  const expanded = ref(defaultSessionSidebarExpanded())

  function persist() {
    writeStoredValue(expanded.value ? '1' : '0')
  }

  function toggle() {
    expanded.value = !expanded.value
    if (expanded.value && onOpen) onOpen()
    persist()
  }

  function close() {
    if (!expanded.value) return
    expanded.value = false
    persist()
  }

  return { expanded, toggle, close }
}
