import { describe, it, expect, beforeEach, vi } from 'vitest'
import { SESSION_SIDEBAR_KEY, defaultSessionSidebarExpanded, useSessionSidebar } from '@/composables/useSessionSidebar'

function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width })
}

describe('useSessionSidebar（智能问答会话侧边栏收拉状态）', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  describe('默认展开状态（首次使用，无历史记录）', () => {
    it('桌面视口（≥640px）默认展开', () => {
      setViewport(1440)
      const { expanded } = useSessionSidebar()
      expect(expanded.value).toBe(true)
      expect(defaultSessionSidebarExpanded()).toBe(true)
    })

    it('移动视口（<640px）默认收起，避免遮罩遮挡聊天区', () => {
      setViewport(375)
      const { expanded } = useSessionSidebar()
      expect(expanded.value).toBe(false)
      expect(defaultSessionSidebarExpanded()).toBe(false)
    })
  })

  describe('状态记忆恢复（刷新后保持用户最后一次设置）', () => {
    it("历史记录 '0' → 初始收起（即使桌面视口）", () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '0')
      setViewport(1440)
      const { expanded } = useSessionSidebar()
      expect(expanded.value).toBe(false)
    })

    it("历史记录 '1' → 初始展开（即使移动视口）", () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '1')
      setViewport(375)
      const { expanded } = useSessionSidebar()
      expect(expanded.value).toBe(true)
    })

    it('非法存储值视为收起（仅接受 "1" 为展开）', () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, 'abc')
      setViewport(1440)
      const { expanded } = useSessionSidebar()
      expect(expanded.value).toBe(false)
    })
  })

  describe('toggle / close 行为与持久化', () => {
    it('toggle：展开 → 收起，并写入 "0"', () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '1')
      const { expanded, toggle } = useSessionSidebar()
      toggle()
      expect(expanded.value).toBe(false)
      expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('0')
    })

    it('toggle：收起 → 展开，触发 onOpen 回调，并写入 "1"', () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '0')
      const onOpen = vi.fn()
      const { expanded, toggle } = useSessionSidebar(onOpen)
      expect(onOpen).not.toHaveBeenCalled()
      toggle()
      expect(expanded.value).toBe(true)
      expect(onOpen).toHaveBeenCalledTimes(1)
      expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('1')
    })

    it('toggle 收起时不触发 onOpen（仅展开时按需加载）', () => {
      const onOpen = vi.fn()
      const { toggle } = useSessionSidebar(onOpen)
      toggle() // 展开 → 触发
      toggle() // 收起 → 不触发
      expect(onOpen).toHaveBeenCalledTimes(1)
    })

    it('close：展开状态下收起并持久化', () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '1')
      const { expanded, close } = useSessionSidebar()
      close()
      expect(expanded.value).toBe(false)
      expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('0')
    })

    it('close：已收起时不重复操作、不覆盖存储', () => {
      localStorage.setItem(SESSION_SIDEBAR_KEY, '0')
      const { close } = useSessionSidebar()
      close()
      expect(localStorage.getItem(SESSION_SIDEBAR_KEY)).toBe('0')
    })
  })

  describe('存储异常兜底', () => {
    it('localStorage 不可用时默认按视口决定，且交互不抛错', () => {
      const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('storage blocked')
      })
      const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('storage blocked')
      })
      try {
        setViewport(1440)
        const { expanded, toggle } = useSessionSidebar()
        expect(expanded.value).toBe(true)
        expect(() => toggle()).not.toThrow()
        expect(expanded.value).toBe(false)
      } finally {
        getItem.mockRestore()
        setItem.mockRestore()
      }
    })
  })
})
