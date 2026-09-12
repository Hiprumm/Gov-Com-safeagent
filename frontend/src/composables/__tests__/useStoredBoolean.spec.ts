import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useStoredBoolean } from '@/composables/useStoredBoolean'

describe('useStoredBoolean（localStorage 记忆布尔状态）', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  describe('默认值（首次使用，无历史记录）', () => {
    it('无历史记录时使用默认值（默认 true）', () => {
      const { value } = useStoredBoolean('test.key')
      expect(value.value).toBe(true)
    })

    it('支持自定义默认函数（如按视口判断）', () => {
      const { value } = useStoredBoolean('test.key', () => false)
      expect(value.value).toBe(false)
    })
  })

  describe('状态记忆恢复（刷新后保持用户最后一次设置）', () => {
    it("历史记录 '1' → 初始为 true", () => {
      localStorage.setItem('test.key', '1')
      const { value } = useStoredBoolean('test.key')
      expect(value.value).toBe(true)
    })

    it("历史记录 '0' → 初始为 false（覆盖默认 true）", () => {
      localStorage.setItem('test.key', '0')
      const { value } = useStoredBoolean('test.key')
      expect(value.value).toBe(false)
    })

    it('非法存储值视为 false（仅接受 "1" 为 true）', () => {
      localStorage.setItem('test.key', 'abc')
      const { value } = useStoredBoolean('test.key')
      expect(value.value).toBe(false)
    })
  })

  describe('toggle / set 行为与持久化', () => {
    it('toggle：true → false 并写入 "0"', () => {
      localStorage.setItem('test.key', '1')
      const { value, toggle } = useStoredBoolean('test.key')
      toggle()
      expect(value.value).toBe(false)
      expect(localStorage.getItem('test.key')).toBe('0')
    })

    it('toggle：false → true 并写入 "1"', () => {
      localStorage.setItem('test.key', '0')
      const { value, toggle } = useStoredBoolean('test.key')
      toggle()
      expect(value.value).toBe(true)
      expect(localStorage.getItem('test.key')).toBe('1')
    })

    it('set 显式设置并持久化', () => {
      const { value, set } = useStoredBoolean('test.key')
      set(false)
      expect(value.value).toBe(false)
      expect(localStorage.getItem('test.key')).toBe('0')
    })

    it('set 相同值时不再重复写入存储', () => {
      localStorage.setItem('test.key', '0')
      const setItem = vi.spyOn(Storage.prototype, 'setItem')
      try {
        const { set } = useStoredBoolean('test.key')
        set(false)
        expect(setItem).not.toHaveBeenCalled()
      } finally {
        setItem.mockRestore()
      }
    })
  })

  describe('存储异常兜底', () => {
    it('localStorage 不可用时读写不抛错，交互正常', () => {
      const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('storage blocked')
      })
      const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('storage blocked')
      })
      try {
        const { value, toggle, set } = useStoredBoolean('test.key')
        expect(value.value).toBe(true)
        expect(() => toggle()).not.toThrow()
        expect(value.value).toBe(false)
        expect(() => set(true)).not.toThrow()
        expect(value.value).toBe(true)
      } finally {
        getItem.mockRestore()
        setItem.mockRestore()
      }
    })
  })
})
