import { ref, type Ref } from 'vue'

export interface StoredBooleanState {
  /** 当前布尔状态 */
  value: Ref<boolean>
  /** 取反并持久化 */
  toggle: () => void
  /** 显式设置并持久化（值未变化时不重复写入） */
  set: (v: boolean) => void
}

function readStored(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function writeStored(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* ignore */
  }
}

/**
 * 带 localStorage 记忆的布尔状态：页面刷新后保持用户最后一次设置（'1' 为 true）。
 * @param key       存储键
 * @param defaultFn 无历史记录时的默认值（支持函数延迟计算，如按视口判断）
 */
export function useStoredBoolean(key: string, defaultFn: () => boolean = () => true): StoredBooleanState {
  const saved = readStored(key)
  const value = ref(saved !== null ? saved === '1' : defaultFn())

  function persist() {
    writeStored(key, value.value ? '1' : '0')
  }

  function toggle() {
    value.value = !value.value
    persist()
  }

  function set(v: boolean) {
    if (value.value === v) return
    value.value = v
    persist()
  }

  return { value, toggle, set }
}
