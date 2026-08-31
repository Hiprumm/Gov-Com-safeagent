import { ref, readonly } from 'vue'

export interface Toast {
  id: number
  type: 'success' | 'error' | 'warning' | 'info'
  message: string
  duration: number
}

const toasts = ref<Toast[]>([])
let toastId = 0

function show(message: string, type: Toast['type'] = 'info', duration = 3000) {
  const id = ++toastId
  toasts.value.push({ id, type, message, duration })
  if (duration > 0) {
    setTimeout(() => dismiss(id), duration)
  }
  return id
}

function dismiss(id: number) {
  const idx = toasts.value.findIndex(t => t.id === id)
  if (idx >= 0) {
    toasts.value.splice(idx, 1)
  }
}

// 全局 toast 对象 — 可在组件外使用（main.ts 的 axios 拦截器等）
export const toast = {
  success: (msg: string, d?: number) => show(msg, 'success', d),
  error: (msg: string, d?: number) => show(msg, 'error', d ?? 4000),
  warning: (msg: string, d?: number) => show(msg, 'warning', d),
  info: (msg: string, d?: number) => show(msg, 'info', d),
  dismiss,
}

// composable — 组件内使用，返回只读 toasts 列表
export function useToast() {
  return {
    toasts: readonly(toasts),
    ...toast,
  }
}
