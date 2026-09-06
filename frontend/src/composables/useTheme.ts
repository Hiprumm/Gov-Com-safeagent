import { ref, watch, onMounted, computed } from 'vue'

type Theme = 'light' | 'dark'

/**
 * 主题管理
 *
 * 防闪烁时序说明（index.html 内联脚本 + 本 composable 协同）：
 * 1. 挂载前 index.html 脚本根据 localStorage/系统偏好给 <html> 预设 class，避免白屏闪烁；
 * 2. 本 composable 必须使用「无 immediate 的 watch」——若用 watchEffect 会在 setup 同步阶段
 *    立即 applyTheme('light')，把持久化偏好（localStorage）覆盖成 light，导致刷新后永远回退浅色。
 * 3. onMounted 读取持久化偏好驱动 watch 应用正确主题。
 */
export function useTheme() {
  const theme = ref<Theme>('light')

  const getPreferredTheme = (): Theme => {
    const saved = localStorage.getItem('theme') as Theme | null
    if (saved === 'light' || saved === 'dark') return saved
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light'
  }

  const applyTheme = (t: Theme) => {
    document.documentElement.classList.remove('light', 'dark')
    document.documentElement.classList.add(t)
    localStorage.setItem('theme', t)
  }

  const toggleTheme = () => {
    theme.value = theme.value === 'light' ? 'dark' : 'light'
  }

  // 挂载后按持久化偏好设置主题 → 触发下方 watch 应用；
  // 再显式应用一次：若偏好恰与初始值相同（light→light），watch 不触发，但需保证 class 与图标同步
  onMounted(() => {
    theme.value = getPreferredTheme()
    applyTheme(theme.value)
  })

  // 主题变化时应用；不使用 immediate，避免覆盖 index.html 预置的持久化主题
  watch(theme, (t) => {
    applyTheme(t)
  })

  return {
    theme,
    toggleTheme,
    isDark: computed(() => theme.value === 'dark'),
  }
}
