/**
 * 账号与角色认证 Composable
 *
 * - 强制登录：未登录时全局路由守卫拦截，仅可访问登录页（/login），无法使用任何业务功能
 * - 登录：按角色收敛导航（admin 全部 / operator 安全运营 / auditor 审计 / user 业务）
 * - token 持久化于 localStorage，刷新后经 /api/auth/me 恢复身份
 */
import { ref, computed } from 'vue'
import axios from 'axios'
import router from '@/router'
import { toast } from '@/composables/useToast'

export interface AuthUser {
  username: string
  display_name: string
  role: string
  department?: string
  position?: string
}
export interface DemoAccount {
  username: string
  display_name: string
  role: string
  department?: string
  desc: string
}

const TOKEN_KEY = 'auth_token'

const currentUser = ref<AuthUser | null>(null)
const demoAccounts = ref<DemoAccount[]>([])

/** 本地是否持有令牌（同步、可靠的“已登录”判据，供路由守卫使用） */
const hasToken = computed(() => !!localStorage.getItem(TOKEN_KEY))
/** 响应式“是否已登录”：令牌有效（用户身份已恢复）视为已登录 */
const isAuthed = computed(() => !!currentUser.value)

function setToken(t: string) {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

/** 初始化：恢复持久化登录态；无/失效 token 时清空并保留演示账号列表供登录页展示 */
async function initAuth(): Promise<boolean> {
  const token = localStorage.getItem(TOKEN_KEY) || ''
  try {
    const res = await axios.get('/ai/auth/me')
    demoAccounts.value = res.data.demo_accounts || []
    if (res.data.user) {
      currentUser.value = res.data.user
      return true
    } else if (token) {
      // 本地有 token 但服务端不认（重启/过期）→ 清理
      setToken('')
    }
  } catch {
    setToken('')
  }
  currentUser.value = null
  return false
}

/** 登录成功后跳转首页；由路由守卫保证登录前到不了工作台 */
async function login(username: string, password: string): Promise<boolean> {
  try {
    const res = await axios.post('/ai/auth/login', { username, password })
    setToken(res.data.token)
    currentUser.value = res.data.user
    toast.success(`欢迎，${res.data.user.display_name}`)
    router.replace('/')
    return true
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '登录失败，请检查账号与口令')
    return false
  }
}

/** 登出：清令牌并回到登录页 */
async function logout() {
  try {
    if (localStorage.getItem(TOKEN_KEY)) await axios.post('/ai/auth/logout')
  } catch { /* ignore */ }
  setToken('')
  currentUser.value = null
  toast.info('已退出登录')
  router.replace('/login')
}

export function useAuth() {
  return { currentUser, demoAccounts, isAuthed, hasToken, initAuth, login, logout }
}
