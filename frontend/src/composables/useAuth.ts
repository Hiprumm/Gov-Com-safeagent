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
  status?: string
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
/** MFA 二步登录挂起态：密码校验通过但待输入 TOTP 验证码 */
const mfaPending = ref<{ ticket: string; username: string } | null>(null)
/**
 * 认证状态版本号：登录/登出/身份切换时自增。
 * 用于丢弃过期的 initAuth 响应——登录页 onMounted 发出的 /auth/me 请求若在后端慢时
 * 晚于登录完成才返回（user=null），会覆盖掉刚写入的 currentUser，把用户弹回登录页
 * （表现：点击登录不跳转，刷新后因 token 仍在才跳转）。版本号比对可安全丢弃过期响应。
 */
let authEpoch = 0

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
  const epoch = authEpoch
  const token = localStorage.getItem(TOKEN_KEY) || ''
  try {
    const res = await axios.get('/ai/auth/me')
    demoAccounts.value = res.data.demo_accounts || []
    // 请求期间发生了登录/登出等身份变更：本次结果已过期，丢弃以免覆盖新状态
    if (epoch !== authEpoch) return currentUser.value !== null
    if (res.data.user) {
      currentUser.value = res.data.user
      return true
    } else if (token) {
      // 本地有 token 但服务端不认（重启/过期）→ 清理
      setToken('')
    }
  } catch {
    if (epoch !== authEpoch) return currentUser.value !== null
    setToken('')
  }
  if (epoch === authEpoch) currentUser.value = null
  return false
}

/** 登录后跳转：优先客户端路由导航；失败（如懒加载 chunk 加载异常）时硬跳转兜底，保证登录必然离开登录页 */
async function navigateTo(path: string) {
  try {
    await router.replace(path)
  } catch {
    window.location.href = path
  }
}

// ======== 登录口令 RSA-OAEP 传输加密（防明文裸露于传输链路） ========
const PUBKEY_CACHE_KEY = 'safeagent_login_rsa_pubkey'

interface PubKey { kid: string; public_pem: string }

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer
}

/** 取登录公钥：sessionStorage 缓存（按 kid），缺失时向后端获取 */
async function fetchPubKey(): Promise<PubKey | null> {
  try {
    const cachedRaw = sessionStorage.getItem(PUBKEY_CACHE_KEY)
    if (cachedRaw) {
      const cached = JSON.parse(cachedRaw) as PubKey
      if (cached && cached.public_pem) return cached
    }
    const res = await axios.get('/api/auth/pubkey', { timeout: 8000 })
    const pk: PubKey = { kid: res.data.kid, public_pem: res.data.public_pem }
    try { sessionStorage.setItem(PUBKEY_CACHE_KEY, JSON.stringify(pk)) } catch { /* ignore */ }
    return pk
  } catch {
    return null
  }
}

/** 用 WebCrypto 对口令做 RSA-OAEP(SHA-256) 加密；环境不支持或公钥获取失败返回 null（退回明文） */
async function encryptPassword(pubkey: PubKey, password: string): Promise<string | null> {
  try {
    if (!('crypto' in window) || !window.crypto?.subtle) return null
    const key = await window.crypto.subtle.importKey(
      'spki', pemToArrayBuffer(pubkey.public_pem),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
    const data = new TextEncoder().encode(password)
    const enc = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)
    let bin = ''
    new Uint8Array(enc).forEach((b) => (bin += String.fromCharCode(b)))
    return btoa(bin)
  } catch {
    return null
  }
}

/** 登录成功后跳转 redirect（默认首页）；若账号启用 MFA 则进入二步验证（返回 false 并置 mfaPending） */
async function login(username: string, password: string, redirect = '/'): Promise<boolean> {
  try {
    const pubkey = await fetchPubKey()
    let body: Record<string, unknown> = { username }
    const enc = pubkey ? await encryptPassword(pubkey, password) : null
    if (pubkey && enc) {
      body = { username, enc_password: enc, kid: pubkey.kid }
    } else {
      // 公钥不可用（后端未启用/环境不支持）时退回明文，保证登录可用
      body = { username, password }
    }
    const res = await axios.post('/api/auth/login', body)
    // 二步验证：密码通过但需输入 TOTP
    if (res.data?.mfa_required) {
      mfaPending.value = { ticket: res.data.mfa_ticket, username: res.data.username || username }
      return false
    }
    authEpoch++ // 使仍在途的旧 initAuth 响应失效，避免其晚到覆盖本次登录
    setToken(res.data.token)
    currentUser.value = res.data.user
    mfaPending.value = null
    toast.success(`欢迎，${res.data.user.display_name}`)
    await navigateTo(redirect)
    return true
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '登录失败，请检查账号与口令')
    return false
  }
}

/** MFA 二步：校验 TOTP 验证码完成登录 */
async function verifyMfa(code: string, redirect = '/'): Promise<boolean> {
  if (!mfaPending.value) return false
  try {
    const res = await axios.post('/ai/auth/mfa/verify', {
      ticket: mfaPending.value.ticket,
      code: code.trim(),
    })
    authEpoch++ // 使仍在途的旧 initAuth 响应失效
    setToken(res.data.token)
    currentUser.value = res.data.user
    mfaPending.value = null
    toast.success(`欢迎，${res.data.user.display_name}`)
    await navigateTo(redirect)
    return true
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '验证码不正确')
    return false
  }
}

/** 取消 MFA 二步，回到账号口令输入 */
function cancelMfa() {
  mfaPending.value = null
}

/** 数据同步：重新拉取 /api/auth/me 恢复最新身份（个人中心"刷新"、资料编辑后调用） */
async function refreshProfile(): Promise<AuthUser | null> {
  try {
    const res = await axios.get('/ai/auth/me')
    demoAccounts.value = res.data.demo_accounts || []
    if (res.data.user) {
      currentUser.value = res.data.user
      return res.data.user
    }
  } catch { /* 网络异常时保留旧身份，不打断当前会话 */ }
  return null
}

/** 登出：清令牌并回到登录页 */
async function logout() {
  authEpoch++ // 使在途的 initAuth 响应失效，避免其晚到重新写回身份
  try {
    if (localStorage.getItem(TOKEN_KEY)) await axios.post('/ai/auth/logout')
  } catch { /* ignore */ }
  setToken('')
  currentUser.value = null
  mfaPending.value = null
  toast.info('已退出登录')
  router.replace('/login')
}

export function useAuth() {
  return {
    currentUser, demoAccounts, isAuthed, hasToken,
    mfaPending, initAuth, login, verifyMfa, cancelMfa, refreshProfile, logout,
  }
}
