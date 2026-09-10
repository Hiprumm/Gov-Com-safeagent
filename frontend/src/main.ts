import { createApp } from 'vue'
import axios from 'axios'
import './style.css'
import App from './App.vue'
import router from './router'
import { toast } from './composables/useToast'

// ======== 全局 axios 拦截器（统一鉴权与错误反馈） ========
axios.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('x_api_key') || ''
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }
  const authToken = localStorage.getItem('auth_token') || ''
  if (authToken) {
    config.headers['X-Auth-Token'] = authToken
  }
  return config
})

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    let msg: string
    if (status === 401) {
      // 401：登录失败或令牌失效，已由认证层（登录页/守卫）统一引导，此处不再重复弹窗
      msg = '登录已失效，请重新登录'
    } else if (status === 429) {
      msg = '请求过于频繁，请稍后再试'
    } else if (status && status >= 500) {
      msg = '服务器异常，请稍后重试'
    } else {
      msg = error.response?.data?.detail || error.message || '网络错误'
    }
    console.warn(`[${status || 'NET'}] ${msg}`)
    // 全局错误反馈：401 由认证层处理；登录接口的错误由登录页统一提示，避免重复弹窗
    const isAuthLogin = (error.config?.url || '').includes('/auth/login')
    if (status !== 401 && !isAuthLogin) {
      toast.error(msg)
    }
    return Promise.reject(error)
  }
)

// 创建Vue应用实例
const app = createApp(App)

// 全局错误处理器 — 捕获未处理异常，避免白屏
app.config.errorHandler = (err, _instance, info) => {
  console.error('[Vue Error]', info, err)
  toast.error('界面异常，请刷新页面重试')
}

// 使用路由
app.use(router)

// 挂载应用
app.mount('#app')
