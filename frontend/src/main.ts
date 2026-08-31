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
  return config
})

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    let msg: string
    if (status === 401) {
      msg = '认证失败，请在设置中配置 API Key'
    } else if (status === 429) {
      msg = '请求过于频繁，请稍后再试'
    } else if (status && status >= 500) {
      msg = '服务器异常，请稍后重试'
    } else {
      msg = error.response?.data?.detail || error.message || '网络错误'
    }
    console.error(`[${status || 'NET'}] ${msg}`)
    // 全局错误反馈（401 等业务错误已由调用方处理时可覆盖）
    if (status !== 401) {
      toast.error(msg)
    } else {
      toast.warning(msg)
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
