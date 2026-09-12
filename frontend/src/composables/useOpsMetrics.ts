/**
 * 运维监控 · 指标数据 composable
 *
 * 10s 轮询 /api/metrics（只读，登录 + system.view；熔断期间仍可查看）。
 * 后端为进程内计数：/api/metrics 返回 worker_pid，标注"当前 worker 视图"。
 * 服务运行时长在客户端每秒跳动（以最近一次 uptime_s 为基线，无需额外请求）。
 */
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'

export interface MetricsHttpBucket {
  ts: string
  total: number
  '2xx': number
  '4xx': number
  '5xx': number
}
export interface MetricsDetectBucket {
  ts: string
  total: number
  blocked: number
}
export interface MetricsLlmBucket {
  ts: string
  total: number
  ok: number
  fail: number
  timeout: number
}

export interface MetricsSnapshot {
  uptime_s: number
  worker_pid: number
  http: {
    total: number
    by_prefix: Record<string, number>
    trend: MetricsHttpBucket[]
  }
  detect: {
    total: number
    by_risk: Record<string, number>
    trend: MetricsDetectBucket[]
  }
  llm: {
    total: number
    ok: number
    fail: number
    timeout: number
    switch: number
    avg_ms: number
    p95_ms: number
    trend: MetricsLlmBucket[]
  }
}

export const PREFIX_LABELS: Record<string, string> = {
  'security.detect': '安全检测',
  agent: '智能问答',
  audit: '审计追溯',
  dashboard: '风险看板',
  auth: '认证',
  compliance: '合规报告',
  governance: '应急联动',
  ecosystem: '开放生态',
  pipl: 'PIPL台账',
  model: '模型接入',
  other: '其他',
}

export function useOpsMetrics(intervalMs = 10000) {
  const metrics = ref<MetricsSnapshot | null>(null)
  const loading = ref(false)
  const error = ref('')
  const lastUpdated = ref(0)
  // 服务运行时长实时跳动：以最近一次拉取的 uptime_s 为基线，客户端每秒累计
  const uptimeBase = ref(0)
  const uptimeRefTime = ref(0)
  const nowTick = ref(0)
  let timer: ReturnType<typeof setInterval> | null = null
  let tickTimer: ReturnType<typeof setInterval> | null = null

  const uptimeSeconds = computed(() => {
    void nowTick.value
    if (!uptimeRefTime.value) return uptimeBase.value
    return uptimeBase.value + Math.max(0, Math.floor((Date.now() - uptimeRefTime.value) / 1000))
  })

  async function fetchMetrics(force = false): Promise<void> {
    if (!force && metrics.value && Date.now() - lastUpdated.value < 8000) return
    loading.value = true
    try {
      const res = await axios.get('/ai/metrics')
      metrics.value = res.data as MetricsSnapshot
      uptimeBase.value = res.data?.uptime_s ?? 0
      uptimeRefTime.value = Date.now()
      lastUpdated.value = Date.now()
      error.value = ''
    } catch (e: any) {
      error.value = e?.response?.data?.detail || e?.message || '加载失败'
      console.warn('[OpsMetrics] 指标加载失败:', error.value)
    } finally {
      loading.value = false
    }
  }

  onMounted(() => {
    fetchMetrics(true)
    timer = setInterval(() => fetchMetrics(true), intervalMs)
    tickTimer = setInterval(() => { nowTick.value++ }, 1000)
  })
  onUnmounted(() => {
    if (timer) clearInterval(timer)
    if (tickTimer) clearInterval(tickTimer)
  })

  return { metrics, loading, error, lastUpdated, fetchMetrics, uptimeSeconds }
}
