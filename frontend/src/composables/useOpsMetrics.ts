/**
 * 运维监控 · 指标数据 composable
 *
 * 30s 轮询 /api/metrics（只读，登录 + system.view；熔断期间仍可查看）。
 * 后端为进程内计数：/api/metrics 返回 worker_pid，标注"当前 worker 视图"。
 */
import { ref, onMounted, onUnmounted } from 'vue'
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

export function useOpsMetrics(intervalMs = 30000) {
  const metrics = ref<MetricsSnapshot | null>(null)
  const loading = ref(false)
  const error = ref('')
  const lastUpdated = ref(0)
  let timer: ReturnType<typeof setInterval> | null = null

  async function fetchMetrics(force = false): Promise<void> {
    if (!force && metrics.value && Date.now() - lastUpdated.value < 8000) return
    loading.value = true
    try {
      const res = await axios.get('/ai/metrics')
      metrics.value = res.data as MetricsSnapshot
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
  })
  onUnmounted(() => {
    if (timer) clearInterval(timer)
  })

  return { metrics, loading, error, lastUpdated, fetchMetrics }
}
