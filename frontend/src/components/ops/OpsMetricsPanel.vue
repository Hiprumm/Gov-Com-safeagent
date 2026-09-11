<script setup lang="ts">
/**
 * 安全管控台 · 运维监控（可观测性大盘）
 * 实时展示 HTTP 请求量/错误率、检测拦截、LLM 调用成功率与容灾切换、服务运行时长。
 * 数据源：/api/metrics（进程内计数，标注当前 worker 视图）。
 */
import { computed } from 'vue'
import {
  Server, AlertTriangle, Gauge, ShieldX, ShieldCheck,
  Clock, RefreshCw, Activity, Cpu,
} from 'lucide-vue-next'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart, BarChart } from 'echarts/charts'
import {
  GridComponent, TooltipComponent, LegendComponent,
} from 'echarts/components'
import VChart from 'vue-echarts'
import { useOpsMetrics, PREFIX_LABELS } from '@/composables/useOpsMetrics'
import { useToast } from '@/composables/useToast'

use([CanvasRenderer, LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent])

const { metrics, loading, error, fetchMetrics } = useOpsMetrics(30000)
const { success } = useToast()

// 图表配色（与风险看板一致）
const BLUE = '#3b82f6'
const CYAN = '#06b6d4'
const RED = '#ef4444'
const AMBER = '#f59e0b'
const GREEN = '#22c55e'
const PURPLE = '#a855f7'
const TEXT_DIM = '#94a3b8'

function fmtDuration(sec: number): string {
  if (!sec) return '—'
  if (sec < 60) return `${sec} 秒`
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟`
  if (sec < 86400) return `${Math.floor(sec / 3600)} 时 ${Math.floor((sec % 3600) / 60)} 分`
  return `${Math.floor(sec / 86400)} 天 ${Math.floor((sec % 86400) / 3600)} 时`
}
function fmtTs(ts: string): string {
  return ts ? ts.slice(11, 16) : ''
}

const http = computed(() => metrics.value?.http)
const detect = computed(() => metrics.value?.detect)
const llm = computed(() => metrics.value?.llm)

const httpErrorRate = computed(() => {
  const h = http.value
  if (!h || !h.total) return 0
  const err = h.trend.reduce((acc, t) => acc + (t['4xx'] || 0) + (t['5xx'] || 0), 0)
  return (err / h.total) * 100
})
const llmSuccessRate = computed(() => {
  const l = llm.value
  if (!l || !l.total) return 0
  return (l.ok / l.total) * 100
})
const blockedTotal = computed(() => detect.value?.trend.reduce((acc, t) => acc + t.blocked, 0) || 0)

const kpiCards = computed(() => [
  { label: 'HTTP 总请求', value: http.value?.total ?? 0, color: 'accent', icon: Server },
  { label: 'HTTP 错误率', value: `${httpErrorRate.value.toFixed(2)}%`, color: httpErrorRate.value > 5 ? 'critical' : 'safe', icon: AlertTriangle },
  { label: '检测总量', value: detect.value?.total ?? 0, color: 'high', icon: Gauge },
  { label: '检测拦截', value: blockedTotal.value, color: 'critical', icon: ShieldX },
  { label: 'LLM 成功率', value: `${llmSuccessRate.value.toFixed(1)}%`, color: llmSuccessRate.value >= 95 ? 'safe' : 'medium', icon: ShieldCheck },
  { label: 'LLM 平均延迟', value: llm.value ? `${llm.value.avg_ms.toFixed(0)}ms` : '—', color: 'accent2', icon: Clock },
  { label: '容灾切换次数', value: llm.value?.switch ?? 0, color: llm.value?.switch ? 'medium' : 'safe', icon: RefreshCw },
  { label: '服务运行时长', value: fmtDuration(metrics.value?.uptime_s || 0), color: 'safe', icon: Activity },
])

// HTTP 请求趋势（近 24h 分钟级）
const httpTrendOption = computed(() => {
  const trend = http.value?.trend || []
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: ['2xx', '4xx', '5xx'], textStyle: { color: TEXT_DIM }, top: 0 },
    grid: { left: 40, right: 20, top: 34, bottom: 30 },
    xAxis: {
      type: 'category',
      data: trend.map(t => fmtTs(t.ts)),
      axisLabel: { color: TEXT_DIM },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: TEXT_DIM },
      splitLine: { lineStyle: { color: 'rgba(148,163,184,0.15)' } },
    },
    series: [
      { name: '2xx', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t['2xx']), lineStyle: { width: 2, color: GREEN }, itemStyle: { color: GREEN } },
      { name: '4xx', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t['4xx']), lineStyle: { width: 2, color: AMBER }, itemStyle: { color: AMBER } },
      { name: '5xx', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t['5xx']), lineStyle: { width: 2, color: RED }, itemStyle: { color: RED } },
    ],
  }
})

// 接口请求分布
const prefixBarOption = computed(() => {
  const byPrefix = http.value?.by_prefix || {}
  const entries = Object.entries(byPrefix).sort((a, b) => b[1] - a[1])
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 90, right: 20, top: 10, bottom: 30 },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: TEXT_DIM },
      splitLine: { lineStyle: { color: 'rgba(148,163,184,0.15)' } },
    },
    yAxis: {
      type: 'category',
      data: entries.map(([k]) => PREFIX_LABELS[k] || k),
      axisLabel: { color: TEXT_DIM },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    series: [{
      type: 'bar',
      data: entries.map(([, v]) => v),
      itemStyle: { color: BLUE, borderRadius: [0, 4, 4, 0] },
      barMaxWidth: 18,
    }],
  }
})

// LLM 调用趋势（近 24h）
const llmTrendOption = computed(() => {
  const trend = llm.value?.trend || []
  return {
    tooltip: { trigger: 'axis' },
    legend: { data: ['成功', '失败', '超时'], textStyle: { color: TEXT_DIM }, top: 0 },
    grid: { left: 40, right: 20, top: 34, bottom: 30 },
    xAxis: {
      type: 'category',
      data: trend.map(t => fmtTs(t.ts)),
      axisLabel: { color: TEXT_DIM },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: TEXT_DIM },
      splitLine: { lineStyle: { color: 'rgba(148,163,184,0.15)' } },
    },
    series: [
      { name: '成功', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t.ok), lineStyle: { width: 2, color: GREEN }, itemStyle: { color: GREEN } },
      { name: '失败', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t.fail), lineStyle: { width: 2, color: RED }, itemStyle: { color: RED } },
      { name: '超时', type: 'line', smooth: true, showSymbol: false, data: trend.map(t => t.timeout), lineStyle: { width: 2, color: AMBER, type: 'dashed' }, itemStyle: { color: AMBER } },
    ],
  }
})

async function refresh() {
  await fetchMetrics(true)
  success('指标数据已刷新')
}
</script>

<template>
  <div class="space-y-5">
    <!-- 标题栏 -->
    <div class="flex items-center justify-between flex-wrap gap-3">
      <div>
        <h2 class="text-lg font-bold text-primary flex items-center gap-2">
          <Activity class="w-5 h-5 text-accent" />
          运维监控 · 可观测性大盘
        </h2>
        <p class="text-sm text-muted mt-0.5">请求量 · 检测拦截 · LLM 调用与容灾 · 服务可用性（30s 自动刷新）</p>
        <div
          v-if="metrics"
          class="mt-2 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-border-default text-xs text-muted"
        >
          <Cpu class="w-3.5 h-3.5" />
          当前 Worker 视图（PID {{ metrics.worker_pid }}）· 服务已运行 {{ fmtDuration(metrics.uptime_s) }}
        </div>
      </div>
      <div class="flex items-center gap-3">
        <span v-if="error" class="text-xs text-critical">{{ error }}</span>
        <button
          @click="refresh"
          :disabled="loading"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95 disabled:opacity-50"
        >
          <RefreshCw class="w-4 h-4" :class="loading ? 'animate-spin' : ''" />
          刷新
        </button>
      </div>
    </div>

    <!-- KPI 卡片 -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div
        v-for="(kpi, idx) in kpiCards"
        :key="kpi.label"
        class="flex items-center gap-3 px-4 py-3 rounded-xl bg-elevated/50 border border-border-default animate-card-in"
        :style="{ animationDelay: `${idx * 50}ms` }"
      >
        <div :class="['w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0', `bg-${kpi.color}/10`]">
          <component :is="kpi.icon" class="w-5 h-5" :class="`text-${kpi.color}`" />
        </div>
        <div class="min-w-0">
          <div :class="['text-2xl font-bold tabular-nums leading-tight', `text-${kpi.color}`]">{{ kpi.value }}</div>
          <div class="text-xs text-muted leading-tight truncate">{{ kpi.label }}</div>
        </div>
      </div>
    </div>

    <!-- 图表区 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">HTTP 请求趋势（近 24h）</h3>
        <v-chart :option="httpTrendOption" autoresize style="height: 260px" />
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">接口请求分布</h3>
        <v-chart :option="prefixBarOption" autoresize style="height: 260px" />
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4 lg:col-span-2">
        <h3 class="text-sm font-semibold text-secondary mb-2">LLM 调用趋势（近 24h · 成功/失败/超时）</h3>
        <v-chart :option="llmTrendOption" autoresize style="height: 240px" />
      </div>
    </div>

    <p class="text-xs text-muted">
      说明：指标为进程内采集（多 worker 各进程独立），展示当前 worker 视图；检测拦截 = medium/high/critical 风险事件数；容灾切换次数统计主模型故障时自动切至备用模型的调用次数。
    </p>
  </div>
</template>
