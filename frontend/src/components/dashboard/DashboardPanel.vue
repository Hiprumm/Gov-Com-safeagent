<script setup lang="ts">
/**
 * 安全管控台 · 风险看板
 * KPI 总览 + 7日拦截趋势 + 攻击类型分布 + 实时风险事件流
 */
import { computed } from 'vue'
import {
  ShieldX, Clock, AlertTriangle, Gauge,
  RefreshCw, Activity, ShieldCheck, Ban,
} from 'lucide-vue-next'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import {
  GridComponent, TooltipComponent, LegendComponent,
} from 'echarts/components'
import VChart from 'vue-echarts'
import { useDashboard, attackTypeLabel, riskLevelLabel } from '@/composables/useDashboard'
import { useToast } from '@/composables/useToast'

use([CanvasRenderer, BarChart, LineChart, PieChart, GridComponent, TooltipComponent, LegendComponent])

// 实时连接由 HomePage 全局建立（useDashboardRealtime），此处只消费共享状态
const { overview, loading, wsConnected, fetchOverview } = useDashboard()
const { success } = useToast()

// 图表配色（与评测页一致）
const BLUE = '#3b82f6'
const CYAN = '#06b6d4'
const RED = '#ef4444'
const AMBER = '#f59e0b'
const ORANGE = '#f97316'
const GREEN = '#22c55e'
const PURPLE = '#a855f7'
const TEXT_DIM = '#94a3b8'

const kpiCards = computed(() => {
  const kpi = overview.value?.kpi
  return [
    { label: '今日拦截', value: kpi?.today_blocked ?? 0, color: 'critical', icon: ShieldX },
    { label: '待审批', value: kpi?.pending_approvals ?? 0, color: 'medium', icon: Clock },
    { label: '今日风险事件', value: kpi?.risk_events_today ?? 0, color: 'high', icon: AlertTriangle },
    { label: '24h拦截率', value: `${kpi?.blocked_rate_24h ?? 0}%`, color: 'safe', icon: Gauge },
  ]
})

// 7 日趋势：总量柱 + 拦截折线
const trendOption = computed(() => {
  const trend = overview.value?.trend_7d || []
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { data: ['检测总量', '拦截数'], textStyle: { color: TEXT_DIM }, top: 0 },
    grid: { left: 40, right: 20, top: 40, bottom: 30 },
    xAxis: {
      type: 'category',
      data: trend.map(t => t.date),
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
      {
        name: '检测总量',
        type: 'bar',
        data: trend.map(t => t.total),
        itemStyle: { color: BLUE, borderRadius: [4, 4, 0, 0] },
        barMaxWidth: 28,
      },
      {
        name: '拦截数',
        type: 'line',
        data: trend.map(t => t.blocked),
        smooth: true,
        symbol: 'circle',
        symbolSize: 7,
        lineStyle: { color: RED, width: 2.5 },
        itemStyle: { color: RED },
      },
    ],
  }
})

// 攻击类型分布（Top 6 + 其他）
const attackPieOption = computed(() => {
  const dist = overview.value?.attack_distribution || {}
  const entries = Object.entries(dist).filter(([, n]) => n > 0)
  const top = entries.slice(0, 6)
  const rest = entries.slice(6).reduce((s, [, n]) => s + n, 0)
  const data = top.map(([k, v]) => ({ name: attackTypeLabel(k), value: v }))
  if (rest > 0) data.push({ name: '其他', value: rest })
  const palette = [RED, ORANGE, AMBER, PURPLE, BLUE, CYAN, TEXT_DIM]
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      right: 0,
      top: 'center',
      textStyle: { color: TEXT_DIM, fontSize: 12 },
    },
    series: [
      {
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['38%', '50%'],
        avoidLabelOverlap: true,
        itemStyle: { borderColor: 'transparent', borderWidth: 2 },
        label: { show: false },
        data: data.map((d, i) => ({ ...d, itemStyle: { color: palette[i % palette.length] } })),
      },
    ],
  }
})

const recentEvents = computed(() => overview.value?.recent_events || [])

function riskBadgeClass(level: string): string {
  const map: Record<string, string> = {
    low: 'bg-low/10 text-low border-low/30',
    medium: 'bg-medium/10 text-medium border-medium/30',
    high: 'bg-high/10 text-high border-high/30',
    critical: 'bg-critical/10 text-critical border-critical/30',
  }
  return map[level] || 'bg-muted/10 text-muted border-border-default'
}

function formatTime(ts: string): string {
  if (!ts) return ''
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts.slice(11, 19)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

async function refresh() {
  await fetchOverview(true)
  success('看板数据已刷新')
}
</script>

<template>
  <div class="space-y-5">
    <!-- 标题栏 -->
    <div class="flex items-center justify-between flex-wrap gap-3">
      <div>
        <h2 class="text-lg font-bold text-primary flex items-center gap-2">
          <Activity class="w-5 h-5 text-accent" />
          安全态势总览
        </h2>
        <p class="text-sm text-muted mt-0.5">实时聚合审计日志 · 风险事件 · 审批动态</p>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-1.5 text-xs">
          <span
            class="w-2 h-2 rounded-full"
            :class="wsConnected ? 'bg-safe animate-pulse' : ''"
            :style="!wsConnected ? 'background:#94a3b8' : ''"
          ></span>
          <span :class="wsConnected ? 'text-safe' : 'text-muted'">
            {{ wsConnected ? '实时推送已连接' : '实时推送未连接（轮询中）' }}
          </span>
        </div>
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
        :style="{ animationDelay: `${idx * 60}ms` }"
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
        <h3 class="text-sm font-semibold text-secondary mb-2">近 7 日检测与拦截趋势</h3>
        <v-chart :option="trendOption" autoresize style="height: 280px" />
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">攻击类型分布（近 7 日）</h3>
        <v-chart v-if="recentEvents.length || Object.keys(overview?.attack_distribution || {}).length" :option="attackPieOption" autoresize style="height: 280px" />
        <div v-else class="h-[280px] flex flex-col items-center justify-center text-muted gap-2">
          <ShieldCheck class="w-10 h-10 text-safe/60" />
          <span class="text-sm">近 7 日暂无攻击记录</span>
        </div>
      </div>
    </div>

    <!-- 实时风险事件流 -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-3 flex items-center gap-2">
        <Ban class="w-4 h-4 text-critical" />
        最近风险事件
      </h3>
      <div v-if="recentEvents.length" class="space-y-2">
        <div
          v-for="ev in recentEvents"
          :key="ev.log_id"
          class="flex items-start gap-3 px-3 py-2.5 rounded-lg bg-canvas/50 border border-border-default hover:border-hover transition-colors"
        >
          <div class="flex flex-col items-center gap-1 flex-shrink-0 w-16">
            <span class="text-xs font-mono text-muted tabular-nums">{{ formatTime(ev.timestamp) }}</span>
            <span
              class="px-1.5 py-0.5 rounded border text-[10px] font-medium whitespace-nowrap"
              :class="riskBadgeClass(ev.risk_level)"
            >
              {{ riskLevelLabel(ev.risk_level) }}
            </span>
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap text-sm">
              <span class="font-medium text-primary">{{ attackTypeLabel(ev.attack_type) }}</span>
              <span class="text-xs text-muted px-1.5 py-0.5 rounded bg-elevated border border-border-default">
                {{ ev.action_type }}
              </span>
              <span
                v-if="ev.is_blocked"
                class="text-xs text-critical px-1.5 py-0.5 rounded bg-critical/10 border border-critical/30 flex items-center gap-1"
              >
                <ShieldX class="w-3 h-3" /> 已拦截
              </span>
            </div>
            <p v-if="ev.preview" class="text-xs text-muted mt-1 truncate font-mono">{{ ev.preview }}</p>
          </div>
        </div>
      </div>
      <div v-else class="py-10 flex flex-col items-center text-muted gap-2">
        <ShieldCheck class="w-10 h-10 text-safe/60" />
        <span class="text-sm">暂无中高风险事件，系统运行平稳</span>
      </div>
    </div>
  </div>
</template>
