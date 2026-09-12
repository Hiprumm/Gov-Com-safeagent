<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { useAuth } from '@/composables/useAuth'
import { useEvaluation } from '@/composables/useEvaluation'

// ---------- ECharts modular registration ----------
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { HeatmapChart, BarChart, GaugeChart, PieChart, RadarChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  VisualMapComponent,
} from 'echarts/components'
import VChart from 'vue-echarts'

use([
  CanvasRenderer,
  HeatmapChart,
  BarChart,
  GaugeChart,
  PieChart,
  RadarChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  VisualMapComponent,
])

// ---------- State ----------
const loading = ref(true)
const error = ref('')
const report = ref<any>(null)

// ---------- Colour palette ----------
const BLUE = '#3b82f6'
const BLUE_LIGHT = '#60a5fa'
const CYAN = '#06b6d4'
const GREEN = '#22c55e'
const AMBER = '#f59e0b'
const RED = '#ef4444'
const TEXT_DIM = '#94a3b8'
const TEXT_BRIGHT = '#e2e8f0'
const CARD_BG = '#1e293b'
const PAGE_BG = '#0f172a'

// ---------- Fetch data ----------
// 权限：评测报告"查看人人可用"；"生成/重新生成"仅管理员（方案2：非管理员看不到按钮）
const { currentUser, initAuth } = useAuth()
const isAdmin = computed(() => currentUser.value?.role === 'admin')
// 评测生成中状态（模块级共享：切换页面不中断，返回后自动恢复）
const { generating, syncFromBackend, begin, finish, startPolling, stopPolling } = useEvaluation()
onMounted(async () => {
  // 直接访问/刷新本页时恢复登录身份（决定"生成报告"按钮是否可见）
  if (!currentUser.value) await initAuth()
  // 本页为深色看板设计（图表配色固定）：进入时强制深色，离开时恢复用户偏好
  document.documentElement.classList.remove('light')
  document.documentElement.classList.add('dark')
  try {
    const { data } = await axios.get('/api/evaluation/report')
    report.value = data
  } catch (e: any) {
    error.value = '评测报告数据加载失败，请先运行评测生成报告。'
    console.error('Evaluation report fetch error:', e)
  } finally {
    loading.value = false
    // 恢复"生成中"展示：后端仍在生成（切换页面/刷新后重新进入）→ 自动恢复轮询
    const stillRunning = await syncFromBackend()
    if (stillRunning) {
      startPolling(pullFreshReport)
    }
  }
})

onUnmounted(() => {
  // 切换页面：仅停止轮询（避免对已卸载组件回调），全局生成中状态保留
  stopPolling()
  const saved = localStorage.getItem('theme')
  const t = saved === 'light' || saved === 'dark'
    ? saved
    : (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  document.documentElement.classList.remove('light', 'dark')
  document.documentElement.classList.add(t)
})

// ---------- Derived helpers ----------
const metrics = computed(() => report.value?.metrics ?? null)
const classification = computed(() => report.value?.classification ?? null)
const generatedAt = computed(() => report.value?.generated_at ?? '')

// 生成/重新生成评测报告（后台异步，轮询状态完成后刷新）
const reportPolls = ref(0)
const pullFreshReport = async (): Promise<boolean> => {
  // 轮询到 running=false 时拉取最新报告；时间戳未刷新则继续等下一轮（返回 false）
  reportPolls.value++
  try {
    const { data } = await axios.get('/api/evaluation/report')
    if (data?.generated_at && data.generated_at === genOldAt.value && reportPolls.value < 480) return false
    finish()
    report.value = data
    error.value = ''
    return true
  } catch {
    return false
  }
}
const genOldAt = ref('')
const generateReport = async () => {
  if (generating.value) return
  try {
    const r = await axios.post('/api/evaluation/generate')
    if (!r.data?.success) { window.alert(r.data?.error || '生成失败'); return }
    genOldAt.value = report.value?.generated_at ?? ''
    reportPolls.value = 0
    begin()
    startPolling(pullFreshReport)
  } catch (e: any) {
    window.alert(e.response?.data?.error || e.response?.data?.detail || '生成失败')
  }
}

// Attack-type list sorted by total sample count (desc), "normal" excluded
const attackTypesSorted = computed(() => {
  if (!classification.value?.by_type) return []
  const entries = Object.entries(classification.value.by_type as Record<string, { total: number; detected: number }>)
  return entries
    .filter(([key]) => key !== 'normal')
    .sort((a, b) => b[1].total - a[1].total)
})

// CNAME mapping for chart labels
const attackNameMap: Record<string, string> = {
  prompt_injection: '提示注入',
  jailbreak: '越狱攻击',
  data_leakage: '数据泄露',
  content_injection: '内容注入',
  command_injection: '命令注入',
  network_attack: '网络攻击',
  data_exfiltration: '数据窃取',
  data_poisoning: '数据投毒',
  normal: '正常样本',
}

const cn = (key: string) => attackNameMap[key] ?? key

// ==================== Chart 1: Confusion Matrix Heatmap ====================
const confusionMatrixOption = computed(() => {
  const m = metrics.value
  if (!m) return {}
  const maxVal = Math.max(m.tp, m.tn, m.fp, m.fn, 1)
  return {
    tooltip: {
      formatter: (p: any) => `${p.data?.[0] ?? ''} · ${p.data?.[1] ?? ''}<br/>数量: <b>${p.data?.[2] ?? 0}</b>`,
      backgroundColor: CARD_BG,
      borderColor: '#334155',
      textStyle: { color: TEXT_BRIGHT },
    },
    grid: { left: 100, right: 20, top: 20, bottom: 40 },
    xAxis: {
      type: 'category',
      data: ['预测正常', '预测攻击'],
      splitArea: { show: true },
      axisLabel: { color: TEXT_DIM, fontSize: 13 },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    yAxis: {
      type: 'category',
      data: ['实际正常', '实际攻击'],
      splitArea: { show: true },
      axisLabel: { color: TEXT_DIM, fontSize: 13 },
      axisLine: { lineStyle: { color: '#475569' } },
    },
    visualMap: {
      min: 0,
      max: maxVal,
      calculable: true,
      orient: 'horizontal',
      left: 'center',
      bottom: 0,
      textStyle: { color: TEXT_DIM },
      inRange: { color: ['#1e3a5f', '#1e40af', '#2563eb', '#3b82f6', '#60a5fa'] },
    },
    series: [
      {
        type: 'heatmap',
        data: [
          { value: [0, 0, m.tn], name: '实际正常·预测正常' },
          { value: [1, 0, m.fp], name: '实际正常·预测攻击' },
          { value: [0, 1, m.fn], name: '实际攻击·预测正常' },
          { value: [1, 1, m.tp], name: '实际攻击·预测攻击' },
        ],
        label: {
          show: true,
          color: '#e2e8f0',
          fontSize: 16,
          fontWeight: 'bold',
        },
        emphasis: {
          itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,0,0,0.5)' },
        },
      },
    ],
  }
})

// ==================== Chart 2: Detection Rate by Attack Type (horizontal bar) ====================
const detectionRateOption = computed(() => {
  if (!attackTypesSorted.value.length) return {}
  const names = attackTypesSorted.value.map(([k]) => cn(k))
  const rates = attackTypesSorted.value.map(([, v]) =>
    v.total > 0 ? Math.round((v.detected / v.total) * 100 * 10) / 10 : 0,
  )
  // Add "normal" correct-classification rate at the end
  const normalData = classification.value?.by_type?.normal
  if (normalData) {
    names.push(cn('normal'))
    rates.push(normalData.total > 0 ? Math.round(((normalData.total - normalData.detected) / normalData.total) * 100 * 10) / 10 : 100)
  }

  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: CARD_BG,
      borderColor: '#334155',
      textStyle: { color: TEXT_BRIGHT },
      formatter: (p: any) => {
        const item = Array.isArray(p) ? p[0] : p
        return `${item.name}<br/>检出率: <b>${item.value}%</b>`
      },
    },
    grid: { left: 120, right: 60, top: 10, bottom: 30 },
    xAxis: {
      type: 'value',
      min: 0,
      max: 100,
      axisLabel: { color: TEXT_DIM, formatter: '{value}%' },
      splitLine: { lineStyle: { color: '#334155', type: 'dashed' } },
    },
    yAxis: {
      type: 'category',
      data: names.reverse(),
      axisLabel: { color: TEXT_BRIGHT, fontSize: 12 },
      axisLine: { lineStyle: { color: '#475569' } },
      inverse: true,
    },
    series: [
      {
        type: 'bar',
        data: rates.reverse().map((v, i) => {
          const key = attackTypesSorted.value[attackTypesSorted.value.length - 1 - i]?.[0] ?? 'normal'
          return {
            value: v,
            itemStyle: {
              color: key === 'normal'
                ? GREEN
                : v >= 90 ? GREEN : v >= 70 ? AMBER : RED,
              borderRadius: [0, 4, 4, 0],
            },
          }
        }),
        barWidth: 20,
        label: {
          show: true,
          position: 'right',
          color: TEXT_DIM,
          formatter: '{c}%',
        },
      },
    ],
  }
})

// ==================== Chart 3: Gauge cards (accuracy / precision / recall / F1) ====================
function makeGauge(title: string, value: number, color: string) {
  return {
    series: [
      {
        type: 'gauge',
        startAngle: 210,
        endAngle: -30,
        center: ['50%', '60%'],
        radius: '90%',
        min: 0,
        max: 100,
        splitNumber: 10,
        axisLine: {
          show: true,
          lineStyle: {
            width: 18,
            color: [
              [0.3, RED],
              [0.7, AMBER],
              [1, GREEN],
            ],
          },
        },
        pointer: {
          icon: 'path://M12.8,0.7l12,40.1H0.7L12.8,0.7z',
          length: '60%',
          width: 8,
          offsetCenter: [0, '-60%'],
          itemStyle: { color: color },
        },
        axisTick: {
          length: 10,
          lineStyle: { color: 'auto', width: 2 },
        },
        splitLine: {
          length: 22,
          lineStyle: { color: 'auto', width: 4 },
        },
        axisLabel: {
          color: TEXT_DIM,
          fontSize: 10,
          distance: -36,
        },
        title: {
          offsetCenter: [0, '85%'],
          fontSize: 16,
          color: TEXT_BRIGHT,
        },
        detail: {
          valueAnimation: true,
          formatter: '{value}%',
          color: TEXT_BRIGHT,
          fontSize: 28,
          fontWeight: 'bold',
          offsetCenter: [0, '42%'],
        },
        data: [{ value: Math.round(value * 100), name: title }],
      },
    ],
  }
}

const gaugeAccuracyOption = computed(() => makeGauge('准确率', metrics.value?.accuracy ?? 0, BLUE))
const gaugePrecisionOption = computed(() => makeGauge('精确率', metrics.value?.precision ?? 0, CYAN))
const gaugeRecallOption = computed(() => makeGauge('召回率', metrics.value?.recall ?? 0, GREEN))
const gaugeF1Option = computed(() => makeGauge('F1 分数', metrics.value?.f1_score ?? 0, AMBER))

// ==================== Chart 4: Risk Level Distribution (pie/donut) ====================
const riskDistributionOption = computed(() => {
  const m = metrics.value
  if (!m) return {}
  const attackCount = m.tp + m.fn   // total attack samples
  const normalCount = m.tn + m.fp    // total normal samples

  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: CARD_BG,
      borderColor: '#334155',
      textStyle: { color: TEXT_BRIGHT },
      formatter: '{b}: {c} 条 ({d}%)',
    },
    legend: {
      bottom: 0,
      textStyle: { color: TEXT_DIM, fontSize: 12 },
    },
    series: [
      {
        type: 'pie',
        radius: ['45%', '72%'],
        center: ['50%', '48%'],
        avoidLabelOverlap: false,
        padAngle: 2,
        itemStyle: { borderRadius: 6 },
        label: {
          show: true,
          formatter: '{b}\n{d}%',
          color: TEXT_BRIGHT,
          fontSize: 12,
        },
        emphasis: {
          label: { fontSize: 18, fontWeight: 'bold' },
          scaleSize: 8,
        },
        data: [
          { value: attackCount, name: '攻击样本', itemStyle: { color: RED } },
          { value: normalCount, name: '正常样本', itemStyle: { color: GREEN } },
        ],
      },
    ],
  }
})

// ==================== Chart 5: Adversarial Robustness – Radar Chart ====================
const robustnessOption = computed(() => {
  if (!classification.value?.type_recall) return {}
  const typeRecall = classification.value.type_recall as Record<string, number>
  const indicators = Object.keys(typeRecall)
    .filter(k => k !== 'normal')
    .map(k => ({ name: cn(k), max: 1 }))
  const data = Object.entries(typeRecall)
    .filter(([k]) => k !== 'normal')
    .map(([, v]) => v)

  return {
    tooltip: {
      backgroundColor: CARD_BG,
      borderColor: '#334155',
      textStyle: { color: TEXT_BRIGHT },
    },
    legend: {
      bottom: 0,
      textStyle: { color: TEXT_DIM },
    },
    radar: {
      center: ['50%', '50%'],
      radius: '68%',
      indicator: indicators,
      axisName: { color: TEXT_DIM, fontSize: 11 },
      shape: 'polygon',
      splitNumber: 4,
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#334155' } },
      splitArea: {
        areaStyle: {
          color: ['rgba(59,130,246,0.06)', 'rgba(59,130,246,0.02)'],
        },
      },
    },
    series: [
      {
        type: 'radar',
        data: [
          {
            value: data,
            name: '检出率',
            areaStyle: { color: 'rgba(59,130,246,0.2)' },
            lineStyle: { color: BLUE, width: 2 },
            itemStyle: { color: BLUE_LIGHT },
            symbol: 'circle',
            symbolSize: 6,
          },
        ],
      },
    ],
  }
})

// ---------- Formatters ----------
const fmtPct = (v: number | undefined) => v != null ? `${(v * 100).toFixed(1)}%` : '--'
const fmtInt = (v: number | undefined) => v != null ? v.toLocaleString() : '--'
const fmtTime = (iso: string) => {
  if (!iso) return '--'
  try {
    const d = new Date(iso)
    return d.toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

// ---------- 报告导出 ----------
const downloadMarkdown = () => {
  const r = report.value
  if (!r) return
  const m = r.metrics || {}
  const pct = (v?: number) => (typeof v === 'number' ? `${(v * 100).toFixed(2)}%` : '--')
  const L: string[] = []
  L.push('# 政企大模型智能体安全平台 — 检测效果评测报告')
  L.push('')
  L.push(`- 报告生成时间：${fmtTime(r.generated_at)}`)
  L.push(`- 评测样本总数：${m.total ?? '--'} 条`)
  L.push('')
  L.push('## 一、总体指标')
  L.push('')
  L.push('| 指标 | 数值 |')
  L.push('| --- | --- |')
  L.push(`| 混淆矩阵 | TP=${m.tp ?? '--'}，TN=${m.tn ?? '--'}，FP=${m.fp ?? '--'}，FN=${m.fn ?? '--'} |`)
  L.push(`| 准确率 Accuracy | ${pct(m.accuracy)} |`)
  L.push(`| 精确率 Precision | ${pct(m.precision)} |`)
  L.push(`| 召回率 Recall | ${pct(m.recall)} |`)
  L.push(`| F1 分数 | ${pct(m.f1_score)} |`)
  if (m.false_positive_rate != null) L.push(`| 误报率 | ${pct(m.false_positive_rate)} |`)
  L.push('')
  const cls = r.classification || {}
  const byType: Record<string, any> = cls.by_type || {}
  const types = Object.keys(byType).filter(k => k !== 'normal')
  if (types.length) {
    L.push('## 二、分类别检测效果（近 7 日样本）')
    L.push('')
    L.push('| 攻击类型 | 样本数 | 检出数 |')
    L.push('| --- | --- | --- |')
    for (const t of types) {
      const item = byType[t]
      L.push(`| ${t} | ${item?.total ?? '--'} | ${item?.detected ?? '--'} |`)
    }
    L.push('')
  }
  const blob = new Blob([L.join('\n')], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'SafeAgent-安全评测报告.md'
  a.click()
  URL.revokeObjectURL(url)
}

const printReport = () => {
  window.print()
}
</script>

<template>
  <!-- 独立路由页：#app 全局 overflow-hidden，需在页面容器内滚动 -->
  <div class="eval-page" :style="{ background: PAGE_BG, height: '100%', overflowY: 'auto', color: TEXT_BRIGHT }">
    <!-- ========== Header ========== -->
    <header :style="{ background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)', borderBottom: '1px solid #334155' }">
      <div class="max-w-7xl mx-auto px-4 py-5 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div :style="{ width: '40px', height: '40px', background: 'linear-gradient(135deg, #3b82f6, #6366f1)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center' }">
            <span :style="{ color: '#fff', fontSize: '20px', fontWeight: 'bold' }">评</span>
          </div>
          <div>
            <h1 class="text-xl font-bold" :style="{ color: TEXT_BRIGHT }">安全评测报告</h1>
            <p :style="{ color: TEXT_DIM, fontSize: '13px' }">政企大模型智能体安全检测效果评估</p>
          </div>
        </div>
        <div :style="{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }">
          <button
            v-if="isAdmin"
            @click="generateReport"
            :disabled="generating"
            class="eval-gen-btn"
            :style="{ padding: '8px 14px', background: generating ? '#b45309' : '#7c3aed', color: generating ? '#fef3c7' : '#e9d5ff', borderRadius: '8px', fontSize: '14px', fontWeight: 600, border: generating ? '1px solid #f59e0b' : '1px solid #8b5cf6', cursor: generating ? 'wait' : 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px' }"
          >
            <span v-if="generating" class="eval-spin" :style="{ display: 'inline-block', width: '14px', height: '14px', border: '2px solid #fef3c7', borderTopColor: 'transparent', borderRadius: '50%' }"></span>
            {{ generating ? '评测生成中…' : '生成报告' }}
          </button>
          <button
            v-if="report"
            @click="downloadMarkdown"
            :style="{ padding: '8px 14px', background: '#14532d', color: '#86efac', borderRadius: '8px', fontSize: '14px', fontWeight: 500, border: '1px solid #15803d', cursor: 'pointer' }"
          >下载 Markdown</button>
          <button
            v-if="report"
            @click="printReport"
            :style="{ padding: '8px 14px', background: '#1e3a5f', color: BLUE_LIGHT, borderRadius: '8px', fontSize: '14px', fontWeight: 500, border: '1px solid #1e40af', cursor: 'pointer' }"
          >打印 / 存为 PDF</button>
          <a
            href="/"
            :style="{ padding: '8px 16px', background: '#1e3a5f', color: BLUE_LIGHT, borderRadius: '8px', textDecoration: 'none', fontSize: '14px', fontWeight: 500, border: '1px solid #1e40af', transition: 'all .2s' }"
            class="hover:bg-blue-900/30"
          >← 返回主页</a>
        </div>
      </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-6">
      <!-- ========== 评测生成中醒目横幅（全局状态：切换页面不中断，返回后自动恢复） ========== -->
      <div
        v-if="generating"
        class="eval-progress"
        :style="{ display: 'flex', alignItems: 'center', gap: '14px', background: 'linear-gradient(90deg, rgba(180,83,9,0.25), rgba(217,119,6,0.15))', border: '1px solid rgba(245,158,11,0.55)', borderRadius: '12px', padding: '14px 18px', marginBottom: '20px' }"
      >
        <div class="eval-spin" :style="{ width: '26px', height: '26px', border: '3px solid #f59e0b', borderTopColor: 'transparent', borderRadius: '50%', flexShrink: 0 }"></div>
        <div :style="{ flex: 1 }">
          <div :style="{ color: '#fbbf24', fontSize: '15px', fontWeight: 700, marginBottom: '2px' }">评测正在生成中…</div>
          <div :style="{ color: '#d1d5db', fontSize: '13px' }">
            系统正在对 <strong>{{ metrics?.total || '全部' }}</strong> 条样本逐条执行安全检测（含 LLM 语义分类），预计 1~3 分钟。
            生成完成后本页将<strong>自动刷新</strong>最新报告；<strong>切换页面不会中断</strong>，返回后自动恢复进度。
          </div>
        </div>
        <div :style="{ color: '#f59e0b', fontSize: '12px', fontWeight: 600, flexShrink: 0 }" class="eval-blink">进行中</div>
      </div>

      <!-- ========== Loading / Error ========== -->
      <div v-if="loading" :style="{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }">
        <div :style="{ color: TEXT_DIM, fontSize: '16px' }">
          <span :style="{ marginRight: '8px' }">⏳</span> 正在加载评测报告数据...
        </div>
      </div>

      <div v-else-if="error" :style="{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }">
        <div :style="{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '12px', padding: '32px', textAlign: 'center', maxWidth: '500px' }">
          <div :style="{ fontSize: '40px', marginBottom: '12px' }">⚠️</div>
          <div :style="{ color: '#fca5a5', fontSize: '16px', fontWeight: 600, marginBottom: '8px' }">数据加载失败</div>
          <div :style="{ color: TEXT_DIM, fontSize: '14px' }">{{ error }}</div>
        </div>
      </div>

      <template v-else-if="report">
        <!-- ========== Meta info ========== -->
        <div :style="{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }">
          <div :style="{ color: TEXT_DIM, fontSize: '13px' }">
            报告生成时间: {{ fmtTime(generatedAt) }}
          </div>
        </div>

        <!-- ========== Key Metric Cards – Row 1 (4 big cards) ========== -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '22px 20px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '13px', marginBottom: '6px' }">准确率 Accuracy</div>
            <div :style="{ color: BLUE_LIGHT, fontSize: '36px', fontWeight: 700, lineHeight: 1.1 }">{{ fmtPct(metrics?.accuracy) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '22px 20px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '13px', marginBottom: '6px' }">精确率 Precision</div>
            <div :style="{ color: CYAN, fontSize: '36px', fontWeight: 700, lineHeight: 1.1 }">{{ fmtPct(metrics?.precision) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '22px 20px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '13px', marginBottom: '6px' }">召回率 Recall</div>
            <div :style="{ color: GREEN, fontSize: '36px', fontWeight: 700, lineHeight: 1.1 }">{{ fmtPct(metrics?.recall) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '22px 20px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '13px', marginBottom: '6px' }">F1 分数 F1-Score</div>
            <div :style="{ color: AMBER, fontSize: '36px', fontWeight: 700, lineHeight: 1.1 }">{{ fmtPct(metrics?.f1_score) }}</div>
          </div>
        </div>

        <!-- ========== Key Metric Cards – Row 2 (4 small cards) ========== -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div :style="{ background: CARD_BG, borderRadius: '12px', padding: '16px 18px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '12px', marginBottom: '4px' }">样本总数</div>
            <div :style="{ color: TEXT_BRIGHT, fontSize: '26px', fontWeight: 700 }">{{ fmtInt(metrics?.total) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '12px', padding: '16px 18px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '12px', marginBottom: '4px' }">攻击样本</div>
            <div :style="{ color: '#f87171', fontSize: '26px', fontWeight: 700 }">{{ fmtInt((metrics?.tp ?? 0) + (metrics?.fn ?? 0)) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '12px', padding: '16px 18px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '12px', marginBottom: '4px' }">正常样本</div>
            <div :style="{ color: '#4ade80', fontSize: '26px', fontWeight: 700 }">{{ fmtInt((metrics?.tn ?? 0) + (metrics?.fp ?? 0)) }}</div>
          </div>
          <div :style="{ background: CARD_BG, borderRadius: '12px', padding: '16px 18px', border: '1px solid #334155' }">
            <div :style="{ color: TEXT_DIM, fontSize: '12px', marginBottom: '4px' }">误报率 FPR</div>
            <div :style="{ color: metrics?.false_positive_rate === 0 ? GREEN : RED, fontSize: '26px', fontWeight: 700 }">{{ fmtPct(metrics?.false_positive_rate) }}</div>
          </div>
        </div>

        <!-- ========== Chart Row 1: Confusion Matrix + Detection Rate ========== -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '20px', border: '1px solid #334155', display: 'flex', flexDirection: 'column' }">
            <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '12px' }">📊 混淆矩阵</h3>
            <v-chart :option="confusionMatrixOption" autoresize style="height:320px" />
            <div :style="{ color: TEXT_DIM, fontSize: '12px', textAlign: 'center', marginTop: '6px' }">
              TP:{{ metrics?.tp }} · TN:{{ metrics?.tn }} · FP:{{ metrics?.fp }} · FN:{{ metrics?.fn }}
            </div>
          </div>

          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '20px', border: '1px solid #334155', display: 'flex', flexDirection: 'column' }">
            <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '12px' }">📋 各类型检出率</h3>
            <v-chart :option="detectionRateOption" autoresize style="height:320px" />
          </div>
        </div>

        <!-- ========== Chart Row 2: 4 Gauge Charts ========== -->
        <div class="mb-6">
          <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '16px' }">📈 核心指标仪表盘</h3>
          <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '12px', border: '1px solid #334155' }">
              <v-chart :option="gaugeAccuracyOption" autoresize style="height:210px" />
            </div>
            <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '12px', border: '1px solid #334155' }">
              <v-chart :option="gaugePrecisionOption" autoresize style="height:210px" />
            </div>
            <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '12px', border: '1px solid #334155' }">
              <v-chart :option="gaugeRecallOption" autoresize style="height:210px" />
            </div>
            <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '12px', border: '1px solid #334155' }">
              <v-chart :option="gaugeF1Option" autoresize style="height:210px" />
            </div>
          </div>
        </div>

        <!-- ========== Chart Row 3: Risk Distribution + Adversarial Robustness ========== -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '20px', border: '1px solid #334155', display: 'flex', flexDirection: 'column' }">
            <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '12px' }">🎯 样本分布</h3>
            <v-chart :option="riskDistributionOption" autoresize style="height:340px" />
          </div>

          <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '20px', border: '1px solid #334155', display: 'flex', flexDirection: 'column' }">
            <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '12px' }">🛡️ 对抗鲁棒性雷达图</h3>
            <v-chart :option="robustnessOption" autoresize style="height:340px" />
          </div>
        </div>

        <!-- ========== Classification detail table ========== -->
        <div :style="{ background: CARD_BG, borderRadius: '14px', padding: '20px', border: '1px solid #334155', marginBottom: '24px' }">
          <h3 :style="{ color: TEXT_BRIGHT, fontSize: '15px', fontWeight: 600, marginBottom: '16px' }">📋 分类详情表</h3>
          <div :style="{ overflowX: 'auto' }">
            <table :style="{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }">
              <thead>
                <tr :style="{ borderBottom: '2px solid #334155', textAlign: 'left' }">
                  <th :style="{ padding: '10px 14px', color: TEXT_DIM, fontWeight: 500 }">攻击类型</th>
                  <th :style="{ padding: '10px 14px', color: TEXT_DIM, fontWeight: 500, textAlign: 'right' }">样本数</th>
                  <th :style="{ padding: '10px 14px', color: TEXT_DIM, fontWeight: 500, textAlign: 'right' }">检出数</th>
                  <th :style="{ padding: '10px 14px', color: TEXT_DIM, fontWeight: 500, textAlign: 'right' }">检出率</th>
                  <th :style="{ padding: '10px 14px', color: TEXT_DIM, fontWeight: 500, textAlign: 'right' }">漏报数</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="([key, val]) in attackTypesSorted"
                  :key="key"
                  :style="{ borderBottom: '1px solid #1e293b' }"
                >
                  <td :style="{ padding: '10px 14px', color: TEXT_BRIGHT }">{{ cn(key) }}</td>
                  <td :style="{ padding: '10px 14px', color: TEXT_BRIGHT, textAlign: 'right' }">{{ val.total }}</td>
                  <td :style="{ padding: '10px 14px', color: val.detected === val.total ? GREEN : AMBER, textAlign: 'right' }">{{ val.detected }}</td>
                  <td :style="{ padding: '10px 14px', textAlign: 'right', fontWeight: 600 }">
                    <span :style="{ color: val.total > 0 && val.detected === val.total ? GREEN : AMBER }">
                      {{ val.total > 0 ? ((val.detected / val.total) * 100).toFixed(1) + '%' : '--' }}
                    </span>
                  </td>
                  <td :style="{ padding: '10px 14px', textAlign: 'right' }">
                    <span :style="{ color: val.total - val.detected > 0 ? RED : TEXT_DIM }">{{ val.total - val.detected }}</span>
                  </td>
                </tr>
                <tr v-if="classification?.by_type?.normal" :style="{ borderBottom: '1px solid #1e293b' }">
                  <td :style="{ padding: '10px 14px', color: TEXT_BRIGHT }">
                    {{ cn('normal') }}
                    <span :style="{ color: TEXT_DIM, fontSize: '11px', marginLeft: '6px' }">（正确拒绝）</span>
                  </td>
                  <td :style="{ padding: '10px 14px', color: TEXT_BRIGHT, textAlign: 'right' }">{{ classification.by_type.normal.total }}</td>
                  <td :style="{ padding: '10px 14px', color: GREEN, textAlign: 'right' }">{{ classification.by_type.normal.total - classification.by_type.normal.detected }}</td>
                  <td :style="{ padding: '10px 14px', color: GREEN, textAlign: 'right', fontWeight: 600 }">
                    {{ ((classification.by_type.normal.total - classification.by_type.normal.detected) / classification.by_type.normal.total * 100).toFixed(1) }}%
                  </td>
                  <td :style="{ padding: '10px 14px', color: TEXT_DIM, textAlign: 'right' }">{{ classification.by_type.normal.detected }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
    </main>

    <footer :style="{ background: CARD_BG, borderTop: '1px solid #334155', marginTop: '40px' }">
      <div class="max-w-7xl mx-auto px-4 py-4 text-center" :style="{ color: TEXT_DIM, fontSize: '13px' }">
        <p>面向政企场景的大模型智能体安全关键技术研究 · 安全评测报告</p>
      </div>
    </footer>
  </div>
</template>

<style scoped>
/* 评测生成中：旋转指示器 + 进行中闪烁 */
@keyframes eval-spin-kf {
  to { transform: rotate(360deg); }
}
.eval-spin {
  animation: eval-spin-kf 0.9s linear infinite;
}
@keyframes eval-blink-kf {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.25; }
}
.eval-blink {
  animation: eval-blink-kf 1.2s ease-in-out infinite;
}
/* 横幅轻微呼吸，强化"正在处理"感知 */
@keyframes eval-progress-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.35); }
  50% { box-shadow: 0 0 18px 2px rgba(245, 158, 11, 0.25); }
}
.eval-progress {
  animation: eval-progress-pulse 2s ease-in-out infinite;
}
</style>
