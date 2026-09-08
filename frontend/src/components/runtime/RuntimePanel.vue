<script setup lang="ts">
/**
 * 安全管控台 · 运行时监控
 *
 * 针对智能体 ReAct 执行过程的实时监管：
 * - 会话选择（历史会话 + 活跃风险会话）
 * - 会话风险累积画像（评分/攻击类型数/升级状态）
 * - Think-Act-Observe 执行轨迹时间线
 * - 工具调用任务链
 * - 异常告警 + 级联失败检测
 * - 一键终止会话（human-in-the-loop，需二次确认）
 */
import { ref, computed, onActivated, watch } from 'vue'
import axios from 'axios'
import {
  Activity, RefreshCw, Loader2, ChevronRight, Brain, Wrench, Eye,
  AlertTriangle, OctagonX, ShieldAlert, Radio,
} from 'lucide-vue-next'
import { useToast } from '@/composables/useToast'
import { riskLevelLabel, attackTypeLabel } from '@/composables/useDashboard'

const { success, error } = useToast()

interface SessionItem {
  session_id: string
  title: string | null
  updated_at: string
  message_count: number
}
interface RiskProfile {
  session_id: string
  overall_risk_level: string
  cumulative_score: number
  event_count: number
  unique_attack_types: string[]
  unique_sources: string[]
  top_attack_type: string | null
  escalated: boolean
  escalated_from: string | null
  escalated_to: string | null
  escalation_reasons: string[]
  active_since: string | null
  last_event_time: string | null
}
interface TraceStep {
  step_id: number
  step_type: string
  tool_name: string | null
  reasoning: string
  risk_level: string
  timestamp: string
}
interface ChainNode {
  step_id: number
  tool_name: string
  action_category: string
  target: string
  risk_level: string
}
interface Anomaly {
  alert_type: string
  severity: string
  description: string
  step_id: number
  evidence: string[]
}

const sessions = ref<SessionItem[]>([])
const activeRiskSessions = ref<RiskProfile[]>([])
// 上次选中的会话持久化：切模块（KeepAlive）与页面刷新后都保留，无需重新选择
const selectedSid = ref(localStorage.getItem('safeagent.rt_selected_sid') || '')
watch(selectedSid, v => {
  if (v) localStorage.setItem('safeagent.rt_selected_sid', v)
})
const loading = ref(false)
const profile = ref<RiskProfile | null>(null)
const trace = ref<TraceStep[]>([])
const chain = ref<ChainNode[]>([])
const anomalies = ref<Anomaly[]>([])
const cascade = ref<any>(null)
const runtimeSummary = ref<any>(null)
const detailLoading = ref(false)
const showTerminateConfirm = ref(false)
const terminating = ref(false)

async function loadSessions() {
  loading.value = true
  try {
    const [sessRes, riskRes] = await Promise.all([
      axios.get('/ai/agent/sessions'),
      axios.get('/ai/security/session_risk').catch(() => ({ data: { sessions: [] } })),
    ])
    sessions.value = (sessRes.data?.sessions || sessRes.data || []).map((s: any) => ({
      session_id: s.session_id,
      title: s.title,
      updated_at: s.updated_at,
      message_count: s.message_count ?? 0,
    }))
    activeRiskSessions.value = riskRes.data?.sessions || []
    // 默认选中风险分最高的活跃会话，否则选最近会话；
    // 已选会话若已不存在（如被删除/清理），回退为自动选择
    const allSids = new Set([
      ...sessions.value.map(s => s.session_id),
      ...activeRiskSessions.value.map(s => s.session_id),
    ])
    if (selectedSid.value && !allSids.has(selectedSid.value)) {
      selectedSid.value = ''
    }
    if (!selectedSid.value) {
      selectedSid.value = activeRiskSessions.value[0]?.session_id || sessions.value[0]?.session_id || ''
    }
    if (selectedSid.value) await loadDetail()
  } catch (e: any) {
    error(e.response?.data?.detail || e.message || '会话列表加载失败')
  } finally {
    loading.value = false
  }
}

async function loadDetail() {
  if (!selectedSid.value) return
  detailLoading.value = true
  const sid = selectedSid.value
  try {
    const [riskRes, traceRes, chainRes, anomRes, sumRes] = await Promise.all([
      axios.get(`/ai/security/session_risk/${sid}`).catch(() => ({ data: { profile: null } })),
      axios.get(`/ai/security/runtime/trace/${sid}`).catch(() => ({ data: { trace: [] } })),
      axios.get(`/ai/security/runtime/task_chain/${sid}`).catch(() => ({ data: { nodes: [] } })),
      axios.get(`/ai/security/runtime/anomalies/${sid}`).catch(() => ({ data: { anomalies: [], cascade_failure: null } })),
      axios.get(`/ai/security/runtime/summary/${sid}`).catch(() => ({ data: { summary: null } })),
    ])
    profile.value = riskRes.data?.profile || null
    trace.value = traceRes.data?.trace || []
    chain.value = chainRes.data?.nodes || []
    anomalies.value = anomRes.data?.anomalies || []
    cascade.value = anomRes.data?.cascade_failure || null
    runtimeSummary.value = sumRes.data?.summary || null
  } catch (e: any) {
    error(e.response?.data?.detail || e.message || '监控详情加载失败')
  } finally {
    detailLoading.value = false
  }
}

async function terminateSession() {
  if (!selectedSid.value) return
  terminating.value = true
  try {
    const res = await axios.post(
      `/ai/security/runtime/terminate/${selectedSid.value}`,
      null,
      { params: { reason: '管控台人工终止：发现异常运行时行为' } },
    )
    success(res.data?.message || '会话已终止')
    showTerminateConfirm.value = false
    await loadDetail()
  } catch (e: any) {
    error(e.response?.data?.detail || e.message || '终止失败')
  } finally {
    terminating.value = false
  }
}

function riskBadgeClass(level: string): string {
  const map: Record<string, string> = {
    none: 'bg-muted/10 text-muted border-border-default',
    low: 'bg-low/10 text-low border-low/30',
    medium: 'bg-medium/10 text-medium border-medium/30',
    high: 'bg-high/10 text-high border-high/30',
    critical: 'bg-critical/10 text-critical border-critical/30',
  }
  return map[level] || map.none
}

function scoreColor(score: number): string {
  // 量纲：后端累积风险分 0-200（时间衰减加权，见 session_risk_accumulator）
  if (score >= 80) return 'text-critical'
  if (score >= 50) return 'text-high'
  if (score >= 20) return 'text-medium'
  return 'text-safe'
}

const stepIcon = (t: string) => (t === 'think' ? Brain : t === 'act' ? Wrench : Eye)
const stepLabel = (t: string) => ({ think: '推理 Think', act: '行动 Act', observe: '观察 Observe' } as Record<string, string>)[t] || t

function formatTime(ts: string | null): string {
  if (!ts) return ''
  const d = new Date(ts)
  if (isNaN(d.getTime())) return String(ts).slice(11, 19)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function shortSid(sid: string): string {
  return sid ? sid.slice(0, 8) : ''
}

const isTerminated = computed(() => {
  const s = runtimeSummary.value
  return s?.terminated || s?.is_terminated || false
})

// KeepAlive 缓存面板：onActivated 在首次挂载和每次重新进入模块时都会触发，
// 重新拉取会话列表与风险画像，保证累积分/事件数与最新检测数据同步
onActivated(() => { loadSessions() })
</script>

<template>
  <div class="space-y-5">
    <!-- 标题栏 -->
    <div class="flex items-center justify-between flex-wrap gap-3">
      <div>
        <h2 class="text-lg font-bold text-primary flex items-center gap-2">
          <Activity class="w-5 h-5 text-accent" />
          运行时监控
        </h2>
        <p class="text-sm text-muted mt-0.5">智能体 ReAct 执行过程监管 · 风险累积 · 异常告警 · 人工熔断</p>
      </div>
      <button
        @click="loadSessions"
        :disabled="loading"
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95 disabled:opacity-50"
      >
        <RefreshCw class="w-4 h-4" :class="loading ? 'animate-spin' : ''" />
        刷新
      </button>
    </div>

    <!-- 会话选择 -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <div class="flex items-center gap-2 flex-wrap">
        <Radio class="w-4 h-4 text-muted flex-shrink-0" />
        <select
          v-model="selectedSid"
          @change="loadDetail"
          class="flex-1 min-w-[220px] px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent"
        >
          <option value="" disabled>选择要监控的会话…</option>
          <option v-for="s in sessions" :key="s.session_id" :value="s.session_id">
            {{ shortSid(s.session_id) }} · {{ s.title || '未命名会话' }} · {{ s.message_count }} 条消息
          </option>
        </select>
        <span v-if="activeRiskSessions.length" class="text-xs text-high flex items-center gap-1">
          <ShieldAlert class="w-3.5 h-3.5" />
          {{ activeRiskSessions.length }} 个活跃风险会话
        </span>
      </div>
      <!-- 活跃风险会话快捷入口 -->
      <div v-if="activeRiskSessions.length" class="flex flex-wrap gap-2 mt-3">
        <button
          v-for="r in activeRiskSessions"
          :key="r.session_id"
          @click="selectedSid = r.session_id; loadDetail()"
          class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs transition-all active:scale-95"
          :class="selectedSid === r.session_id ? 'bg-accent/15 text-accent border-accent/40' : riskBadgeClass(r.overall_risk_level)"
        >
          <span class="w-1.5 h-1.5 rounded-full" :class="r.overall_risk_level === 'critical' ? 'bg-critical animate-pulse' : 'bg-high'"></span>
          {{ shortSid(r.session_id) }} · 风险分 {{ r.cumulative_score.toFixed(0) }}
        </button>
      </div>
    </div>

    <div v-if="!selectedSid" class="py-16 flex flex-col items-center text-muted gap-2">
      <Activity class="w-10 h-10 text-muted/40" />
      <span class="text-sm">暂无会话，请先在「智能问答」中发起对话</span>
    </div>

    <template v-else>
      <div v-if="detailLoading" class="py-12 flex justify-center">
        <Loader2 class="w-7 h-7 animate-spin text-accent" />
      </div>

      <template v-else>
        <!-- 级联失败横幅 -->
        <div v-if="cascade" class="rounded-xl border border-critical/40 bg-critical/10 p-4 flex items-start gap-3">
          <OctagonX class="w-5 h-5 text-critical flex-shrink-0 mt-0.5" />
          <div>
            <div class="text-sm font-bold text-critical">{{ cascade.name }} · 级联失败</div>
            <p class="text-xs text-secondary mt-1">{{ cascade.description }}</p>
          </div>
        </div>

        <!-- 风险画像 + 熔断操作 -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div class="lg:col-span-2 bg-elevated/50 rounded-xl border border-border-default p-4">
            <h3 class="text-sm font-semibold text-secondary mb-3">会话风险累积画像</h3>
            <div v-if="profile" class="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div class="text-center px-2 py-2.5 rounded-lg bg-canvas/50 border border-border-default">
                <div class="text-xl font-bold tabular-nums" :class="scoreColor(profile.cumulative_score)">
                  {{ profile.cumulative_score.toFixed(0) }}
                </div>
                <div class="text-xs text-muted">累积风险分（0-200）</div>
              </div>
              <div class="text-center px-2 py-2.5 rounded-lg bg-canvas/50 border border-border-default">
                <div class="text-xl font-bold text-accent tabular-nums">{{ profile.event_count }}</div>
                <div class="text-xs text-muted">风险事件</div>
              </div>
              <div class="text-center px-2 py-2.5 rounded-lg bg-canvas/50 border border-border-default">
                <div class="text-xl font-bold text-accent tabular-nums">{{ profile.unique_attack_types?.length || 0 }}</div>
                <div class="text-xs text-muted">攻击类型数</div>
              </div>
              <div class="text-center px-2 py-2.5 rounded-lg bg-canvas/50 border border-border-default">
                <span class="inline-block px-2 py-0.5 rounded border text-xs font-medium" :class="riskBadgeClass(profile.overall_risk_level)">
                  {{ riskLevelLabel(profile.overall_risk_level) }}
                </span>
                <div class="text-xs text-muted mt-1.5">综合等级</div>
              </div>
            </div>
            <div v-if="profile?.top_attack_type" class="mt-3 flex items-center gap-2 text-xs flex-wrap">
              <span class="text-muted">主要攻击类型：</span>
              <span class="px-2 py-0.5 rounded bg-high/10 text-high border border-high/30">
                {{ attackTypeLabel(profile.top_attack_type) }}
              </span>
              <span v-if="profile.escalated" class="px-2 py-0.5 rounded bg-critical/10 text-critical border border-critical/30 flex items-center gap-1">
                <AlertTriangle class="w-3 h-3" />
                风险已升级{{ profile.escalated_from ? `（${riskLevelLabel(profile.escalated_from)} → ${riskLevelLabel(profile.escalated_to || '')}）` : '' }}
              </span>
            </div>
          </div>

          <!-- 人工熔断 -->
          <div class="bg-critical/5 rounded-xl border border-critical/30 p-4 flex flex-col">
            <h3 class="text-sm font-semibold text-critical flex items-center gap-2 mb-2">
              <OctagonX class="w-4 h-4" />
              人工熔断
            </h3>
            <p class="text-xs text-muted leading-relaxed flex-1">
              发现智能体异常行为时，管理员可一键终止该会话的 ReAct 执行循环，操作记入审计日志（等保 2.0 可追溯）。
            </p>
            <div v-if="isTerminated" class="mt-3 px-3 py-2 rounded-lg bg-critical/10 border border-critical/30 text-xs text-critical text-center">
              该会话已被终止
            </div>
            <button
              v-else
              @click="showTerminateConfirm = true"
              class="mt-3 w-full flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-critical/15 text-critical border border-critical/40 text-sm font-medium hover:bg-critical/25 transition-colors active:scale-95"
            >
              <OctagonX class="w-4 h-4" />
              终止此会话
            </button>
          </div>
        </div>

        <!-- 执行轨迹 + 任务链 -->
        <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <!-- ReAct 轨迹 -->
          <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
            <h3 class="text-sm font-semibold text-secondary mb-3">ReAct 执行轨迹（Think-Act-Observe）</h3>
            <div v-if="trace.length" class="space-y-2 max-h-[420px] overflow-y-auto pr-1">
              <div
                v-for="step in trace"
                :key="step.step_id"
                class="flex items-start gap-3 px-3 py-2.5 rounded-lg bg-canvas/50 border border-border-default"
              >
                <div class="w-7 h-7 rounded-lg bg-elevated flex items-center justify-center flex-shrink-0">
                  <component :is="stepIcon(step.step_type)" class="w-4 h-4 text-accent" />
                </div>
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-medium text-secondary">{{ stepLabel(step.step_type) }}</span>
                    <span v-if="step.tool_name" class="text-xs px-1.5 py-0.5 rounded bg-elevated border border-border-default text-muted font-mono">
                      {{ step.tool_name }}
                    </span>
                    <span v-if="step.risk_level && step.risk_level !== 'none'"
                      class="text-[10px] px-1.5 py-0.5 rounded border" :class="riskBadgeClass(step.risk_level)">
                      {{ riskLevelLabel(step.risk_level) }}
                    </span>
                    <span class="text-[10px] text-disabled ml-auto">{{ formatTime(step.timestamp) }}</span>
                  </div>
                  <p v-if="step.reasoning" class="text-xs text-muted mt-1 line-clamp-3 break-all">{{ step.reasoning }}</p>
                </div>
              </div>
            </div>
            <div v-else class="py-10 text-center text-muted text-sm">该会话暂无执行轨迹</div>
          </div>

          <!-- 任务链 + 异常 -->
          <div class="space-y-4">
            <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
              <h3 class="text-sm font-semibold text-secondary mb-3">工具调用任务链</h3>
              <div v-if="chain.length" class="flex flex-wrap items-center gap-1.5">
                <template v-for="(node, i) in chain" :key="node.step_id">
                  <div
                    class="px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5"
                    :class="riskBadgeClass(node.risk_level)"
                  >
                    <Wrench class="w-3 h-3" />
                    <span class="font-mono">{{ node.tool_name }}</span>
                  </div>
                  <ChevronRight v-if="i < chain.length - 1" class="w-3.5 h-3.5 text-disabled flex-shrink-0" />
                </template>
              </div>
              <div v-else class="py-6 text-center text-muted text-sm">该会话暂无工具调用</div>
            </div>

            <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
              <h3 class="text-sm font-semibold text-secondary mb-3 flex items-center gap-2">
                <AlertTriangle class="w-4 h-4 text-high" />
                运行时异常告警
                <span v-if="anomalies.length" class="px-1.5 py-0.5 rounded bg-high/10 text-high text-[10px] border border-high/30">
                  {{ anomalies.length }}
                </span>
              </h3>
              <div v-if="anomalies.length" class="space-y-2 max-h-56 overflow-y-auto pr-1">
                <div
                  v-for="(a, i) in anomalies"
                  :key="i"
                  class="px-3 py-2 rounded-lg bg-canvas/50 border border-border-default"
                >
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="px-1.5 py-0.5 rounded border text-[10px]" :class="riskBadgeClass(a.severity)">
                      {{ riskLevelLabel(a.severity) }}
                    </span>
                    <span class="text-xs font-medium text-secondary">{{ a.alert_type }}</span>
                  </div>
                  <p class="text-xs text-muted mt-1">{{ a.description }}</p>
                </div>
              </div>
              <div v-else class="py-6 flex flex-col items-center text-muted gap-1.5">
                <ShieldAlert class="w-8 h-8 text-safe/50" />
                <span class="text-xs">未检测到运行时异常</span>
              </div>
            </div>
          </div>
        </div>
      </template>
    </template>

    <!-- 终止确认弹窗 -->
    <Teleport to="body">
      <div v-if="showTerminateConfirm" class="fixed inset-0 z-[95] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4" @click.self="showTerminateConfirm = false">
        <div class="w-full max-w-sm bg-surface rounded-2xl border border-critical/40 shadow-2xl p-5">
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-lg bg-critical/10 flex items-center justify-center">
              <OctagonX class="w-5 h-5 text-critical" />
            </div>
            <div>
              <h3 class="text-base font-bold text-primary">确认终止会话？</h3>
              <p class="text-xs text-muted">该操作将中断智能体执行循环并记入审计日志</p>
            </div>
          </div>
          <p class="text-sm text-secondary mb-4">
            会话 <span class="font-mono text-critical">{{ shortSid(selectedSid) }}</span> 的 ReAct 循环将被立即终止，正在进行的工具调用会被中断。
          </p>
          <div class="flex justify-end gap-2">
            <button
              @click="showTerminateConfirm = false"
              class="px-4 py-2 rounded-lg text-sm text-muted border border-border-default hover:border-hover transition-colors active:scale-95"
            >
              取消
            </button>
            <button
              @click="terminateSession"
              :disabled="terminating"
              class="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-critical/20 text-critical border border-critical/40 text-sm font-medium hover:bg-critical/30 transition-colors active:scale-95 disabled:opacity-50"
            >
              <Loader2 v-if="terminating" class="w-4 h-4 animate-spin" />
              确认终止
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
