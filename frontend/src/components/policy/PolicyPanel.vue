<script setup lang="ts">
/**
 * 安全管控台 · 策略配置中心
 *
 * 检测引擎关键参数在线调整，保存后热生效（无需重启）：
 * - LLM 语义分类层开关
 * - 拦截阈值（中/高/严重）
 * - 审计日志留存天数
 * - 可信域名后缀白名单
 */
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import {
  SlidersHorizontal, Save, RotateCcw, Loader2, ShieldCheck,
  BrainCircuit, Filter, CalendarClock, Globe, Plus, X, Tag,
} from 'lucide-vue-next'
import { useToast } from '@/composables/useToast'

const { success, error } = useToast()

interface Policy {
  llm_classifier_enabled: boolean
  block_threshold: string
  audit_retention_days: number
  trusted_domain_suffixes: string[]
  policy_version: number
  updated_at: string
}

const DEFAULTS = {
  llm_classifier_enabled: true,
  block_threshold: 'high',
  audit_retention_days: 180,
  trusted_domain_suffixes: ['.gov.cn', '.gov.org', '.gov', '.edu.cn', '.edu', '.ac.cn'],
}

const policy = ref<Policy | null>(null)
const llmEffective = ref(false)
const llmKeyPresent = ref(false)
const loading = ref(false)
const saving = ref(false)
const newSuffix = ref('')

async function loadPolicy() {
  loading.value = true
  try {
    const res = await axios.get('/ai/security/policy')
    policy.value = res.data.policy
    llmEffective.value = res.data.capabilities?.llm_classifier_effective ?? false
    llmKeyPresent.value = res.data.capabilities?.llm_api_key_present ?? false
  } catch (e: any) {
    error(e.response?.data?.detail || e.message || '策略加载失败')
  } finally {
    loading.value = false
  }
}
onMounted(loadPolicy)

const thresholdOptions = [
  { value: 'medium', label: '中风险即拦截', desc: '最严格，误报略多', color: 'medium' },
  { value: 'high', label: '高风险拦截', desc: '推荐 · 均衡', color: 'high' },
  { value: 'critical', label: '仅严重拦截', desc: '最宽松，漏报风险', color: 'critical' },
]

const retentionOptions = [30, 90, 180, 365]

function addSuffix() {
  if (!policy.value) return
  let s = newSuffix.value.trim().toLowerCase()
  if (!s) return
  if (!s.startsWith('.')) s = '.' + s
  if (policy.value.trusted_domain_suffixes.includes(s)) {
    newSuffix.value = ''
    return
  }
  policy.value.trusted_domain_suffixes.push(s)
  newSuffix.value = ''
}

function removeSuffix(s: string) {
  if (!policy.value) return
  policy.value.trusted_domain_suffixes = policy.value.trusted_domain_suffixes.filter(x => x !== s)
}

async function save() {
  if (!policy.value) return
  saving.value = true
  try {
    const res = await axios.put('/ai/security/policy', {
      policy: {
        llm_classifier_enabled: policy.value.llm_classifier_enabled,
        block_threshold: policy.value.block_threshold,
        audit_retention_days: policy.value.audit_retention_days,
        trusted_domain_suffixes: policy.value.trusted_domain_suffixes,
      },
    })
    policy.value = res.data.policy
    llmEffective.value = res.data.capabilities?.llm_classifier_effective ?? false
    success(res.data.message || '策略已保存并热生效')
  } catch (e: any) {
    error(e.response?.data?.detail || e.message || '策略保存失败')
  } finally {
    saving.value = false
  }
}

function resetDefaults() {
  if (!policy.value) return
  policy.value.llm_classifier_enabled = DEFAULTS.llm_classifier_enabled
  policy.value.block_threshold = DEFAULTS.block_threshold
  policy.value.audit_retention_days = DEFAULTS.audit_retention_days
  policy.value.trusted_domain_suffixes = [...DEFAULTS.trusted_domain_suffixes]
  success('已恢复默认值，点击「保存并热生效」后应用')
}

function formatTime(ts: string): string {
  if (!ts) return '未修改'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const thresholdColor = computed(() => {
  const opt = thresholdOptions.find(o => o.value === policy.value?.block_threshold)
  return opt?.color || 'high'
})
</script>

<template>
  <div class="space-y-5 max-w-4xl">
    <!-- 标题栏 -->
    <div class="flex items-center justify-between flex-wrap gap-3">
      <div>
        <h2 class="text-lg font-bold text-primary flex items-center gap-2">
          <SlidersHorizontal class="w-5 h-5 text-accent" />
          安全策略配置中心
        </h2>
        <p class="text-sm text-muted mt-0.5">检测引擎关键参数在线调整 · 保存即时生效，无需重启服务</p>
      </div>
      <div v-if="policy" class="flex items-center gap-2 text-xs">
        <span class="px-2 py-1 rounded-full bg-accent/10 text-accent border border-accent/20">
          策略版本 v{{ policy.policy_version }}
        </span>
        <span class="text-muted">最近更新：{{ formatTime(policy.updated_at) }}</span>
      </div>
    </div>

    <div v-if="loading" class="py-16 flex flex-col items-center text-muted gap-2">
      <Loader2 class="w-8 h-8 animate-spin text-accent" />
      <span class="text-sm">策略加载中…</span>
    </div>

    <template v-else-if="policy">
      <!-- ===== LLM 语义分类层 ===== -->
      <section class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="flex items-start justify-between gap-4">
          <div class="flex items-start gap-3">
            <div class="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center flex-shrink-0">
              <BrainCircuit class="w-5 h-5 text-accent" />
            </div>
            <div>
              <h3 class="text-sm font-semibold text-secondary">LLM 语义分类层</h3>
              <p class="text-xs text-muted mt-1 leading-relaxed">
                对规则层判定模糊的灰区样本（低/中置信度、间接注入高发来源）调用大模型语义复核，显著降低隐蔽注入漏报。
              </p>
              <p v-if="!llmKeyPresent" class="text-xs text-medium mt-1.5 flex items-center gap-1">
                <Tag class="w-3 h-3" />
                当前未配置 LLM API Key，该层不可用（需在服务端配置后开关才生效）
              </p>
              <p v-else class="text-xs mt-1.5 flex items-center gap-1" :class="policy.llm_classifier_enabled ? 'text-safe' : 'text-muted'">
                <ShieldCheck class="w-3 h-3" />
                实际状态：{{ llmEffective ? '已启用（规则 + 语义双层检测）' : '已停用（仅规则层检测）' }}
              </p>
            </div>
          </div>
          <button
            @click="policy.llm_classifier_enabled = !policy.llm_classifier_enabled"
            :disabled="!llmKeyPresent"
            class="relative w-12 h-6 rounded-full transition-colors flex-shrink-0 disabled:opacity-40 mt-1"
            :class="policy.llm_classifier_enabled && llmKeyPresent ? 'bg-safe' : 'bg-border-default'"
          >
            <span
              class="absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all"
              :class="policy.llm_classifier_enabled && llmKeyPresent ? 'left-6' : 'left-0.5'"
            ></span>
          </button>
        </div>
      </section>

      <!-- ===== 拦截阈值 ===== -->
      <section class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="flex items-center gap-3 mb-3">
          <div class="w-10 h-10 rounded-lg bg-high/10 flex items-center justify-center flex-shrink-0">
            <Filter class="w-5 h-5 text-high" />
          </div>
          <div>
            <h3 class="text-sm font-semibold text-secondary">拦截阈值</h3>
            <p class="text-xs text-muted mt-0.5">风险等级达到阈值即阻断输入进入大模型，同时驱动会话风险累积</p>
          </div>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          <button
            v-for="opt in thresholdOptions"
            :key="opt.value"
            @click="policy.block_threshold = opt.value"
            class="text-left px-4 py-3 rounded-xl border transition-all active:scale-[0.98]"
            :class="policy.block_threshold === opt.value
              ? `bg-${opt.color}/10 border-${opt.color}/50 shadow-glow`
              : 'bg-canvas/50 border-border-default hover:border-hover'"
          >
            <div class="flex items-center justify-between">
              <span class="text-sm font-medium" :class="policy.block_threshold === opt.value ? `text-${opt.color}` : 'text-secondary'">
                {{ opt.label }}
              </span>
              <span
                class="w-4 h-4 rounded-full border-2 flex items-center justify-center"
                :class="policy.block_threshold === opt.value ? `border-${opt.color}` : 'border-disabled'"
              >
                <span v-if="policy.block_threshold === opt.value" class="w-2 h-2 rounded-full" :class="`bg-${opt.color}`"></span>
              </span>
            </div>
            <p class="text-xs text-muted mt-1">{{ opt.desc }}</p>
          </button>
        </div>
      </section>

      <!-- ===== 审计留存 ===== -->
      <section class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="flex items-center gap-3 mb-3">
          <div class="w-10 h-10 rounded-lg bg-medium/10 flex items-center justify-center flex-shrink-0">
            <CalendarClock class="w-5 h-5 text-medium" />
          </div>
          <div>
            <h3 class="text-sm font-semibold text-secondary">审计日志留存周期</h3>
            <p class="text-xs text-muted mt-0.5">等保 2.0 要求审计记录留存不少于 6 个月；调短后保存时将立即清理超期日志</p>
          </div>
        </div>
        <div class="flex flex-wrap gap-2">
          <button
            v-for="days in retentionOptions"
            :key="days"
            @click="policy.audit_retention_days = days"
            class="px-4 py-2 rounded-lg border text-sm transition-all active:scale-95"
            :class="policy.audit_retention_days === days
              ? 'bg-accent/15 text-accent border-accent/50'
              : 'bg-canvas/50 text-secondary border-border-default hover:border-hover'"
          >
            {{ days }} 天<span class="text-xs text-muted ml-1">（{{ days >= 180 ? '合规推荐' : days === 90 ? '3个月' : '1个月' }}）</span>
          </button>
        </div>
      </section>

      <!-- ===== 可信域名 ===== -->
      <section class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="flex items-center gap-3 mb-3">
          <div class="w-10 h-10 rounded-lg bg-safe/10 flex items-center justify-center flex-shrink-0">
            <Globe class="w-5 h-5 text-safe" />
          </div>
          <div>
            <h3 class="text-sm font-semibold text-secondary">可信域名后缀白名单</h3>
            <p class="text-xs text-muted mt-0.5">网页抓取/外部链接来源命中白名单时降低间接注入嫌疑，用于政务/教育等可信来源</p>
          </div>
        </div>
        <div class="flex flex-wrap gap-2 mb-3">
          <span
            v-for="s in policy.trusted_domain_suffixes"
            :key="s"
            class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-safe/10 text-safe border border-safe/30 text-xs font-mono"
          >
            {{ s }}
            <button @click="removeSuffix(s)" class="hover:text-critical transition-colors" title="移除">
              <X class="w-3 h-3" />
            </button>
          </span>
          <span v-if="!policy.trusted_domain_suffixes.length" class="text-xs text-muted">暂无白名单后缀</span>
        </div>
        <div class="flex gap-2">
          <input
            v-model="newSuffix"
            @keydown.enter.prevent="addSuffix"
            type="text"
            placeholder="新增后缀，如 .gov.cn"
            class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
          />
          <button
            @click="addSuffix"
            class="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-elevated border border-border-default text-secondary text-sm hover:border-accent hover:text-accent transition-colors active:scale-95"
          >
            <Plus class="w-4 h-4" />
            添加
          </button>
        </div>
      </section>

      <!-- ===== 操作栏 ===== -->
      <div class="flex items-center justify-end gap-3 sticky bottom-0 bg-surface/80 backdrop-blur-sm py-3 -mx-2 px-2">
        <button
          @click="resetDefaults"
          class="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm text-muted hover:text-secondary border border-border-default hover:border-hover transition-colors active:scale-95"
        >
          <RotateCcw class="w-4 h-4" />
          恢复默认
        </button>
        <button
          @click="save"
          :disabled="saving"
          class="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-accent/15 text-accent border border-accent/30 text-sm font-medium hover:bg-accent/25 transition-colors active:scale-95 disabled:opacity-50"
        >
          <Loader2 v-if="saving" class="w-4 h-4 animate-spin" />
          <Save v-else class="w-4 h-4" />
          保存并热生效
        </button>
      </div>
    </template>
  </div>
</template>
