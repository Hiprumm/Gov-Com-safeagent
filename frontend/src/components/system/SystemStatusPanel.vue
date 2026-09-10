<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { toast } from '@/composables/useToast'

interface SystemStatus {
  success: boolean
  health: string
  service: { name: string; version: string; started_at: string; uptime_seconds: number }
  websocket: { active_connections: number; channels: number }
  llm: { api_key_present: boolean; classifier_enabled: boolean }
  policy: { version: number; block_threshold: string; audit_retention_days: number }
  data: { audit_logs: number; approvals_total: number; approvals_pending: number; sessions_active: number }
}

const status = ref<SystemStatus | null>(null)
const loading = ref(false)
const cleaning = ref(false)

const load = async () => {
  loading.value = true
  try {
    const res = await axios.get('/ai/system/status')
    status.value = res.data
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '系统状态获取失败')
  } finally {
    loading.value = false
  }
}

const cleanEmptySessions = async () => {
  if (!window.confirm('将清理全部“无消息”的空会话（多次新建/清空对话产生的残留）。有内容的会话不受影响。确认继续？')) return
  cleaning.value = true
  try {
    const res = await axios.post('/ai/system/maintenance/clean_sessions')
    toast.success(res.data?.message || '清理完成')
    await load()
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '清理失败')
  } finally {
    cleaning.value = false
  }
}

// ---------- 通知渠道（Webhook）配置 ----------
const webhookCfg = ref({ url: '', enabled: false })
const whSaving = ref(false)
const whTesting = ref(false)
const loadWebhook = async () => {
  try {
    const res = await axios.get('/ai/notifications/webhook')
    webhookCfg.value = res.data.config || { url: '', enabled: false }
  } catch { /* ignore */ }
}
const saveWebhook = async () => {
  whSaving.value = true
  try {
    const res = await axios.put('/ai/notifications/webhook', webhookCfg.value)
    webhookCfg.value = res.data.config
    toast.success(webhookCfg.value.enabled ? 'Webhook 已启用' : 'Webhook 已关闭')
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '保存失败')
  } finally {
    whSaving.value = false
  }
}
const testWebhook = async () => {
  if (!webhookCfg.value.url) {
    toast.warning('请先填写 Webhook 地址')
    return
  }
  whTesting.value = true
  try {
    const res = await axios.post('/ai/notifications/webhook/test', { url: webhookCfg.value.url })
    toast.success(res.data.detail || '测试消息已发送')
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '测试失败')
  } finally {
    whTesting.value = false
  }
}

// ---------- 模型接入配置（P2-6） ----------
const modelCfg = ref({ provider: 'zhipu', base_url: '', model: '', api_key: '' })
const modelStatus = ref<any>(null)
const mdSaving = ref(false)
const mdTesting = ref(false)
const loadModel = async () => {
  try {
    const res = await axios.get('/ai/model/config')
    modelStatus.value = res.data.config
    if (res.data.config) {
      modelCfg.value.provider = res.data.config.provider || 'zhipu'
      modelCfg.value.base_url = res.data.config.base_url || ''
      modelCfg.value.model = res.data.config.model || ''
      modelCfg.value.api_key = ''
    }
  } catch { /* ignore */ }
}
const saveModel = async () => {
  if (!modelCfg.value.base_url || !modelCfg.value.model) {
    toast.warning('请填写 Base URL 与模型名称')
    return
  }
  mdSaving.value = true
  try {
    const res = await axios.put('/ai/model/config', {
      provider: modelCfg.value.provider,
      api_key: modelCfg.value.api_key,   // 留空=清除覆盖 Key（回落 .env）
      base_url: modelCfg.value.base_url,
      model: modelCfg.value.model,
    })
    modelStatus.value = res.data.config
    modelCfg.value.api_key = ''
    toast.success('模型接入配置已保存并热生效')
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '保存失败')
  } finally {
    mdSaving.value = false
  }
}
const testModel = async () => {
  if (!modelCfg.value.base_url || !modelCfg.value.model) {
    toast.warning('请填写 Base URL 与模型名称')
    return
  }
  mdTesting.value = true
  try {
    const res = await axios.post('/ai/model/config/test', {
      provider: modelCfg.value.provider,
      api_key: modelCfg.value.api_key,
      base_url: modelCfg.value.base_url,
      model: modelCfg.value.model,
    })
    toast.success(res.data.detail || '连接成功')
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '连接失败')
  } finally {
    mdTesting.value = false
  }
}

const fmtUptime = (s: number) => {
  if (s < 60) return `${s} 秒`
  if (s < 3600) return `${Math.floor(s / 60)} 分钟`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`
  return `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`
}

const thresholdText = (t: string) => {
  const map: Record<string, string> = { medium: '中风险即拦截', high: '高风险拦截', critical: '仅严重拦截' }
  return map[t] || t
}

onMounted(() => {
  load()
  loadWebhook()
  loadModel()
})
</script>

<template>
  <div class="h-full space-y-4">
    <div class="flex items-center justify-between mb-1">
      <h2 class="text-xl font-bold text-primary">系统状态</h2>
      <button
        @click="load"
        :disabled="loading"
        class="px-4 py-2 bg-gradient-to-r from-accent to-low text-white rounded-lg text-sm hover:opacity-90 transition-all active:scale-95 disabled:opacity-40"
      >
        {{ loading ? '刷新中...' : '刷新' }}
      </button>
    </div>

    <!-- 健康横幅 -->
    <div
      class="rounded-xl border px-4 py-3 flex items-center gap-3 animate-card-in"
      :class="status && status.health === 'healthy' ? 'bg-safe/10 border-safe/30' : 'bg-critical/10 border-critical/30'"
    >
      <span class="w-2.5 h-2.5 rounded-full" :class="status && status.health === 'healthy' ? 'bg-safe animate-pulse' : 'bg-critical'"></span>
      <span class="font-medium text-primary">
        {{ status && status.health === 'healthy' ? '服务运行正常' : '服务状态异常' }}
      </span>
      <span v-if="status" class="text-xs text-muted ml-1">
        {{ status.service.name }} v{{ status.service.version }}
      </span>
      <span v-if="status" class="ml-auto text-xs text-muted tabular-nums">
        启动 {{ status.service.started_at }} · 已运行 {{ fmtUptime(status.service.uptime_seconds) }}
      </span>
    </div>

    <!-- 关键能力 -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="text-xs text-muted mb-1">WebSocket 实时通道</div>
        <div class="text-xl font-bold text-primary tabular-nums">{{ status?.websocket.active_connections ?? '—' }}</div>
        <div class="text-xs text-disabled mt-1">活跃连接 / {{ status?.websocket.channels ?? '—' }} 频道</div>
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="text-xs text-muted mb-1">LLM 语义分类层</div>
        <div class="text-xl font-bold tabular-nums"
          :class="status?.llm.api_key_present ? 'text-safe' : 'text-medium'">
          {{ status?.llm.api_key_present ? '已配置 Key' : '未配置' }}
        </div>
        <div class="text-xs text-muted mt-1">{{ status?.llm.classifier_enabled ? '规则 + 语义双检测' : '规则检测' }}</div>
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="text-xs text-muted mb-1">安全策略</div>
        <div class="text-xl font-bold text-primary tabular-nums">v{{ status?.policy.version ?? '—' }}</div>
        <div class="text-xs text-disabled mt-1">{{ thresholdText(status?.policy.block_threshold || '') }}</div>
      </div>
      <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
        <div class="text-xs text-muted mb-1">审计留存</div>
        <div class="text-xl font-bold text-primary tabular-nums">{{ status?.policy.audit_retention_days ?? '—' }}天</div>
        <div class="text-xs text-disabled mt-1">等保 2.0 建议 ≥ 180 天</div>
      </div>
    </div>

    <!-- 数据规模 -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-3">数据规模</h3>
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <div class="text-2xl font-bold text-primary tabular-nums">{{ status?.data.audit_logs ?? '—' }}</div>
          <div class="text-xs text-muted">审计日志</div>
        </div>
        <div>
          <div class="text-2xl font-bold text-primary tabular-nums">{{ status?.data.approvals_total ?? '—' }}</div>
          <div class="text-xs text-muted">审批请求（待审 {{ status?.data.approvals_pending ?? 0 }}）</div>
        </div>
        <div>
          <div class="text-2xl font-bold text-primary tabular-nums">{{ status?.data.sessions_active ?? '—' }}</div>
          <div class="text-xs text-muted">有效会话</div>
        </div>
      </div>
    </div>

    <!-- 数据维护 -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-2">数据维护</h3>
      <p class="text-xs text-muted mb-3">
        演示/长期使用中反复点击「清空对话 / 新建会话」可能产生无消息空会话，可一键清理（不影响有内容的会话与审计日志）。
      </p>
      <button
        @click="cleanEmptySessions"
        :disabled="cleaning"
        class="px-4 py-2 rounded-lg bg-critical/10 text-critical border border-critical/30 text-sm font-medium hover:bg-critical/20 transition-colors active:scale-95 disabled:opacity-50"
      >
        {{ cleaning ? '清理中...' : '清理空会话' }}
      </button>
    </div>

    <!-- 通知渠道（Webhook） -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-1">通知渠道 · Webhook</h3>
      <p class="text-xs text-muted mb-3">审批 / 中高风险告警事件自动 POST 到外部地址（钉钉/企微/自建网关），便于离线即时通知。</p>
      <div class="flex items-center gap-2 mb-3">
        <input
          v-model="webhookCfg.url"
          type="text"
          placeholder="https://example.com/hook/safeagent"
          class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
        />
        <button
          @click="webhookCfg.enabled = !webhookCfg.enabled"
          :class="['flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm transition-colors', webhookCfg.enabled ? 'bg-safe/10 text-safe border-safe/30' : 'bg-elevated text-muted border-border-default']"
        >{{ webhookCfg.enabled ? '已启用' : '已停用' }}</button>
      </div>
      <div class="flex gap-2">
        <button
          @click="testWebhook"
          :disabled="whTesting"
          class="px-3.5 py-2 rounded-lg text-sm bg-elevated border border-border-default text-secondary hover:border-accent/40 hover:text-accent transition-colors disabled:opacity-50"
        >{{ whTesting ? '测试中...' : '发送测试' }}</button>
        <button
          @click="saveWebhook"
          :disabled="whSaving"
          class="px-3.5 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 transition-colors disabled:opacity-50"
        >{{ whSaving ? '保存中...' : '保存配置' }}</button>
      </div>
    </div>

    <!-- 模型接入（内网/离线部署） -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-1">模型接入配置</h3>
      <p class="text-xs text-muted mb-3">
        默认接入智谱 GLM（.env 的 ZHIPU_API_KEY）。内网/离线部署可选择 OpenAI 兼容端点（vLLM / Ollama 等），保存后即时热生效。
      </p>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
        <div>
          <label class="block text-xs text-muted mb-1">接入方式</label>
          <select v-model="modelCfg.provider" class="w-full px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent">
            <option value="zhipu">智谱 GLM（bigmodel.cn）</option>
            <option value="openai">OpenAI 兼容端点（内网）</option>
          </select>
        </div>
        <div>
          <label class="block text-xs text-muted mb-1">Base URL</label>
          <input v-model="modelCfg.base_url" type="text" placeholder="https://open.bigmodel.cn/api/paas/v4"
            class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
        </div>
        <div>
          <label class="block text-xs text-muted mb-1">模型名称</label>
          <input v-model="modelCfg.model" type="text" placeholder="glm-4-flash"
            class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
        </div>
        <div>
          <label class="block text-xs text-muted mb-1">API Key</label>
          <input v-model="modelCfg.api_key" type="password" autocomplete="off" placeholder="留空保存 = 清除覆盖 Key（回落 .env）"
            class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
        </div>
      </div>
      <div class="flex items-center gap-2 flex-wrap">
        <button
          @click="testModel"
          :disabled="mdTesting"
          class="px-3.5 py-2 rounded-lg text-sm bg-elevated border border-border-default text-secondary hover:border-accent/40 hover:text-accent transition-colors disabled:opacity-50"
        >{{ mdTesting ? '测试中...' : '连通性测试' }}</button>
        <button
          @click="saveModel"
          :disabled="mdSaving"
          class="px-3.5 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 transition-colors disabled:opacity-50"
        >{{ mdSaving ? '保存中...' : '保存并热生效' }}</button>
        <span v-if="modelStatus" class="text-[11px] text-muted">
          {{ modelStatus.provider === 'openai' ? 'OpenAI 兼容' : '智谱' }} · {{ modelStatus.model }}
          · <span :class="modelStatus.has_key ? 'text-safe' : 'text-critical'">{{ modelStatus.has_key ? '已配置 Key' : '未配置 Key（回退规则检测）' }}</span>
        </span>
      </div>
    </div>
  </div>
</template>
