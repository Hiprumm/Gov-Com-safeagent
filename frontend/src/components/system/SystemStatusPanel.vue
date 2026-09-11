<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import { toast } from '@/composables/useToast'
import { useAuth } from '@/composables/useAuth'

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

// ---------- 知识库管理 ----------
const kb = ref<any>(null)
const kbDocs = ref<any[]>([])
const kbLoading = ref(false)
const kbCmdBusy = ref(false)
const kbFile = ref<File | null>(null)
const kbFileName = ref('')
const kbUploadErr = ref('')

const loadKb = async () => {
  kbLoading.value = true
  try {
    const res = await axios.get('/ai/kb/status')
    kb.value = res.data.kb
    kbDocs.value = res.data.documents || []
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '知识库状态获取失败')
  } finally {
    kbLoading.value = false
  }
}

const onKbFilePicked = (e: Event) => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0] || null
  kbFile.value = file
  kbFileName.value = file ? file.name : ''
  kbUploadErr.value = ''
}

const uploadKb = async () => {
  if (!kbFile.value) return
  kbCmdBusy.value = true
  kbUploadErr.value = ''
  try {
    const ext = kbFile.value!.name.toLowerCase()
    if (!ext.endsWith('.md') && !ext.endsWith('.txt')) {
      kbUploadErr.value = '仅支持 .md / .txt 文档'
      return
    }
    const content = await kbFile.value.text()
    const res = await axios.post('/ai/kb/upload', { filename: kbFile.value!.name, content })
    if (!res.data?.success) {
      kbUploadErr.value = res.data?.error || '上传失败'
      return
    }
    toast.success('知识文档已上传并重建索引')
    kb.value = res.data.kb
    kbDocs.value = res.data.documents || []
    kbFile.value = null
    kbFileName.value = ''
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '上传失败')
  } finally {
    kbCmdBusy.value = false
  }
}

const deleteKbDoc = async (name: string) => {
  if (!window.confirm(`将删除知识文档「${name}」并重建索引，确定删除？`)) return
  kbCmdBusy.value = true
  try {
    const res = await axios.post('/ai/kb/delete_document', { filename: name })
    if (!res.data?.success) {
      toast.error(res.data?.error || '删除失败')
      return
    }
    toast.success(`已删除「${name}」`)
    kb.value = res.data.kb
    kbDocs.value = res.data.documents || []
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '删除失败')
  } finally {
    kbCmdBusy.value = false
  }
}

const rebuildKb = async () => {
  kbCmdBusy.value = true
  try {
    const res = await axios.post('/ai/kb/rebuild')
    if (!res.data?.success) {
      toast.error(res.data?.error || '重建失败')
      return
    }
    toast.success('索引已重建')
    kb.value = res.data.kb
    kbDocs.value = res.data.documents || []
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '重建失败')
  } finally {
    kbCmdBusy.value = false
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
    if (!res.data?.success) {
      toast.error(res.data?.error || '保存失败')
      return
    }
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

// ---------- 模型接入配置（P2-6：内网/离线 OpenAI 兼容端点 + 多供应商容灾） ----------
const { currentUser } = useAuth()
// 模型接入配置仅系统管理员可查看/管理（与后端 admin.manage 权限一致）
const isAdmin = computed(() => ['admin', 'super_admin'].includes(currentUser.value?.role ?? ''))
const modelCfg = ref({
  provider: 'zhipu', base_url: '', model: '', api_key: '',
  backup_provider: 'openai', backup_base_url: '', backup_model: '', backup_api_key: '',
})
const modelStatus = ref<any>(null)
const mdSaving = ref(false)
const mdTesting = ref(false)
const mdBackupTesting = ref(false)
// 国产模型预设（信创适配：一键填充接入参数，API Key 手填）
const MODEL_PRESETS = [
  { label: '自定义（手动填写）', base_url: '', model: '' },
  { label: 'DeepSeek 官方 API', base_url: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  { label: '千问 Qwen2.5 私有化部署', base_url: 'http://<内网地址>/v1', model: 'qwen2.5-72b-instruct' },
  { label: 'GLM-4 私有化（bigmodel 网关）', base_url: 'https://open.bigmodel.cn/api/paas/v4', model: 'glm-4' },
  { label: 'Ollama 本地部署（数据不出域）', base_url: 'http://localhost:11434/v1', model: 'qwen2.5:7b' },
]
const mainPreset = ref('')
const backupPreset = ref('')
const applyPreset = (target: 'main' | 'backup', label: string) => {
  const p = MODEL_PRESETS.find(x => x.label === label)
  if (!p || !p.base_url) return
  if (target === 'main') {
    modelCfg.value.provider = 'openai'
    modelCfg.value.base_url = p.base_url
    modelCfg.value.model = p.model
  } else {
    modelCfg.value.backup_provider = 'openai'
    modelCfg.value.backup_base_url = p.base_url
    modelCfg.value.backup_model = p.model
  }
}
const loadModel = async () => {
  try {
    const res = await axios.get('/ai/model/config')
    modelStatus.value = res.data.config
    if (res.data.config) {
      modelCfg.value.provider = res.data.config.provider || 'zhipu'
      modelCfg.value.base_url = res.data.config.base_url || ''
      modelCfg.value.model = res.data.config.model || ''
      modelCfg.value.api_key = ''
      modelCfg.value.backup_provider = res.data.config.backup_provider || 'openai'
      modelCfg.value.backup_base_url = res.data.config.backup_base_url || ''
      modelCfg.value.backup_model = res.data.config.backup_model || ''
      modelCfg.value.backup_api_key = ''
    }
  } catch { /* ignore */ }
}
const saveModel = async () => {
  if (!modelCfg.value.base_url || !modelCfg.value.model) {
    toast.warning('请填写主模型 Base URL 与模型名称')
    return
  }
  mdSaving.value = true
  try {
    const res = await axios.put('/ai/model/config', {
      provider: modelCfg.value.provider,
      api_key: modelCfg.value.api_key,   // 留空=清除覆盖 Key（回落 .env）
      base_url: modelCfg.value.base_url,
      model: modelCfg.value.model,
      backup_provider: modelCfg.value.backup_provider,
      backup_api_key: modelCfg.value.backup_api_key,   // 留空=清除备用 Key（关闭容灾）
      backup_base_url: modelCfg.value.backup_base_url,
      backup_model: modelCfg.value.backup_model,
    })
    if (!res.data?.success) {
      toast.error(res.data?.error || '保存失败')
      return
    }
    modelStatus.value = res.data.config
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
const testBackupModel = async () => {
  if (!modelCfg.value.backup_base_url || !modelCfg.value.backup_model) {
    toast.warning('请填写备用模型 Base URL 与模型名称')
    return
  }
  mdBackupTesting.value = true
  try {
    const res = await axios.post('/ai/model/config/test', {
      provider: modelCfg.value.backup_provider,
      api_key: modelCfg.value.backup_api_key,
      base_url: modelCfg.value.backup_base_url,
      model: modelCfg.value.backup_model,
    })
    toast.success(res.data.detail || '备用模型连接成功')
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '备用模型连接失败')
  } finally {
    mdBackupTesting.value = false
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
  loadKb()
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

    <!-- 知识库管理 -->
    <div class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <div class="flex items-center justify-between mb-2">
        <h3 class="text-sm font-semibold text-secondary">知识库管理</h3>
        <button
          @click="loadKb"
          :disabled="kbLoading"
          class="px-2.5 py-1 rounded-md text-xs bg-elevated border border-border-default text-secondary hover:border-accent/40 hover:text-accent transition-colors disabled:opacity-50"
        >{{ kbLoading ? '刷新中...' : '刷新' }}</button>
      </div>
      <p class="text-xs text-muted mb-3">
        支持上传 <code class="text-accent">.md / .txt</code> 政务知识文档，写入本地语料并重建索引；智能问答的「知识检索」工具即可据此回答。
      </p>

      <!-- KB 统计 -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3" v-if="kb">
        <div class="rounded-lg bg-canvas border border-border-default px-3 py-2">
          <div class="text-lg font-bold text-primary tabular-nums">{{ kb.doc_count ?? '—' }}</div>
          <div class="text-[11px] text-muted">文档数</div>
        </div>
        <div class="rounded-lg bg-canvas border border-border-default px-3 py-2">
          <div class="text-lg font-bold text-primary tabular-nums">{{ kb.chunk_count ?? '—' }}</div>
          <div class="text-[11px] text-muted">检索分块</div>
        </div>
        <div class="rounded-lg bg-canvas border border-border-default px-3 py-2">
          <div class="text-lg font-bold text-accent tabular-nums">{{ kb.model || '—' }}</div>
          <div class="text-[11px] text-muted">嵌入模型</div>
        </div>
        <div class="rounded-lg bg-canvas border border-border-default px-3 py-2">
          <div class="text-lg font-bold tabular-nums" :class="kb.ready ? 'text-safe' : 'text-critical'">
            {{ kb.ready ? '就绪' : '未就绪' }}
          </div>
          <div class="text-[11px] text-muted">状态</div>
        </div>
      </div>

      <!-- 上传 -->
      <div class="flex items-center gap-2 mb-3">
        <label
          class="px-3.5 py-2 rounded-lg border border-dashed border-border-default text-secondary text-sm cursor-pointer hover:border-accent/50 hover:text-accent transition-colors inline-flex items-center gap-1.5 flex-shrink-0"
        >
          {{ kbFileName || '选择 .md / .txt 文档' }}
          <input type="file" accept=".md,.txt" class="hidden" @change="onKbFilePicked" />
        </label>
        <button
          @click="uploadKb"
          :disabled="!kbFile || kbCmdBusy"
          class="px-3.5 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 transition-colors disabled:opacity-40 flex-shrink-0"
        >{{ kbCmdBusy ? '上传中...' : '上传 & 重建索引' }}</button>
        <p v-if="kbUploadErr" class="text-xs text-critical flex-1">{{ kbUploadErr }}</p>
      </div>

      <!-- 文档清单 -->
      <div v-if="kbDocs.length" class="divide-y divide-border-default border border-border-default rounded-lg">
        <div v-for="d in kbDocs" :key="d.name" class="flex items-center gap-2 px-3 py-2 text-sm">
          <svg class="w-4 h-4 text-accent shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
          </svg>
          <span class="flex-1 truncate text-primary">{{ d.name }}</span>
          <span class="text-xs text-muted tabular-nums">{{ d.size_kb }} KB</span>
          <button
            @click="deleteKbDoc(d.name)"
            :disabled="kbCmdBusy"
            class="p-1 rounded text-muted hover:text-critical hover:bg-critical/10 transition-colors disabled:opacity-40"
            title="删除该文档"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
            </svg>
          </button>
        </div>
      </div>
      <p v-else class="text-xs text-muted mt-1">暂无知识文档，上传后自动建索引。</p>

      <div class="flex items-center gap-2 mt-3">
        <button
          @click="rebuildKb"
          :disabled="kbCmdBusy"
          class="px-3 py-1.5 rounded-lg text-xs bg-critical/10 text-critical border border-critical/30 hover:bg-critical/20 transition-colors disabled:opacity-50"
        >{{ kbCmdBusy ? '操作中...' : '重建索引' }}</button>
        <span class="text-[11px] text-muted" v-if="kb?.built_at">上次建索引 {{ kb.built_at }}</span>
      </div>
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

    <!-- 模型接入（内网/离线部署 + 多供应商容灾） -->
    <div v-if="isAdmin" class="bg-elevated/50 rounded-xl border border-border-default p-4 space-y-4">
      <div>
        <h3 class="text-sm font-semibold text-secondary mb-1">模型接入配置</h3>
        <p class="text-xs text-muted">
          默认接入智谱 GLM（.env 的 ZHIPU_API_KEY）。信创/内网部署可选择国产模型私有化端点（DeepSeek / 千问 / Ollama 等 OpenAI 兼容），
          保存后即时热生效；可配置<strong>备用模型</strong>实现多供应商容灾——主模型故障/超时自动切换。
        </p>
      </div>

      <!-- 国产模型预设（信创适配） -->
      <div>
        <label class="block text-xs text-muted mb-1">国产模型预设（一键填充接入参数，API Key 手填）</label>
        <select v-model="mainPreset" @change="applyPreset('main', mainPreset)"
          class="w-full px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent">
          <option v-for="p in MODEL_PRESETS" :key="p.label" :value="p.label">{{ p.label }}</option>
        </select>
      </div>

      <!-- 主模型 -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <h4 class="text-xs font-semibold text-accent">主模型</h4>
          <span class="text-[10px] text-muted">当前：{{ modelStatus?.provider === 'openai' ? 'OpenAI 兼容' : '智谱' }} · {{ modelStatus?.model || '未配置' }}</span>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-xs text-muted mb-1">接入方式</label>
            <select v-model="modelCfg.provider" class="w-full px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent">
              <option value="zhipu">智谱 GLM（bigmodel.cn）</option>
              <option value="openai">OpenAI 兼容端点（内网/国产）</option>
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
        <div class="mt-2 flex items-center gap-2 flex-wrap">
          <button
            @click="testModel"
            :disabled="mdTesting"
            class="px-3.5 py-1.5 rounded-lg text-xs bg-elevated border border-border-default text-secondary hover:border-accent/40 hover:text-accent transition-colors disabled:opacity-50"
          >{{ mdTesting ? '测试中...' : '主模型连通测试' }}</button>
          <span v-if="modelStatus" class="text-[11px] text-muted">
            <span :class="modelStatus.has_key ? 'text-safe' : 'text-critical'">{{ modelStatus.has_key ? '已配置 Key（安全隐藏，不在输入框回显）' : '未配置 Key（回退规则检测）' }}</span>
            <template v-if="modelStatus.backup_has_key && modelStatus.backup_base_url"> · 已启用备用容灾</template>
          </span>
        </div>
      </div>

      <!-- 备用模型（多供应商容灾） -->
      <div class="border-t border-border-default pt-3">
        <div class="flex items-center gap-2 mb-2">
          <h4 class="text-xs font-semibold text-accent2">备用模型（容灾切换）</h4>
          <span class="text-[10px] text-muted">主模型故障/超时自动切换 · 连续失败 3 次进入冷却</span>
        </div>
        <div class="mb-2">
          <label class="block text-xs text-muted mb-1">备用模型预设</label>
          <select v-model="backupPreset" @change="applyPreset('backup', backupPreset)"
            class="w-full px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent">
            <option v-for="p in MODEL_PRESETS" :key="p.label" :value="p.label">{{ p.label }}</option>
          </select>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-xs text-muted mb-1">接入方式</label>
            <select v-model="modelCfg.backup_provider" class="w-full px-3 py-2 bg-canvas border border-border-default text-secondary rounded-lg text-sm focus:outline-none focus:border-accent">
              <option value="openai">OpenAI 兼容端点（内网/国产）</option>
              <option value="zhipu">智谱 GLM（bigmodel.cn）</option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">Base URL</label>
            <input v-model="modelCfg.backup_base_url" type="text" placeholder="http://localhost:11434/v1"
              class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">模型名称</label>
            <input v-model="modelCfg.backup_model" type="text" placeholder="qwen2.5:7b"
              class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">API Key</label>
            <input v-model="modelCfg.backup_api_key" type="password" autocomplete="off" placeholder="留空保存 = 关闭备用容灾"
              class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
          </div>
        </div>
        <div class="mt-2 flex items-center gap-2 flex-wrap">
          <button
            @click="testBackupModel"
            :disabled="mdBackupTesting"
            class="px-3.5 py-1.5 rounded-lg text-xs bg-elevated border border-border-default text-secondary hover:border-accent/40 hover:text-accent transition-colors disabled:opacity-50"
          >{{ mdBackupTesting ? '测试中...' : '备用模型连通测试' }}</button>
        </div>
      </div>

      <div class="flex items-center gap-2 flex-wrap">
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

    <!-- 非管理员只读提示（模型接入配置仅管理员可管理） -->
    <div v-else class="bg-elevated/50 rounded-xl border border-border-default p-4">
      <h3 class="text-sm font-semibold text-secondary mb-1">模型接入配置</h3>
      <p class="text-xs text-muted">
        模型接入配置仅系统管理员可查看与管理（含模型供应商 / API Key / 备用容灾）。若需切换模型或配置备用模型，请使用系统管理员账号登录。
      </p>
    </div>
  </div>
</template>
