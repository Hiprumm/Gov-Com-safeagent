<template>
  <div class="h-full space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-bold text-primary">治理中心</h2>
        <p class="text-xs text-muted mt-0.5">应急联动 · 开放生态 · PIPL 合规台账 · 合规对标报告</p>
      </div>
    </div>

    <!-- 子页签 -->
    <div class="flex gap-2 flex-wrap">
      <button
        v-for="t in subTabs" :key="t.key"
        @click="active = t.key"
        :class="['px-3 py-1.5 rounded-lg text-sm transition-colors', active === t.key ? 'bg-accent/15 text-accent border border-accent/30' : 'bg-elevated text-muted border border-border-default hover:text-secondary']"
      >{{ t.label }}</button>
    </div>

    <!-- ============ ① 应急联动中心 ============ -->
    <div v-if="active === 'emergency'" class="space-y-4">
      <!-- 全局熔断 -->
      <div class="rounded-xl border p-4" :class="emg.global_engaged ? 'bg-critical/10 border-critical/40' : 'bg-elevated/50 border-border-default'">
        <div class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full" :class="emg.global_engaged ? 'bg-critical animate-pulse' : 'bg-safe'"></span>
            <h3 class="text-sm font-semibold" :class="emg.global_engaged ? 'text-critical' : 'text-secondary'">全局熔断</h3>
          </div>
          <span class="text-xs text-muted">{{ emg.global_engaged ? '执行中：所有智能体请求被拦截' : '正常：未触发熔断' }}</span>
        </div>
        <p class="text-xs text-muted mb-3">一键暂停平台所有智能体执行（登录、审计、管理接口不受影响），用于重大安全事件应急处置。</p>
        <div class="flex items-center gap-2">
          <input v-model="circuitReason" placeholder="熔断原因（必填）"
                 class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent" />
          <button v-if="!emg.global_engaged" @click="engage"
                  :disabled="busy || !circuitReason"
                  class="px-4 py-2 rounded-lg text-sm bg-critical text-white hover:bg-critical/90 transition-colors disabled:opacity-40">开启全局熔断</button>
          <button v-else @click="disengage" :disabled="busy"
                  class="px-4 py-2 rounded-lg text-sm bg-safe text-white hover:opacity-90 transition-colors disabled:opacity-40">解除熔断</button>
        </div>
      </div>

      <!-- 账号/IP 封锁 -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
          <h3 class="text-sm font-semibold text-secondary mb-2">账号封锁</h3>
          <div class="flex gap-2 mb-3">
            <input v-model="userTarget" placeholder="用户名" class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg focus:outline-none" />
            <button @click="blockUser" :disabled="busy || !userTarget" class="px-3 py-2 rounded-lg text-sm bg-critical/10 text-critical border border-critical/30 hover:bg-critical/20 disabled:opacity-40">封锁</button>
          </div>
          <div v-if="emg.blocked_users.length" class="space-y-1.5">
            <div v-for="u in emg.blocked_users" :key="u" class="flex items-center justify-between text-sm px-2 py-1 bg-canvas border border-border-default rounded">
              <span class="text-primary">{{ u }}</span>
              <button @click="unblockUser(u)" class="text-xs text-accent hover:underline">解封</button>
            </div>
          </div>
          <p v-else class="text-xs text-muted">当前无被封锁账号。</p>
        </div>
        <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
          <h3 class="text-sm font-semibold text-secondary mb-2">IP 封锁</h3>
          <div class="flex gap-2 mb-3">
            <input v-model="ipTarget" placeholder="IP 地址，如 192.168.1.5" class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg focus:outline-none" />
            <button @click="blockIp" :disabled="busy || !ipTarget" class="px-3 py-2 rounded-lg text-sm bg-critical/10 text-critical border border-critical/30 hover:bg-critical/20 disabled:opacity-40">封锁</button>
          </div>
          <div v-if="emg.blocked_ips.length" class="space-y-1.5">
            <div v-for="ip in emg.blocked_ips" :key="ip" class="flex items-center justify-between text-sm px-2 py-1 bg-canvas border border-border-default rounded">
              <span class="text-primary">{{ ip }}</span>
              <button @click="unblockIp(ip)" class="text-xs text-accent hover:underline">解锁</button>
            </div>
          </div>
          <p v-else class="text-xs text-muted">当前无被封锁 IP。</p>
        </div>
      </div>

      <!-- 联动记录 -->
      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">应急操作记录（审计留痕）</h3>
        <div class="text-xs text-muted mb-2">封锁 / 熔断动作均写入审计日志，并可在「Webhook 通知渠道」联动告警。</div>
        <div v-if="emg.history.length" class="max-h-52 overflow-auto divide-y divide-border-default border border-border-default rounded-lg">
          <div v-for="h in emg.history" :key="h.id" class="flex items-center gap-2 px-3 py-2 text-xs">
            <span class="text-muted tabular-nums">{{ h.created_at }}</span>
            <span class="px-1.5 py-0.5 rounded bg-accent/10 text-accent">{{ h.control_type }}</span>
            <span class="text-secondary">{{ h.target }}</span>
            <span v-if="h.reason" class="text-muted truncate flex-1">{{ h.reason }}</span>
            <span :class="h.enabled ? 'text-critical' : 'text-safe'">{{ h.enabled ? '生效' : '已解除' }}</span>
          </div>
        </div>
        <p v-else class="text-xs text-muted">暂无应急操作记录。</p>
      </div>
    </div>

    <!-- ============ ② 开放生态管理 ============ -->
    <div v-if="active === 'ecosystem'" class="space-y-4">
      <div class="flex flex-wrap gap-2">
        <div class="px-4 py-2 rounded-lg bg-elevated/50 border border-border-default text-sm"><span class="text-muted">调用方 </span><b class="text-primary">{{ eco.client_count ?? 0 }}</b></div>
        <div class="px-4 py-2 rounded-lg bg-elevated/50 border border-border-default text-sm"><span class="text-muted">累计调用 </span><b class="text-primary">{{ eco.total_used ?? 0 }}</b></div>
        <button @click="loadEco" class="ml-auto px-3 py-2 rounded-lg text-sm bg-elevated border border-border-default text-secondary hover:text-accent">刷新</button>
      </div>

      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-3">新增调用方并签发 Token</h3>
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-3">
          <input v-model="ecoForm.name" placeholder="调用方名称 *" class="px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg focus:outline-none" />
          <input v-model.number="ecoForm.rate_limit" type="number" placeholder="限流(次/60s)" class="px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg" />
          <input v-model.number="ecoForm.quota" type="number" placeholder="配额(总调用, 0=不限)" class="px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg" />
          <button @click="createClient" :disabled="busy || !ecoForm.name" class="px-3 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 disabled:opacity-40">签发 Token</button>
        </div>
        <input v-model="ecoForm.description" placeholder="描述（选填）" class="w-full px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg" />
        <div v-if="issuedToken" class="mt-3 text-xs p-2 rounded bg-safe/10 border border-safe/30 text-safe">
          新令牌（仅显示一次，系统只存哈希）：<code class="font-mono select-all">{{ issuedToken }}</code>
        </div>
      </div>

      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">调用方列表</h3>
        <div v-if="eco.clients.length">
          <div class="divide-y divide-border-default border border-border-default rounded-lg">
            <div v-for="c in eco.clients" :key="c.client_id" class="flex items-center gap-3 px-3 py-2 text-sm">
              <div class="flex-1 min-w-0">
                <div class="text-primary truncate">{{ c.name }} <span class="text-xs text-muted">{{ c.client_id }}</span></div>
                <div class="text-xs text-muted tabular-nums">限流 {{ c.rate_limit }}/60s · 配额 {{ c.quota || '∞' }} · 已用 {{ c.used }}</div>
              </div>
              <span :class="c.enabled ? 'text-safe' : 'text-critical'" class="text-xs">{{ c.enabled ? '启用' : '停用' }}</span>
              <button @click="toggleClient(c)" class="px-2 py-1 rounded text-xs border border-border-default text-secondary hover:text-accent">{{ c.enabled ? '停用' : '启用' }}</button>
              <button @click="delClient(c)" class="px-2 py-1 rounded text-xs border border-border-default text-critical hover:bg-critical/10">删除</button>
            </div>
          </div>
          <p class="text-xs text-muted mt-2">外部调用方使用 <code class="text-accent">X-Client-Token: &lt;token&gt;</code> 请求 <code class="text-accent">POST /api/open/chat</code> 即受鉴权 / 限流 / 配额 + 调用审计约束。</p>
        </div>
        <p v-else class="text-xs text-muted">暂无调用方。</p>
      </div>

      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">调用审计日志</h3>
        <div v-if="eco.logs.length" class="max-h-52 overflow-auto divide-y divide-border-default border border-border-default rounded-lg">
          <div v-for="l in eco.logs" :key="l.id" class="px-3 py-1.5 text-xs flex justify-between">
            <span class="text-muted">{{ l.created_at }} · {{ l.name }} · {{ l.path }}</span>
            <span :class="l.status === 200 ? 'text-safe' : 'text-critical'">{{ l.status }}</span>
          </div>
        </div>
        <p v-else class="text-xs text-muted">暂无调用记录。</p>
      </div>
    </div>

    <!-- ============ ③ PIPL 合规台账 ============ -->
    <div v-if="active === 'pipl'" class="space-y-4">
      <div class="flex flex-wrap gap-2">
        <div class="px-4 py-2 rounded-lg bg-elevated/50 border border-border-default text-sm"><span class="text-muted">已登记 </span><b class="text-primary">{{ pipl.total ?? 0 }}</b></div>
        <div class="px-4 py-2 rounded-lg bg-elevated/50 border border-border-default text-sm"><span class="text-muted">待评估 </span><b class="text-medium">{{ pipl.pending ?? 0 }}</b></div>
        <div v-for="(n, k) in pipl.by_type" :key="k" class="px-4 py-2 rounded-lg bg-elevated/50 border border-border-default text-sm"><span class="text-muted">{{ k }} </span><b class="text-primary">{{ n }}</b></div>
        <button @click="loadPipl" class="px-3 py-2 rounded-lg text-sm bg-elevated border border-border-default text-secondary hover:text-accent">刷新</button>
        <button @click="exportPipl('csv')" :disabled="busy || (pipl.total ?? 0) === 0" class="px-3 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 disabled:opacity-40">导出 CSV</button>
        <button @click="exportPipl('json')" :disabled="busy || (pipl.total ?? 0) === 0" class="px-3 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 disabled:opacity-40">导出 JSON</button>
      </div>

      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-1">PII 识别登记</h3>
        <p class="text-xs text-muted mb-3">智能问答中的用户输入会自动识别（手机号/身份证/邮箱/银行卡/IP 等）并登记为台账留痕；也可在此手工扫描一段文本。</p>
        <div class="flex gap-2 mb-2">
          <input v-model="scanText" placeholder="粘贴文本，点击「扫描识别」" class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary text-sm rounded-lg focus:outline-none" />
          <button @click="scanManual" :disabled="busy || !scanText" class="px-3 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 disabled:opacity-40">扫描识别</button>
        </div>
      </div>

      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">台账明细（处理合法性评估）</h3>
        <div v-if="pipl.records.length">
          <div class="divide-y divide-border-default border border-border-default rounded-lg">
            <div v-for="r in pipl.records" :key="r.id" class="px-3 py-2 text-sm space-y-1.5">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="px-1.5 py-0.5 rounded text-xs bg-accent/10 text-accent">{{ r.pii_type }}</span>
                <span class="text-secondary font-mono">{{ r.masked_value }}</span>
                <span class="text-xs text-muted">{{ r.source }} · {{ r.session_id }}</span>
                <span :class="r.assessment === '合规' ? 'text-safe' : r.assessment === '不合规-需整改' ? 'text-critical' : 'text-medium'" class="text-xs">{{ r.assessment }}</span>
              </div>
              <div class="flex items-center gap-2 flex-wrap">
                <select v-model="r.legal_basis" class="px-2 py-1.5 text-xs bg-canvas border border-border-default text-secondary rounded">
                  <option value="">处理合法性依据…</option>
                  <option v-for="b in legalBasis" :key="b" :value="b">{{ b }}</option>
                </select>
                <button @click="savePipl(r)" :disabled="busy" class="px-2 py-1.5 rounded text-xs border border-border-default text-secondary hover:text-accent disabled:opacity-40">保存评估</button>
              </div>
            </div>
          </div>
        </div>
        <p v-else class="text-xs text-muted">暂无 PII 登记记录。发送一条含手机号/身份证号的智能问答，会自动登记到此台账。</p>
      </div>
    </div>

    <!-- ============ ④ 合规对标报告 ============ -->
    <div v-if="active === 'compliance'" class="space-y-4">
      <div class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-1">合规对标报告</h3>
        <p class="text-xs text-muted mb-3">依据等保2.0 / 生成式AI服务合规 / 数据安全法要点实时生成安全评估报告，覆盖审计要素、内容安全合格率、AIGC 标识与风险覆盖矩阵。导出后可在浏览器打印为 PDF。</p>
        <div class="flex gap-2">
          <button @click="loadReport('json')" :disabled="busy" class="px-3 py-2 rounded-lg text-sm bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25 disabled:opacity-40">生成 JSON</button>
          <button @click="loadReport('html')" :disabled="busy" class="px-3 py-2 rounded-lg text-sm bg-elevated border border-border-default text-secondary hover:text-accent disabled:opacity-40">生成 HTML</button>
          <button v-if="reportHtml" @click="openReport" class="px-3 py-2 rounded-lg text-sm bg-critical/10 text-critical border border-critical/30 hover:bg-critical/20">导出 PDF（打开后打印）</button>
        </div>
      </div>

      <div v-if="reportHtml" class="rounded-xl border border-border-default bg-elevated/50 p-4 overflow-auto max-h-[70vh]">
        <div class="text-xs text-muted mb-2">报告 HTML 预览：</div>
        <iframe :srcdoc="reportHtml" class="w-full h-[60vh] bg-white rounded-lg border border-border-default"></iframe>
      </div>

      <div v-if="reportJson" class="rounded-xl border border-border-default bg-elevated/50 p-4">
        <h3 class="text-sm font-semibold text-secondary mb-2">核心指标</h3>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div><div class="text-xl font-bold text-primary tabular-nums">{{ reportJson.overall_score ?? '—' }}</div><div class="text-xs text-muted">综合得分</div></div>
          <div><div class="text-xl font-bold text-primary tabular-nums">{{ reportJson.compliance_grade ?? '—' }}</div><div class="text-xs text-muted">合规等级</div></div>
          <div><div class="text-xl font-bold text-primary tabular-nums">{{ reportJson.audit?.overall ?? '—' }}</div><div class="text-xs text-muted">审计合规率</div></div>
          <div><div class="text-xl font-bold text-primary tabular-nums">{{ reportJson.content_safety?.pass_rate ?? '—' }}</div><div class="text-xs text-muted">内容安全合格率</div></div>
        </div>
        <pre class="mt-3 text-[11px] text-muted bg-canvas p-3 rounded-lg overflow-auto max-h-64">{{ JSON.stringify(reportJson, null, 2) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { useToast } from '@/composables/useToast'

const toast = useToast()
const busy = ref(false)
const active = ref('emergency')
const subTabs = [
  { key: 'emergency', label: '应急联动' },
  { key: 'ecosystem', label: '开放生态' },
  { key: 'pipl', label: 'PIPL 台账' },
  { key: 'compliance', label: '合规报告' },
]

// ---------- ① 应急联动 ----------
const emg = ref<any>({ global_engaged: false, blocked_users: [], blocked_ips: [], history: [] })
const circuitReason = ref('')
const userTarget = ref('')
const ipTarget = ref('')
const loadEmg = async () => {
  try {
    const r = await axios.get('/ai/emergency/status')
    if (r.data) {
      emg.value.global_engaged = !!r.data.global_engaged
      emg.value.blocked_users = r.data.blocked_users || []
      emg.value.blocked_ips = r.data.blocked_ips || []
      emg.value.history = r.data.history || []
    }
  } catch { /* path guarded by backend */ }
}
const engage = async () => {
  if (!circuitReason.value) { toast.warning('请填写熔断原因'); return }
  busy.value = true
  try {
    const r = await axios.post('/ai/emergency/engage', { reason: circuitReason.value })
    if (r.data?.success) { toast.success('全局熔断已开启'); circuitReason.value = '' }
  } catch (e: any) { toast.error(e.response?.data?.detail || '开启失败') } finally { busy.value = false; loadEmg() }
}
const disengage = async () => {
  busy.value = true
  try {
    const r = await axios.post('/ai/emergency/disengage')
    toast.success(r.data?.success ? '已解除熔断' : '解除失败')
  } catch (e: any) { toast.error(e.response?.data?.detail || '解除失败') } finally { busy.value = false; loadEmg() }
}
const blockUser = async () => {
  if (!userTarget.value) return
  busy.value = true
  try {
    await axios.post('/ai/emergency/block_user', { username: userTarget.value, reason: '人工封锁' })
    toast.success('账号已封锁'); userTarget.value = ''
  } catch (e: any) { toast.error(e.response?.data?.detail || '封锁失败') } finally { busy.value = false; loadEmg() }
}
const unblockUser = async (u: string) => { await axios.post('/ai/emergency/unblock_user', { username: u }); toast.success(`已解封 ${u}`); loadEmg() }
const blockIp = async () => {
  if (!ipTarget.value) return
  busy.value = true
  try {
    await axios.post('/ai/emergency/block_ip', { ip: ipTarget.value, reason: '人工封锁' })
    toast.success('IP 已封锁'); ipTarget.value = ''
  } catch (e: any) { toast.error(e.response?.data?.detail || '封锁失败') } finally { busy.value = false; loadEmg() }
}
const unblockIp = async (ip: string) => { await axios.post('/ai/emergency/unblock_ip', { ip }); toast.success(`已解锁 ${ip}`); loadEmg() }

// ---------- ② 开放生态 ----------
const eco = ref<any>({ client_count: 0, total_used: 0, clients: [], logs: [] })
const ecoForm = ref({ name: '', rate_limit: 60, quota: 0, description: '' })
const issuedToken = ref('')
const loadEco = async () => {
  try {
    const [c, l] = await Promise.all([axios.get('/ai/ecosystem/clients'), axios.get('/ai/ecosystem/logs')])
    eco.value.client_count = c.data.client_count
    eco.value.total_used = c.data.total_used
    eco.value.clients = c.data.clients || []
    eco.value.logs = l.data.logs || []
  } catch { /* ignore */ }
}
const createClient = async () => {
  if (!ecoForm.value.name) { toast.warning('请填写调用方名称'); return }
  busy.value = true; issuedToken.value = ''
  try {
    const r = await axios.post('/ai/ecosystem/create', ecoForm.value)
    if (r.data?.success) { issuedToken.value = r.data.token; toast.success('Token 已签发'); ecoForm.value = { name: '', rate_limit: 60, quota: 0, description: '' } }
  } catch (e: any) { toast.error(e.response?.data?.detail || '创建失败') } finally { busy.value = false; loadEco() }
}
const toggleClient = async (c: any) => { await axios.post('/ai/ecosystem/toggle', { client_id: c.client_id, enabled: !c.enabled }); loadEco() }
const delClient = async (c: any) => {
  if (!window.confirm(`删除调用方「${c.name}」及其调用日志？`)) return
  await axios.post('/ai/ecosystem/delete', { client_id: c.client_id }); toast.success('已删除'); loadEco()
}

// ---------- ③ PIPL ----------
const pipl = ref<any>({ total: 0, pending: 0, by_type: {}, records: [] })
const scanText = ref('')
const legalBasis = [
  '同意（个人信息保护法第13条第1项）',
  '为订立/履行合同所必需（第13条第2项）',
  '履行法定职责或义务（第13条第3项）',
  '合理处理已公开信息（第13条第5项）',
]
const loadPipl = async () => {
  try {
    const r = await axios.get('/ai/pipl/records')
    pipl.value.total = r.data.total; pipl.value.pending = r.data.pending; pipl.value.by_type = r.data.by_type || {}; pipl.value.records = r.data.records || []
  } catch { /* ignore */ }
}
const scanManual = async () => {
  if (!scanText.value) return
  busy.value = true
  try {
    const r = await axios.post('/ai/pipl/scan', { text: scanText.value, source: 'manual' })
    toast.success(`识别登记 ${r.data?.found_count ?? 0} 条 PII`); scanText.value = ''
  } catch (e: any) { toast.error(e.response?.data?.detail || '扫描失败') } finally { busy.value = false; loadPipl() }
}
const savePipl = async (r: any) => {
  busy.value = true
  try {
    await axios.post('/ai/pipl/update', { id: r.id, legal_basis: r.legal_basis, assessment: r.assessment || '合规' })
    toast.success('评估已保存'); loadPipl()
  } catch (e: any) { toast.error(e.response?.data?.detail || '保存失败') } finally { busy.value = false }
}
const exportPipl = async (fmt: string) => {
  busy.value = true
  try {
    const r = await axios.get(`/ai/pipl/export?fmt=${fmt}`)
    const blob = new Blob([r.data.content], { type: fmt === 'json' ? 'application/json' : 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = r.data.filename || `pipl_records.${fmt}`
    a.click(); URL.revokeObjectURL(a.href)
    toast.success(`已导出台账 ${r.data?.count ?? 0} 条（已审计留痕）`)
  } catch (e: any) { toast.error(e.response?.data?.detail || '导出失败') } finally { busy.value = false }
}

// ---------- ④ 合规报告 ----------
const reportJson = ref<any>(null)
const reportHtml = ref('')
const loadReport = async (fmt: string) => {
  busy.value = true
  try {
    const r = await axios.get(`/ai/compliance/report?fmt=${fmt}`)
    if (fmt === 'json') { reportJson.value = r.data.data; reportHtml.value = '' }
    else { reportHtml.value = r.data.content }
  } catch (e: any) { toast.error(e.response?.data?.detail || '生成失败') } finally { busy.value = false }
}
const openReport = () => {
  if (!reportHtml.value) return
  const w = window.open('', '_blank', 'width=1000,height=800')
  if (w) { w.document.write(`<html><head><meta charset="utf-8"><title>合规对标报告</title></head><body>${reportHtml.value}</body></html>`); w.document.close(); w.focus() }
}

onMounted(() => { loadEmg(); loadEco(); loadPipl() })
</script>