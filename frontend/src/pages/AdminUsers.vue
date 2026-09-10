<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import {
  Users, UserPlus, ArrowLeft, RefreshCw, KeyRound, ShieldCheck,
  Pencil, Trash2, Ban, CircleCheck, Building2, Settings,
} from 'lucide-vue-next'
import { useAuth } from '@/composables/useAuth'
import { toast } from '@/composables/useToast'

const router = useRouter()
const { currentUser, initAuth } = useAuth()

const ROLES = ['admin', 'operator', 'auditor', 'manager', 'user']
const ROLE_LABEL: Record<string, string> = {
  admin: '系统管理员', operator: '安全运维', auditor: '合规审计', manager: '部门负责人', user: '业务用户',
}

// 口令策略须与后端 auth.check_password_policy 保持一致（≥8 位 + 大小写/数字/符号至少三类），
// 否则前端放行后会被后端拒绝，造成"填了却建不了"的困惑
const pwPolicyError = (pw: string): string => {
  if (!pw || pw.length < 8) return '密码至少 8 位'
  const cats = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length
  if (cats < 3) return '密码需包含大写字母、小写字母、数字、符号中的至少三类'
  return ''
}

// ---- 数据 ----
const users = ref<any[]>([])
const departments = ref<string[]>([])
const stats = ref<any>(null)
const loading = ref(false)

// 编辑/新建抽屉态
const editing = ref(false)
const form = ref<Record<string, any>>({
  username: '', password: '', display_name: '', role: 'user',
  department: '', position: '', note: '', status: 'active',
})
const isEdit = ref(false)

const load = async () => {
  loading.value = true
  try {
    const [u, d, s] = await Promise.all([
      axios.get('/api/admin/users'),
      axios.get('/api/admin/departments'),
      axios.get('/api/admin/stats'),
    ])
    users.value = u.data?.users || []
    departments.value = d.data?.departments || []
    stats.value = s.data?.stats || null
  } catch (e: any) {
    if (e.response?.status === 401 || e.response?.status === 403) {
      toast.error('无管理员权限')
      router.replace('/')
    } else {
      toast.error('加载用户列表失败')
    }
  } finally {
    loading.value = false
  }
}
onMounted(async () => {
  // 恢复登录态（深链接直达 /admin/users 时 currentUser 尚为空）
  if (!currentUser.value) {
    const ok = await initAuth()
    if (!ok) return router.replace('/login')
  }
  // admin-only：非管理员踢回工作台
  if (currentUser.value?.role !== 'admin') {
    toast.info('仅系统管理员可进入后台管理')
    router.replace('/')
    return
  }
  load()
})

// ---- 新增 / 编辑 ----
const openCreate = () => {
  isEdit.value = false
  form.value = { username: '', password: '', display_name: '', role: 'user', department: '', position: '', note: '', status: 'active' }
  editing.value = true
}
const openEdit = (u: any) => {
  isEdit.value = true
  form.value = { username: u.username, display_name: u.display_name, role: u.role, department: u.department || '', position: u.position || '', note: u.note || '', status: u.status }
  editing.value = true
}

const saveUser = async () => {
  if (!isEdit.value) {
    if (!form.value.username?.trim()) return toast.error('请输入用户名')
    const pwErr = pwPolicyError(form.value.password || '')
    if (pwErr) return toast.error(pwErr)
    try {
      const r = await axios.post('/api/admin/users', form.value)
      if (!r.data?.success) return toast.error(r.data?.error || '创建失败')
      toast.success(r.data.message)
    } catch (e: any) {
      return toast.error(e.response?.data?.detail || e.response?.data?.error || '创建失败')
    }
  } else {
    try {
      const { username, ...profile } = form.value
      delete (profile as any).password
      const r = await axios.put(`/api/admin/users/${username}`, profile)
      if (!r.data?.success) return toast.error(r.data?.error || '更新失败')
      toast.success(r.data.message)
    } catch (e: any) {
      return toast.error(e.response?.data?.detail || e.response?.data?.error || '更新失败')
    }
  }
  editing.value = false
  load()
}

// ---- 重置密码 / 启停 / 删除 ----
const resetPw = async (u: any) => {
  const newPw = window.prompt(`为账号 ${u.username} 设置新密码（≥8 位，含大小写/数字/符号至少三类）：`, '')
  if (newPw === null) return
  const pwErr = pwPolicyError(newPw)
  if (pwErr) return toast.error(pwErr)
  try {
    const r = await axios.post(`/api/admin/users/${u.username}/reset_password`, { password: newPw })
    if (!r.data?.success) return toast.error(r.data?.error || '重置失败')
    toast.success(r.data.message)
  } catch (e: any) {
    toast.error(e.response?.data?.detail || e.response?.data?.error || '重置失败')
  }
}
const toggleStatus = async (u: any) => {
  const next = u.status === 'active' ? 'disabled' : 'active'
  try {
    const r = await axios.put(`/api/admin/users/${u.username}`, { status: next })
    if (!r.data?.success) return toast.error(r.data?.error || '操作失败')
    toast.success(next === 'active' ? `已启用 ${u.username}` : `已停用 ${u.username}`)
    load()
  } catch (e: any) {
    toast.error(e.response?.data?.detail || e.response?.data?.error || '操作失败')
  }
}
const delUser = async (u: any) => {
  if (!window.confirm(`确定删除账号 ${u.username} 吗？其历史审计日志仍保留。`)) return
  try {
    const r = await axios.delete(`/api/admin/users/${u.username}`)
    if (!r.data?.success) return toast.error(r.data?.error || '删除失败')
    toast.success(r.data.message)
    load()
  } catch (e: any) {
    toast.error(e.response?.data?.detail || e.response?.data?.error || '删除失败')
  }
}
const addDept = async () => {
  const name = window.prompt('新增部门名称：', '')
  if (!name?.trim()) return
  try {
    const r = await axios.post('/api/admin/departments', { name: name.trim() })
    if (!r.data?.success) return toast.error(r.data?.error || '操作失败')
    toast.success(r.data.message || '已新增部门')
    load()
  } catch (e: any) {
    toast.error(e.response?.data?.detail || e.response?.data?.error || '操作失败')
  }
}

const roleColor = (r: string) => ({
  admin: 'bg-medium/15 text-medium',
  operator: 'bg-accent/15 text-accent',
  auditor: 'bg-accent2/15 text-accent2',
  manager: 'bg-safe/20 text-safe',
  user: 'bg-elevated text-secondary',
}[r] || 'bg-elevated text-secondary')
const statCards = computed(() => [
  { label: '账号总数', value: stats.value?.total ?? '-', icon: Users },
  { label: '启用中', value: stats.value?.active ?? '-', icon: CircleCheck },
  { label: '已停用', value: stats.value?.disabled ?? '-', icon: Ban },
  { label: '部门数', value: departments.value.length, icon: Building2 },
])
</script>

<template>
  <div class="min-h-screen bg-canvas text-primary">
    <!-- 顶栏 -->
    <header class="sticky top-0 z-20 border-b border-border-default bg-surface/90 backdrop-blur">
      <div class="max-w-[1200px] mx-auto px-4 sm:px-6 h-14 flex items-center gap-3">
        <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background: linear-gradient(135deg,#06B6D4,#3B82F6)">
          <Settings class="w-5 h-5 text-white" />
        </div>
        <div class="flex-1 min-w-0">
          <h1 class="text-sm font-bold leading-none">用户与组织管理</h1>
          <p class="text-[11px] text-muted mt-1">后台管理 · 仅系统管理员 · 账号由管理员创建，组织内分部门按岗授权</p>
        </div>
        <button @click="load" class="p-2 rounded-lg hover:bg-hover text-secondary transition-colors" title="刷新">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
        </button>
        <button @click="router.push('/')" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-elevated border border-border-default text-secondary text-xs hover:border-accent/40 hover:text-accent transition-colors">
          <ArrowLeft class="w-4 h-4" /> 返回工作台
        </button>
      </div>
    </header>

    <main class="max-w-[1200px] mx-auto px-4 sm:px-6 py-5 space-y-4">
      <!-- 统计 -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div v-for="c in statCards" :key="c.label" class="bg-surface rounded-2xl border border-border-default p-4 flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-accent/10 text-accent flex items-center justify-center"><component :is="c.icon" class="w-5 h-5" /></div>
          <div>
            <div class="text-xl font-bold">{{ c.value }}</div>
            <div class="text-xs text-muted">{{ c.label }}</div>
          </div>
        </div>
      </div>

      <div class="grid lg:grid-cols-[1fr_260px] gap-4 items-start">
        <!-- 用户表 -->
        <div class="bg-surface rounded-2xl border border-border-default">
          <div class="flex items-center justify-between px-4 py-3 border-b border-border-default">
            <h2 class="text-sm font-bold flex items-center gap-2"><Users class="w-4 h-4 text-accent" /> 账号列表</h2>
            <button @click="openCreate" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-accent to-low text-white text-xs font-medium hover:opacity-90 active:scale-95">
              <UserPlus class="w-4 h-4" /> 新建账号
            </button>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-left text-xs text-muted border-b border-border-default">
                  <th class="px-4 py-2 font-medium">用户名</th>
                  <th class="px-4 py-2 font-medium">姓名</th>
                  <th class="px-4 py-2 font-medium">角色</th>
                  <th class="px-4 py-2 font-medium">部门 / 岗位</th>
                  <th class="px-4 py-2 font-medium">状态</th>
                  <th class="px-4 py-2 font-medium">MFA</th>
                  <th class="px-4 py-2 font-medium text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="u in users" :key="u.username" class="border-b border-border-default/60 hover:bg-hover/40">
                  <td class="px-4 py-2.5 font-medium">{{ u.username }}</td>
                  <td class="px-4 py-2.5">{{ u.display_name }}</td>
                  <td class="px-4 py-2.5"><span class="text-[11px] px-2 py-0.5 rounded-full font-medium" :class="roleColor(u.role)">{{ ROLE_LABEL[u.role] || u.role }}</span></td>
                  <td class="px-4 py-2.5 text-secondary">{{ u.department || '—' }}<span v-if="u.position" class="text-muted"> · {{ u.position }}</span></td>
                  <td class="px-4 py-2.5">
                    <span class="text-[11px] px-2 py-0.5 rounded-full font-medium" :class="u.status === 'active' ? 'bg-safe/15 text-safe' : 'bg-critical/15 text-critical'">
                      {{ u.status === 'active' ? '启用' : '停用' }}
                    </span>
                  </td>
                  <td class="px-4 py-2.5">
                    <span class="text-[11px] px-2 py-0.5 rounded-full font-medium" :class="u.mfa_enabled ? 'bg-accent/15 text-accent' : 'bg-elevated text-disabled'">
                      {{ u.mfa_enabled ? '已启用' : '未启用' }}
                    </span>
                  </td>
                  <td class="px-4 py-2.5">
                    <div class="flex items-center justify-end gap-1">
                      <button @click="openEdit(u)" class="p-1.5 rounded-lg hover:bg-hover text-secondary hover:text-accent transition-colors" title="编辑"><Pencil class="w-4 h-4" /></button>
                      <button @click="resetPw(u)" class="p-1.5 rounded-lg hover:bg-hover text-secondary hover:text-accent transition-colors" title="重置密码"><KeyRound class="w-4 h-4" /></button>
                      <button @click="toggleStatus(u)" class="p-1.5 rounded-lg hover:bg-hover text-secondary transition-colors" :title="u.status === 'active' ? '停用账号' : '启用账号'">
                        <Ban v-if="u.status === 'active'" class="w-4 h-4 hover:text-critical" />
                        <CircleCheck v-else class="w-4 h-4 text-safe" />
                      </button>
                      <button @click="delUser(u)" class="p-1.5 rounded-lg hover:bg-hover text-secondary hover:text-critical transition-colors" title="删除"><Trash2 class="w-4 h-4" /></button>
                    </div>
                  </td>
                </tr>
                <tr v-if="!users.length && !loading"><td colspan="7" class="px-4 py-10 text-center text-muted">暂无账号，点击右上角「新建账号」创建</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 部门目录 + 角色说明 -->
        <div class="space-y-4">
          <div class="bg-surface rounded-2xl border border-border-default p-4">
            <div class="flex items-center justify-between mb-2">
              <h2 class="text-sm font-bold flex items-center gap-2"><Building2 class="w-4 h-4 text-accent" /> 部门目录</h2>
              <button @click="addDept" class="text-xs text-accent hover:underline">＋新增</button>
            </div>
            <div class="flex flex-wrap gap-1.5">
              <span v-for="d in departments" :key="d" class="text-[11px] px-2 py-1 rounded-full bg-elevated border border-border-default text-secondary">{{ d }}</span>
              <span v-if="!departments.length" class="text-xs text-muted">暂未录入部门</span>
            </div>
          </div>
          <div class="bg-surface rounded-2xl border border-border-default p-4">
            <h2 class="text-sm font-bold mb-2 flex items-center gap-2"><ShieldCheck class="w-4 h-4 text-accent" /> 角色职责（职责分离）</h2>
            <ul class="space-y-1.5 text-xs text-secondary leading-relaxed">
              <li><b class="text-medium">admin</b>：系统管理员，全部模块 + 后台管理</li>
              <li><b class="text-accent">operator</b>：安全运维，检测 / 审批 / 工具 / 运行时</li>
              <li><b class="text-accent2">auditor</b>：合规审计，看板 / 审计 / 审批查看</li>
              <li><b class="text-safe">manager</b>：部门负责人，业务 + 审批中心（可批中等风险）</li>
              <li><b class="text-secondary">user</b>：业务用户，智能问答 / 风险看板</li>
            </ul>
          </div>
        </div>
      </div>
    </main>

    <!-- 新建/编辑浮层 -->
    <div v-if="editing" class="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4" @click.self="editing = false">
      <div class="w-full max-w-md bg-surface rounded-2xl border border-border-default shadow-2xl animate-card-in">
        <div class="px-5 py-4 border-b border-border-default">
          <h3 class="font-bold">{{ isEdit ? `编辑账号 ${form.username}` : '新建账号' }}</h3>
        </div>
        <div class="p-5 space-y-3.5 text-sm">
          <template v-if="!isEdit">
            <div>
              <label class="block text-xs text-muted mb-1">用户名（登录账号，唯一）</label>
              <input v-model="form.username" placeholder="如 zhangwei" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
            </div>
            <div>
              <label class="block text-xs text-muted mb-1">初始密码（≥8 位，含大小写/数字/符号至少三类）</label>
              <input v-model="form.password" type="password" placeholder="设置初始密码" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
            </div>
          </template>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-muted mb-1">姓名</label>
              <input v-model="form.display_name" placeholder="显示姓名" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
            </div>
            <div>
              <label class="block text-xs text-muted mb-1">角色</label>
              <select v-model="form.role" class="w-full px-2 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent">
                <option v-for="r in ROLES" :key="r" :value="r">{{ ROLE_LABEL[r] }}（{{ r }}）</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">部门</label>
            <input v-model="form.department" list="dept-list" placeholder="选择或输入部门" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
            <datalist id="dept-list">
              <option v-for="d in departments" :key="d" :value="d" />
            </datalist>
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">岗位</label>
            <input v-model="form.position" placeholder="如 业务经办 / 处长" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
          </div>
          <div>
            <label class="block text-xs text-muted mb-1">备注</label>
            <input v-model="form.note" placeholder="选填" class="w-full px-3 py-2 bg-canvas border border-border-default rounded-lg text-sm focus:outline-none focus:border-accent" />
          </div>
        </div>
        <div class="px-5 py-4 border-t border-border-default flex justify-end gap-2">
          <button @click="editing = false" class="px-4 py-2 rounded-lg bg-elevated border border-border-default text-secondary text-sm">取消</button>
          <button @click="saveUser" class="px-4 py-2 rounded-lg bg-gradient-to-r from-accent to-low text-white text-sm font-medium hover:opacity-90">{{ isEdit ? '保存修改' : '创建账号' }}</button>
        </div>
      </div>
    </div>
  </div>
</template>
