<script setup lang="ts">
/**
 * 个人中心：展示当前登录用户的基本信息（姓名/账号/角色/部门/职位/账号状态）、
 * 我的权限（数据范围/可见模块/权限点）、数据同步（刷新后端身份），
 * 并提供「账号安全」「退出登录」入口，符合真实政企平台个人中心场景。
 *
 * - 资料编辑：仅允许修改本人显示名（昵称），PUT /api/auth/profile 落库后经
 *   refreshProfile 同步全局身份（顶栏、后续请求），保持各模块数据一致。
 * - 我的权限：GET /api/auth/permissions（后端 RBAC/ABAC 单一事实来源），
 *   展示数据可见范围、可见模块与权限点清单。
 * - 数据同步：展示最后同步时间，可手动"刷新"重新拉取后端最新身份。
 */
import { ref, computed, onMounted } from 'vue'
import {
  X, User, Building2, Briefcase, ShieldCheck, LogOut,
  CircleCheck, CircleAlert, Pencil, Check, RotateCcw,
  KeyRound, Database, RefreshCw,
} from 'lucide-vue-next'
import axios from 'axios'
import { toast } from '@/composables/useToast'
import { useAuth } from '@/composables/useAuth'

const emit = defineEmits<{ (e: 'close'): void; (e: 'open-security'): void }>()
const { currentUser, refreshProfile, logout } = useAuth()

const roleLabel = (r?: string) =>
  ({ admin: '管理员', operator: '安全运维', auditor: '合规审计', manager: '部门负责人', user: '业务用户' } as Record<string, string>)[r || ''] || ''

/** 模块英文 key → 中文名（与后端 permission_engine.MODULES 对齐） */
const MODULE_NAMES: Record<string, string> = {
  chat: '智能问答', dashboard: '态势看板', runtime: '运行时防护', security: '安全检测',
  redteam: '红蓝对抗', tools: '安全工具', approval: '审批中心', audit: '审计分析',
  policy: '安全策略', system: '系统管理', governance: '治理中心',
}
const DATA_SCOPE_NAMES: Record<string, string> = { all: '全平台', dept: '本部门', self: '仅本人' }

const department = computed(() => currentUser.value?.department?.trim() || '未分配')
const position = computed(() => currentUser.value?.position?.trim() || '—')
const accountActive = computed(() => (currentUser.value?.status ?? 'active') === 'active')
const deptInitial = computed(() => department.value === '未分配' ? '未' : department.value.slice(0, 1))

// —— 资料编辑（仅显示名）——
const editing = ref(false)
const nameDraft = ref('')
const saving = ref(false)
function startEdit() {
  nameDraft.value = currentUser.value?.display_name || ''
  editing.value = true
}
function cancelEdit() {
  editing.value = false
  nameDraft.value = ''
}
async function saveEdit() {
  const v = nameDraft.value.trim()
  if (!v) return toast.error('显示名不能为空')
  if (v.length > 20) return toast.error('显示名长度不能超过 20 个字符')
  saving.value = true
  try {
    const res = await axios.put('/ai/auth/profile', { display_name: v })
    if (res.data?.success) {
      await refreshProfile()
      lastSync.value = new Date()
      editing.value = false
      toast.success('个人信息已更新')
    } else {
      toast.error(res.data?.detail || '保存失败')
    }
  } catch (e: any) {
    toast.error(e.response?.data?.detail || '保存失败，请稍后重试')
  } finally {
    saving.value = false
  }
}

// —— 我的权限（后端 permission_engine 单一事实来源）——
interface PermInfo {
  role?: string
  permissions?: string[]
  modules?: string[]
  data_scope?: string
  can_approve_approval?: boolean
  is_admin?: boolean
}
const permInfo = ref<PermInfo | null>(null)
const permLoading = ref(false)
async function loadPermissions() {
  permLoading.value = true
  try {
    const res = await axios.get('/ai/auth/permissions')
    permInfo.value = res.data?.success ? {
      role: res.data.role, permissions: res.data.permissions,
      modules: res.data.modules, data_scope: res.data.data_scope,
      can_approve_approval: res.data.can_approve_approval,
      is_admin: res.data.is_admin,
    } : null
  } catch {
    permInfo.value = null
  } finally {
    permLoading.value = false
  }
}

// —— 数据同步 ——
const lastSync = ref<Date | null>(null)
const syncing = ref(false)
async function doSync() {
  syncing.value = true
  try {
    const u = await refreshProfile()
    lastSync.value = new Date()
    if (u) toast.success('身份数据已同步')
    else toast.error('同步失败，请稍后重试')
  } finally {
    syncing.value = false
  }
}
const lastSyncText = computed(() => {
  if (!lastSync.value) return ''
  const d = lastSync.value
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
})

async function doLogout() {
  await logout()
}

onMounted(() => {
  loadPermissions()
  lastSync.value = new Date()
})
</script>

<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
    @click.self="emit('close')"
  >
    <div class="w-full max-w-md bg-surface rounded-2xl border border-border-default shadow-2xl overflow-hidden animate-card-in">
      <!-- 头部 -->
      <div class="px-5 py-3.5 border-b border-border-default flex items-center justify-between">
        <h3 class="text-base font-bold text-primary flex items-center gap-2">
          <User class="w-5 h-5 text-accent" /> 个人中心
        </h3>
        <button @click="emit('close')" class="p-1.5 rounded-lg hover:bg-hover text-muted transition-colors">
          <X class="w-4 h-4" />
        </button>
      </div>

      <div class="p-5 space-y-4 max-h-[78vh] overflow-y-auto">
        <!-- 身份摘要 -->
        <div class="flex items-center gap-3">
          <span
            class="w-14 h-14 rounded-full bg-gradient-to-br from-accent to-low flex items-center justify-center text-white text-xl font-bold flex-shrink-0"
          >
            {{ (currentUser?.display_name || '?').slice(0, 1) }}
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <!-- 显示名：可编辑 -->
              <template v-if="editing">
                <input
                  v-model="nameDraft"
                  maxlength="20"
                  class="w-32 px-2 py-1 text-sm rounded-lg border border-accent/50 bg-elevated/60 text-primary outline-none focus:ring-2 focus:ring-accent/30"
                  placeholder="请输入显示名"
                  @keydown.enter="saveEdit"
                  @keydown.esc="cancelEdit"
                />
                <button @click="saveEdit" :disabled="saving" class="p-1 rounded-md bg-safe/10 text-safe hover:bg-safe/20 transition-colors disabled:opacity-50">
                  <Check class="w-3.5 h-3.5" />
                </button>
                <button @click="cancelEdit" class="p-1 rounded-md bg-hover text-muted hover:bg-elevated transition-colors">
                  <X class="w-3.5 h-3.5" />
                </button>
              </template>
              <template v-else>
                <span class="text-base font-bold text-primary truncate">{{ currentUser?.display_name }}</span>
                <button @click="startEdit" class="p-1 rounded-md text-muted hover:text-accent hover:bg-accent/10 transition-colors" title="编辑显示名">
                  <Pencil class="w-3.5 h-3.5" />
                </button>
              </template>
              <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-accent/10 text-accent font-medium">{{ roleLabel(currentUser?.role) }}</span>
            </div>
            <p class="text-xs text-muted mt-0.5 font-mono">@{{ currentUser?.username }}</p>
          </div>
        </div>

        <!-- 基本信息 -->
        <div class="grid grid-cols-1 gap-2">
          <div class="flex items-center gap-3 p-3 rounded-xl bg-elevated/50 border border-border-default">
            <span class="w-9 h-9 rounded-lg bg-accent/10 text-accent flex items-center justify-center font-bold text-sm flex-shrink-0">
              {{ deptInitial }}
            </span>
            <div class="min-w-0">
              <p class="text-[10px] text-muted uppercase tracking-wide">所属部门 · Department</p>
              <p class="text-sm font-medium text-primary truncate flex items-center gap-1.5">
                <Building2 class="w-3.5 h-3.5 text-muted" /> {{ department }}
              </p>
            </div>
          </div>

          <div class="flex items-center gap-3 p-3 rounded-xl bg-elevated/50 border border-border-default">
            <span class="w-9 h-9 rounded-lg bg-safe/10 text-safe flex items-center justify-center flex-shrink-0">
              <Briefcase class="w-4 h-4" />
            </span>
            <div class="min-w-0">
              <p class="text-[10px] text-muted uppercase tracking-wide">职位 · Position</p>
              <p class="text-sm font-medium text-primary truncate flex items-center gap-1.5">
                <Briefcase class="w-3.5 h-3.5 text-muted" /> {{ position }}
              </p>
            </div>
          </div>

          <div class="flex items-center gap-3 p-3 rounded-xl bg-elevated/50 border border-border-default">
            <span
              class="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
              :class="accountActive ? 'bg-safe/10 text-safe' : 'bg-critical/10 text-critical'"
            >
              <CircleCheck v-if="accountActive" class="w-4 h-4" />
              <CircleAlert v-else class="w-4 h-4" />
            </span>
            <div class="min-w-0">
              <p class="text-[10px] text-muted uppercase tracking-wide">账号状态 · Status</p>
              <p class="text-sm font-medium flex items-center gap-1.5" :class="accountActive ? 'text-safe' : 'text-critical'">
                <CircleCheck v-if="accountActive" class="w-3.5 h-3.5" />
                <CircleAlert v-else class="w-3.5 h-3.5" />
                {{ accountActive ? '正常（已启用）' : '已停用' }}
              </p>
            </div>
          </div>
        </div>

        <!-- 我的权限 -->
        <div class="rounded-xl border border-border-default bg-elevated/30 p-3">
          <p class="text-xs font-semibold text-primary flex items-center gap-1.5 mb-2">
            <KeyRound class="w-3.5 h-3.5 text-accent" /> 我的权限
          </p>
          <div v-if="permLoading" class="text-xs text-muted py-2">权限信息加载中…</div>
          <div v-else-if="permInfo" class="space-y-2.5">
            <!-- 数据范围 -->
            <div class="flex items-center justify-between text-xs">
              <span class="text-muted">数据可见范围</span>
              <span class="font-medium text-primary">{{ DATA_SCOPE_NAMES[permInfo.data_scope || 'self'] || permInfo.data_scope }}</span>
            </div>
            <!-- 可见模块 -->
            <div>
              <p class="text-[10px] text-muted mb-1">可见模块</p>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="m in (permInfo.modules || [])"
                  :key="m"
                  class="text-[10px] px-1.5 py-0.5 rounded-md bg-accent/10 text-accent font-medium"
                >{{ MODULE_NAMES[m] || m }}</span>
              </div>
            </div>
            <!-- 权限点 -->
            <div>
              <p class="text-[10px] text-muted mb-1">权限点（{{ (permInfo.permissions || []).length }} 项）</p>
              <div class="max-h-24 overflow-y-auto pr-1 space-y-0.5">
                <span
                  v-for="p in (permInfo.permissions || [])"
                  :key="p"
                  class="inline-block text-[10px] font-mono px-1.5 py-0.5 mr-1 mb-1 rounded bg-elevated text-secondary border border-border-default"
                >{{ p }}</span>
              </div>
            </div>
          </div>
          <div v-else class="text-xs text-critical py-1">权限信息加载失败，可稍后刷新重试</div>
        </div>

        <!-- 数据同步 -->
        <div class="flex items-center justify-between gap-2 rounded-xl bg-elevated/40 border border-dashed border-border-hover px-3 py-2">
          <div class="flex items-center gap-1.5 text-xs text-muted min-w-0">
            <Database class="w-3.5 h-3.5 flex-shrink-0" />
            <span class="truncate">数据同步自后端账号体系<span v-if="lastSyncText"> · {{ lastSyncText }}</span></span>
          </div>
          <button
            @click="doSync"
            :disabled="syncing"
            class="flex items-center gap-1 text-xs font-medium text-accent hover:text-accent2 transition-colors disabled:opacity-50 flex-shrink-0"
          >
            <RefreshCw class="w-3.5 h-3.5" :class="syncing ? 'animate-spin' : ''" /> 刷新
          </button>
        </div>

        <!-- 操作 -->
        <div class="grid grid-cols-2 gap-2 pt-1">
          <button
            @click="emit('open-security')"
            class="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl bg-accent/10 text-accent border border-accent/20 text-sm font-medium hover:bg-accent/20 transition-colors active:scale-95"
          >
            <ShieldCheck class="w-4 h-4" /> 账号安全
          </button>
          <button
            @click="doLogout"
            class="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl bg-critical/10 text-critical border border-critical/20 text-sm font-medium hover:bg-critical/20 transition-colors active:scale-95"
          >
            <LogOut class="w-4 h-4" /> 退出登录
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
