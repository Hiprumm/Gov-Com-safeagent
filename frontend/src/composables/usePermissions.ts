/**
 * 统一权限 Composable —— 消费后端权限引擎（/ai/auth/permissions）
 *
 * 单一事实来源：可见模块（导航收敛）、权限点、数据可见范围、审批能力均由后端判定，
 * 前端不再各自硬编码"角色→菜单"，避免与后端权限漂移。
 * 拉取失败/未登录时安全回退（modules 为空时由调用方回退到本地默认，保证可用性）。
 */
import { ref, computed } from 'vue'
import axios from 'axios'

const permissions = ref<string[]>([])
const modules = ref<string[]>([])
const dataScope = ref<string>('')          // all | dept | self
const canApproveApproval = ref<boolean>(false)
const isAdmin = ref<boolean>(false)
const loaded = ref<boolean>(false)
const loading = ref<boolean>(false)

async function fetchPermissions(): Promise<void> {
  loading.value = true
  try {
    const res = await axios.get('/ai/auth/permissions')
    if (res.data?.success) {
      permissions.value = res.data.permissions || []
      modules.value = res.data.modules || []
      dataScope.value = res.data.data_scope || ''
      canApproveApproval.value = !!res.data.can_approve_approval
      isAdmin.value = !!res.data.is_admin
      loaded.value = true
    }
  } catch {
    // 未登录/失效：清空，交由路由守卫与调用方回退处理
    resetPermissions()
  } finally {
    loading.value = false
  }
}

function resetPermissions() {
  permissions.value = []
  modules.value = []
  dataScope.value = ''
  canApproveApproval.value = false
  isAdmin.value = false
  loaded.value = false
}

/** 是否拥有某权限点，如 security.detect / approval.approve / admin.manage */
function can(perm: string): boolean {
  if (!loaded.value) return false
  return permissions.value.includes(perm)
}

/** 是否可见某模块（导航收敛）；未加载时返回 false，由调用方决定回退策略 */
function hasModule(name: string): boolean {
  return modules.value.includes(name)
}

export function usePermissions() {
  return {
    permissions,
    modules,
    dataScope,
    canApproveApproval,
    isAdmin,
    loaded,
    loading,
    fetchPermissions,
    resetPermissions,
    can,
    hasModule,
    moduleSet: computed(() => new Set(modules.value)),
  }
}
