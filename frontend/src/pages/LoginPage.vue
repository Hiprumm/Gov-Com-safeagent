<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ShieldCheck, LogIn, Sun, Moon } from 'lucide-vue-next'
import { useAuth } from '@/composables/useAuth'
import { useTheme } from '@/composables/useTheme'

const route = useRoute()
const router = useRouter()
const { isDark, toggleTheme } = useTheme()

const { login, demoAccounts, initAuth } = useAuth()
const username = ref('')
const password = ref('')
const submitting = ref(false)
const errorMsg = ref('')

// 首次进入拉取演示账号列表（未登录时 /me 也返回 demo_accounts）
onMounted(async () => {
  try {
    await initAuth()
  } catch { /* ignore */ }
})

const pickAccount = (u: string) => {
  username.value = u
  password.value = 'admin123' // 演示统一口令
  errorMsg.value = ''
}

const submit = async () => {
  if (!username.value.trim() || !password.value) {
    errorMsg.value = '请输入用户名和口令'
    return
  }
  submitting.value = true
  errorMsg.value = ''
  const ok = await login(username.value.trim(), password.value)
  submitting.value = false
  if (ok) {
    // 登录成功由 useAuth 内部跳转；若带 redirect 参数则回跳来源页
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : ''
    if (redirect && redirect.startsWith('/') && redirect !== '/login') {
      router.replace(redirect)
    }
  }
}
</script>

<template>
  <div class="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-canvas text-primary relative overflow-hidden">
    <!-- 主题切换 -->
    <button
      @click="toggleTheme"
      class="absolute top-5 right-5 p-2 rounded-lg bg-elevated border border-border-default text-secondary hover:text-accent hover:border-accent/40 transition-colors"
      :title="isDark ? '切换到浅色主题' : '切换到深色主题'"
    >
      <Sun v-if="isDark" class="w-5 h-5" />
      <Moon v-else class="w-5 h-5" />
    </button>

    <!-- 装饰光斑 -->
    <div class="pointer-events-none absolute -top-32 -left-32 w-96 h-96 rounded-full opacity-30 blur-3xl" style="background: radial-gradient(circle, #06B6D4, transparent 70%)"></div>
    <div class="pointer-events-none absolute -bottom-32 -right-32 w-96 h-96 rounded-full opacity-30 blur-3xl" style="background: radial-gradient(circle, #3B82F6, transparent 70%)"></div>

    <div class="w-full max-w-md relative animate-card-in">
      <!-- 品牌头 -->
      <div class="mb-6 text-center">
        <div class="w-14 h-14 mx-auto rounded-2xl flex items-center justify-center mb-3 shadow-lg"
             style="background: linear-gradient(135deg, #06B6D4 0%, #3B82F6 100%)">
          <ShieldCheck class="w-8 h-8 text-white" />
        </div>
        <h1 class="text-xl font-bold text-primary">政企大模型智能体安全平台</h1>
        <p class="text-xs text-muted mt-1">SafeAgent · 面向政企场景的安全关键技术 · 请登录后使用</p>
      </div>

      <div class="bg-surface rounded-2xl border border-border-default shadow-2xl overflow-hidden">
        <div class="px-6 py-4 border-b border-border-default flex items-center justify-between">
          <h3 class="text-lg font-bold text-primary flex items-center gap-2">
            <LogIn class="w-5 h-5 text-accent" />
            登录平台
          </h3>
        </div>

        <div class="p-6 space-y-4">
          <!-- 演示账号快捷选择 -->
          <div>
            <p class="text-xs text-muted mb-2">选择演示账号体验不同角色（口令统一 <span class="text-accent font-medium">admin123</span>）：</p>
            <div class="grid grid-cols-2 gap-1.5">
              <button
                v-for="acc in demoAccounts"
                :key="acc.username"
                @click="pickAccount(acc.username)"
                class="px-2.5 py-2 rounded-lg text-xs border transition-colors text-left"
                :class="username === acc.username
                  ? 'bg-accent/15 text-accent border-accent/50'
                  : 'bg-elevated text-secondary border-border-default hover:border-accent/40'"
                :title="acc.desc"
              >
                <span class="block font-medium truncate">{{ acc.display_name }}</span>
                <span class="text-[10px] text-disabled">{{ acc.role }} · {{ acc.desc }}</span>
              </button>
            </div>
          </div>

          <div class="h-px bg-border-default/70"></div>

          <div>
            <label class="block text-sm text-secondary mb-1.5">用户名</label>
            <input
              v-model="username"
              type="text"
              autocomplete="username"
              placeholder="admin / operator / auditor / user"
              class="w-full px-3.5 py-2.5 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            />
          </div>
          <div>
            <label class="block text-sm text-secondary mb-1.5">口令</label>
            <input
              v-model="password"
              type="password"
              autocomplete="current-password"
              placeholder="演示口令：admin123"
              @keydown.enter="submit"
              class="w-full px-3.5 py-2.5 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            />
          </div>

          <p v-if="errorMsg" class="text-sm text-critical">{{ errorMsg }}</p>

          <button
            @click="submit"
            :disabled="submitting"
            class="w-full py-2.5 rounded-xl bg-gradient-to-r from-accent to-low text-white font-medium hover:opacity-90 transition-all active:scale-[0.98] disabled:opacity-50"
          >
            {{ submitting ? '登录中...' : '登 录' }}
          </button>
          <p class="text-[11px] text-disabled text-center leading-relaxed">
            登录后导航将按角色收敛 · 审批与审计操作将记录到当前账号
          </p>
        </div>
      </div>

      <p class="text-center text-[11px] text-disabled mt-4">SafeAgent v5.0 · 面向政企场景的大模型智能体安全关键技术研究</p>
    </div>
  </div>
</template>
