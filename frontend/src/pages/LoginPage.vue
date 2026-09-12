<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { LogIn, Sun, Moon, ShieldCheck } from 'lucide-vue-next'
import { useAuth } from '@/composables/useAuth'
import { useTheme } from '@/composables/useTheme'

const route = useRoute()
const { isDark, toggleTheme } = useTheme()

const { login, initAuth, mfaPending, verifyMfa, cancelMfa } = useAuth()
const username = ref('')
const password = ref('')
const submitting = ref(false)
const errorMsg = ref('')
const mfaCode = ref('')
const mfaSubmitting = ref(false)

// 首次进入初始化认证状态（校验本地令牌有效性）
onMounted(async () => {
  try {
    await initAuth()
  } catch { /* ignore */ }
})

/** 登录成功后的回跳目标：带 redirect 参数（来源页）则回跳，否则回首页 */
const resolveRedirect = (): string => {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : ''
  return redirect && redirect.startsWith('/') && redirect !== '/login' ? redirect : '/'
}

const submit = async () => {
  if (!username.value.trim() || !password.value) {
    errorMsg.value = '请输入用户名和口令'
    return
  }
  submitting.value = true
  errorMsg.value = ''
  // 跳转由 useAuth 内部完成（一次性导航 + 失败硬跳转兜底），避免二次导航竞态
  await login(username.value.trim(), password.value, resolveRedirect())
  submitting.value = false
  // 若需 MFA，useAuth 会置 mfaPending，模板自动切换到二步验证
}

const submitMfa = async () => {
  if (!mfaCode.value.trim()) {
    errorMsg.value = '请输入动态验证码'
    return
  }
  mfaSubmitting.value = true
  errorMsg.value = ''
  await verifyMfa(mfaCode.value, resolveRedirect())
  mfaSubmitting.value = false
}

const backToPassword = () => {
  cancelMfa()
  mfaCode.value = ''
  errorMsg.value = ''
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
        <img
          src="/logo.png"
          alt="政企大模型智能体安全平台"
          class="w-16 h-16 mx-auto mb-3 object-contain rounded-2xl shadow-lg"
        />
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
          <template v-if="!mfaPending">
          <div>
            <label class="block text-sm text-secondary mb-1.5">用户名</label>
            <input
              v-model="username"
              type="text"
              autocomplete="username"
              placeholder="请输入用户名"
              class="w-full px-3.5 py-2.5 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
            />
          </div>
          <div>
            <label class="block text-sm text-secondary mb-1.5">口令</label>
            <input
              v-model="password"
              type="password"
              autocomplete="current-password"
              placeholder="请输入登录口令"
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

          <!-- 安全提示（真实政企场景） -->
          <div class="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-canvas border border-border-default">
            <ShieldCheck class="w-4 h-4 text-safe flex-shrink-0 mt-0.5" />
            <p class="text-[11px] text-muted leading-relaxed">
              安全提示：本系统仅限授权用户访问，登录与操作行为将被完整审计记录。请妥善保管口令，谨防钓鱼与社会工程攻击。
            </p>
          </div>

          <p class="text-[11px] text-disabled text-center">忘记口令？请联系本单位系统管理员重置</p>
          </template>

          <!-- MFA 二步验证 -->
          <template v-else>
            <div class="text-center">
              <h4 class="text-base font-bold text-primary">二步验证</h4>
              <p class="text-xs text-muted mt-1">
                账号 <span class="text-accent font-medium">{{ mfaPending?.username }}</span> 已启用 MFA，请输入认证器中的动态验证码
              </p>
            </div>
            <div>
              <label class="block text-sm text-secondary mb-1.5">动态验证码</label>
              <input
                v-model="mfaCode"
                type="text"
                inputmode="numeric"
                maxlength="6"
                placeholder="6 位数字"
                @keydown.enter="submitMfa"
                class="w-full px-3.5 py-2.5 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-xl text-sm tracking-[0.3em] text-center focus:outline-none focus:ring-2 focus:ring-accent/20 focus:border-accent"
              />
            </div>
            <p v-if="errorMsg" class="text-sm text-critical">{{ errorMsg }}</p>
            <button
              @click="submitMfa"
              :disabled="mfaSubmitting"
              class="w-full py-2.5 rounded-xl bg-gradient-to-r from-accent to-low text-white font-medium hover:opacity-90 transition-all active:scale-[0.98] disabled:opacity-50"
            >
              {{ mfaSubmitting ? '验证中...' : '验 证 并 登 录' }}
            </button>
            <button
              @click="backToPassword"
              class="w-full text-xs text-muted hover:text-accent transition-colors"
            >
              返回账号口令
            </button>
          </template>
        </div>
      </div>

      <p class="text-center text-[11px] text-disabled mt-4">© 2026 政企大模型智能体安全平台 SafeAgent · 安全审计 · 全程留痕</p>
    </div>
  </div>
</template>
