<script setup lang="ts">
/**
 * 账号安全面板：MFA（TOTP）绑定/停用 + 自助修改口令
 * 对接后端：/ai/auth/mfa/status|enroll|confirm|disable、/ai/auth/password
 */
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { X, ShieldCheck, KeyRound } from 'lucide-vue-next'
import { useToast } from '@/composables/useToast'

const emit = defineEmits<{ (e: 'close'): void }>()
const { success, error: toastError } = useToast()

const mfaEnabled = ref(false)
const mfaAvailable = ref(true)
const enroll = ref<{ secret: string; otpauth_uri: string } | null>(null)
const code = ref('')
const mfaBusy = ref(false)
const mfaMsg = ref('')

const oldPw = ref('')
const newPw = ref('')
const pwBusy = ref(false)
const pwMsg = ref('')

async function loadStatus() {
  try {
    const r = await axios.get('/ai/auth/mfa/status')
    if (r.data?.success) {
      mfaEnabled.value = !!r.data.mfa_enabled
      mfaAvailable.value = !!r.data.available
    }
  } catch { /* ignore */ }
}
onMounted(loadStatus)

async function startEnroll() {
  mfaMsg.value = ''
  mfaBusy.value = true
  try {
    const r = await axios.post('/ai/auth/mfa/enroll')
    if (r.data?.success) {
      enroll.value = { secret: r.data.secret, otpauth_uri: r.data.otpauth_uri }
    } else {
      mfaMsg.value = r.data?.message || '无法开始绑定'
    }
  } catch (e: any) {
    mfaMsg.value = e.response?.data?.detail || '操作失败'
  } finally {
    mfaBusy.value = false
  }
}

async function confirmEnroll() {
  mfaMsg.value = ''
  if (!code.value.trim()) { mfaMsg.value = '请输入认证器中的验证码'; return }
  mfaBusy.value = true
  try {
    const r = await axios.post('/ai/auth/mfa/confirm', { code: code.value.trim() })
    if (r.data?.success) {
      success('MFA 已启用')
      enroll.value = null
      code.value = ''
      await loadStatus()
    } else {
      mfaMsg.value = r.data?.message || '验证失败'
    }
  } catch (e: any) {
    mfaMsg.value = e.response?.data?.detail || '验证失败'
  } finally {
    mfaBusy.value = false
  }
}

async function disableMfa() {
  if (!window.confirm('确认停用 MFA？停用后登录将不再需要动态验证码。')) return
  mfaBusy.value = true
  try {
    await axios.post('/ai/auth/mfa/disable')
    success('MFA 已停用')
    enroll.value = null
    await loadStatus()
  } catch (e: any) {
    toastError(e.response?.data?.detail || '停用失败')
  } finally {
    mfaBusy.value = false
  }
}

async function changePw() {
  pwMsg.value = ''
  if (!oldPw.value || !newPw.value) { pwMsg.value = '请填写原口令与新口令'; return }
  pwBusy.value = true
  try {
    const r = await axios.post('/ai/auth/password', { old_password: oldPw.value, new_password: newPw.value })
    success(r.data?.message || '口令已更新')
    oldPw.value = ''
    newPw.value = ''
  } catch (e: any) {
    pwMsg.value = e.response?.data?.detail || '修改失败'
  } finally {
    pwBusy.value = false
  }
}
</script>

<template>
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" @click.self="emit('close')">
    <div class="w-full max-w-lg bg-surface rounded-2xl border border-border-default shadow-2xl overflow-hidden animate-card-in">
      <div class="px-5 py-3.5 border-b border-border-default flex items-center justify-between">
        <h3 class="text-base font-bold text-primary flex items-center gap-2">
          <ShieldCheck class="w-5 h-5 text-accent" /> 账号安全
        </h3>
        <button @click="emit('close')" class="p-1.5 rounded-lg hover:bg-hover text-muted transition-colors">
          <X class="w-4 h-4" />
        </button>
      </div>

      <div class="p-5 space-y-5 max-h-[70vh] overflow-y-auto">
        <!-- MFA -->
        <section>
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h4 class="text-sm font-semibold text-primary flex items-center gap-2">
                <ShieldCheck class="w-4 h-4 text-safe" /> 二步验证（MFA / TOTP）
              </h4>
              <p class="text-xs text-muted mt-1">
                状态：
                <span :class="mfaEnabled ? 'text-safe font-medium' : 'text-muted'">
                  {{ mfaEnabled ? '已启用' : '未启用' }}
                </span>
                <span v-if="!mfaAvailable" class="text-medium ml-2">（系统未开放）</span>
              </p>
            </div>
            <div>
              <button
                v-if="!mfaEnabled && mfaAvailable && !enroll"
                @click="startEnroll"
                :disabled="mfaBusy"
                class="px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 text-xs font-medium hover:bg-accent/20 transition-colors disabled:opacity-50"
              >
                启用 MFA
              </button>
              <button
                v-if="mfaEnabled"
                @click="disableMfa"
                :disabled="mfaBusy"
                class="px-3 py-1.5 rounded-lg bg-critical/10 text-critical border border-critical/20 text-xs font-medium hover:bg-critical/20 transition-colors disabled:opacity-50"
              >
                停用 MFA
              </button>
            </div>
          </div>

          <!-- 绑定流程 -->
          <div v-if="enroll" class="mt-3 p-3 rounded-xl bg-elevated/50 border border-border-default space-y-2">
            <p class="text-xs text-secondary">1) 在认证器 App（如 Google Authenticator / 企业微信）中手动添加密钥，或用下方 URI 生成二维码：</p>
            <div class="text-[11px] font-mono break-all bg-canvas rounded-lg p-2 border border-border-default text-primary">
              密钥：{{ enroll.secret }}
            </div>
            <div class="text-[11px] font-mono break-all bg-canvas rounded-lg p-2 border border-border-default text-muted">
              {{ enroll.otpauth_uri }}
            </div>
            <p class="text-xs text-secondary">2) 输入认证器中的 6 位动态验证码完成绑定：</p>
            <div class="flex items-center gap-2">
              <input
                v-model="code"
                type="text"
                inputmode="numeric"
                maxlength="6"
                placeholder="6 位数字"
                class="flex-1 px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm tracking-[0.2em] text-center focus:outline-none focus:border-accent"
              />
              <button
                @click="confirmEnroll"
                :disabled="mfaBusy"
                class="px-3 py-2 rounded-lg bg-gradient-to-r from-accent to-low text-white text-xs font-medium disabled:opacity-50"
              >
                确认绑定
              </button>
              <button
                @click="enroll = null; code = ''"
                class="px-3 py-2 rounded-lg bg-elevated text-secondary border border-border-default text-xs"
              >
                取消
              </button>
            </div>
          </div>
          <p v-if="mfaMsg" class="text-xs text-critical mt-2">{{ mfaMsg }}</p>
        </section>

        <div class="h-px bg-border-default"></div>

        <!-- 修改口令 -->
        <section>
          <h4 class="text-sm font-semibold text-primary flex items-center gap-2">
            <KeyRound class="w-4 h-4 text-accent" /> 修改口令
          </h4>
          <p class="text-xs text-muted mt-1">口令需至少 8 位，且包含大写/小写/数字/符号中至少三类。</p>
          <div class="mt-3 space-y-2">
            <input
              v-model="oldPw"
              type="password"
              autocomplete="current-password"
              placeholder="原口令"
              class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm focus:outline-none focus:border-accent"
            />
            <input
              v-model="newPw"
              type="password"
              autocomplete="new-password"
              placeholder="新口令"
              class="w-full px-3 py-2 bg-canvas border border-border-default text-primary placeholder:text-disabled rounded-lg text-sm focus:outline-none focus:border-accent"
            />
            <div class="flex items-center gap-2">
              <button
                @click="changePw"
                :disabled="pwBusy"
                class="px-3 py-2 rounded-lg bg-gradient-to-r from-accent to-low text-white text-xs font-medium disabled:opacity-50"
              >
                {{ pwBusy ? '提交中...' : '修改口令' }}
              </button>
              <span v-if="pwMsg" class="text-xs text-critical">{{ pwMsg }}</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
