<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { useWebSocket } from '@/composables/useWebSocket'

interface Notice {
  id: number
  type: string
  title: string
  message: string
  level: string
  read: number
  created_at: string
}

const open = ref(false)
const notices = ref<Notice[]>([])
const unread = ref(0)
const { connect, onEvent } = useWebSocket()

const levelCls = (lv: string) => {
  const m: Record<string, string> = {
    critical: 'text-critical', high: 'text-high',
    medium: 'text-medium', low: 'text-low', info: 'text-accent',
  }
  return m[lv] || 'text-accent'
}
const typeIcon = (t: string) => {
  if (t === 'approval') return '🖋️'
  if (t === 'risk_alert') return '🚨'
  if (t === 'detection') return '🛡️'
  return '🔔'
}
const fmtTime = (iso: string) => {
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

const fetchAll = async () => {
  try {
    const res = await axios.get('/ai/notifications')
    notices.value = res.data.list || []
    unread.value = res.data.unread || 0
  } catch { /* ignore */ }
}

const toggle = async () => {
  open.value = !open.value
  if (open.value) {
    fetchAll()
    if (unread.value > 0) {
      try {
        const res = await axios.post('/ai/notifications/read', {})
        unread.value = res.data.unread || 0
      } catch { /* ignore */ }
    }
  }
}

const clearAll = async () => {
  try {
    await axios.post('/ai/notifications/clear')
    notices.value = []
    unread.value = 0
  } catch { /* ignore */ }
}

onMounted(() => {
  connect()
  fetchAll()
  onEvent('approval_update', fetchAll)
  onEvent('risk_alert', fetchAll)
  onEvent('detection_event', fetchAll)
  const timer = setInterval(fetchAll, 15000)
  onUnmounted(() => clearInterval(timer))
})
</script>

<template>
  <div class="relative flex-shrink-0">
    <button
      @click="toggle"
      class="p-1.5 rounded-lg hover:bg-hover transition-colors flex-shrink-0 active:scale-95 relative"
      title="通知中心"
    >
      <span class="text-base leading-none">🔔</span>
      <span
        v-if="unread > 0"
        class="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-critical text-white text-[10px] font-bold flex items-center justify-center tabular-nums"
      >{{ unread > 99 ? '99+' : unread }}</span>
    </button>

    <div
      v-if="open"
      class="absolute right-0 top-full mt-1.5 w-[340px] sm:w-[380px] bg-surface border border-border-default rounded-2xl shadow-2xl overflow-hidden animate-card-in z-50"
    >
      <div class="px-4 py-3 border-b border-border-default flex items-center justify-between">
        <div>
          <span class="text-sm font-bold text-primary">通知中心</span>
          <span v-if="unread" class="ml-2 text-[10px] px-1.5 py-0.5 rounded-full bg-critical/15 text-critical font-medium">有未读</span>
        </div>
        <button
          @click="clearAll"
          class="text-[11px] text-muted hover:text-critical transition-colors"
          title="清空全部通知"
        >清空</button>
      </div>

      <div class="max-h-[360px] overflow-y-auto">
        <div v-if="notices.length === 0" class="text-center py-10 text-muted text-sm">暂无通知</div>
        <div
          v-for="n in notices"
          :key="n.id"
          class="px-4 py-2.5 border-b border-border-default/60 hover:bg-elevated/50 transition-colors"
        >
          <div class="flex items-start gap-2">
            <span class="text-base leading-none mt-0.5">{{ typeIcon(n.type) }}</span>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-xs font-semibold text-primary truncate">{{ n.title }}</span>
                <span v-if="!n.read" class="w-1.5 h-1.5 rounded-full bg-accent flex-shrink-0"></span>
              </div>
              <p class="text-[11px] text-muted mt-0.5 break-words">{{ n.message || '—' }}</p>
              <p class="text-[10px] text-disabled mt-1 flex items-center gap-2">
                <span :class="levelCls(n.level)">●</span>{{ fmtTime(n.created_at) }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
