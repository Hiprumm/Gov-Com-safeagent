<script setup lang="ts">
import { useToast } from '@/composables/useToast'

const { toasts, dismiss } = useToast()

const typeConfig = {
  success: { icon: '✓', color: 'text-safe border-safe/30 bg-safe/10' },
  error:   { icon: '✕', color: 'text-critical border-critical/30 bg-critical/10' },
  warning: { icon: '!', color: 'text-medium border-medium/30 bg-medium/10' },
  info:    { icon: 'i', color: 'text-accent border-accent/30 bg-accent/10' },
}
</script>

<template>
  <Teleport to="body">
    <div class="fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      <TransitionGroup name="toast">
        <div
          v-for="toast in toasts"
          :key="toast.id"
          :class="[
            'pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-xl border backdrop-blur-md shadow-lg min-w-[280px] max-w-[400px]',
            typeConfig[toast.type].color
          ]"
        >
          <span class="text-lg font-bold flex-shrink-0">{{ typeConfig[toast.type].icon }}</span>
          <p class="text-sm text-primary flex-1">{{ toast.message }}</p>
          <button
            @click="dismiss(toast.id)"
            class="text-muted hover:text-primary text-lg leading-none flex-shrink-0"
          >
            &times;
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active {
  animation: toastIn 0.25s ease-out;
}
.toast-leave-active {
  animation: toastOut 0.2s ease-in forwards;
}
@keyframes toastIn {
  from { opacity: 0; transform: translateX(100%); }
  to { opacity: 1; transform: translateX(0); }
}
@keyframes toastOut {
  from { opacity: 1; transform: translateX(0); }
  to { opacity: 0; transform: translateX(100%); }
}
</style>
