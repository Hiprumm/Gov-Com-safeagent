<script setup lang="ts">
import { ref, computed } from 'vue'
import { toast } from '@/composables/useToast'

/** 与 ChatPanel.vue 中的 ThinkingStep 结构保持一致（源目均为后端 thinking 事件） */
interface ThinkingStep {
  step_id: number
  phase: string
  phase_label: string
  title: string
  detail: string
  node: string
}

const props = defineProps<{
  steps: ThinkingStep[]
  /** 是否处于实时流式"思考中"（展示进度动画，禁止复制/保存） */
  streaming?: boolean
}>()

/** 默认折叠：思考内容不主动展示，用户点击头部才展开（避免干扰正文阅读） */
const expanded = ref(false)

const count = computed(() => props.steps.length)

/** 阶段对应的强调色（复用语义色，禁止硬编码色值） */
const phaseClass = (phase: string): string => {
  switch (phase) {
    case 'analysis': return 'text-low'
    case 'decision': return 'text-accent'
    case 'plan': return 'text-safe'
    case 'logic': return 'text-medium'
    case 'retrieval': return 'text-accent'
    case 'answer': return 'text-safe'
    default: return 'text-muted'
  }
}

function fullText(): string {
  const head = '==== 思考过程 ====\n'
  const body = props.steps
    .map(s => `◉ ${s.phase_label} · ${s.title}\n　${s.detail}`)
    .join('\n')
  return head + body + '\n'
}

async function copyThinking(): Promise<void> {
  try {
    await navigator.clipboard.writeText(fullText())
    toast.success('思考过程已复制')
  } catch {
    toast.error('复制失败，请重试')
  }
}

function saveThinking(): void {
  try {
    const blob = new Blob([fullText()], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `思考过程_${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('思考过程已保存')
  } catch {
    toast.error('保存失败，请重试')
  }
}
</script>

<template>
  <div
    class="mb-2 rounded-xl border-l-2 border-accent/40 bg-surface overflow-hidden"
  >
    <!-- 折叠头部 -->
    <button
      type="button"
      class="w-full flex items-center gap-2 px-3 py-2 hover:bg-hover transition-colors"
      @click="expanded = !expanded"
    >
      <!-- 折叠箭头 -->
      <svg
        class="w-3.5 h-3.5 text-muted transition-transform duration-200"
        :class="expanded ? 'rotate-90' : ''"
        fill="none" stroke="currentColor" viewBox="0 0 24 24"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
      </svg>

      <svg class="w-4 h-4 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.071 0l-.648.648a5 5 0 01-2.828.707H9.222a5 5 0 01-2.828-.707l-.648-.648a5 5 0 010-7.071z"></path>
      </svg>

      <span class="text-sm font-medium text-secondary">思考过程</span>

      <span v-if="streaming" class="flex items-center gap-1 text-xs text-accent">
        思考中
        <span class="flex gap-0.5">
          <span class="w-1 h-1 bg-accent rounded-full animate-bounce" style="animation-delay:0ms"></span>
          <span class="w-1 h-1 bg-accent rounded-full animate-bounce" style="animation-delay:150ms"></span>
          <span class="w-1 h-1 bg-accent rounded-full animate-bounce" style="animation-delay:300ms"></span>
        </span>
      </span>
      <span v-else class="text-xs text-disabled">共 {{ count }} 步</span>

      <!-- 复制 / 保存（非流式且已有步骤时可用） -->
      <span v-if="!streaming && count" class="ml-auto flex items-center gap-1">
        <button
          type="button"
          class="p-1 rounded hover:bg-hover text-muted hover:text-accent transition-colors"
          title="复制思考过程"
          @click.stop="copyThinking"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
          </svg>
        </button>
        <button
          type="button"
          class="p-1 rounded hover:bg-hover text-muted hover:text-accent transition-colors"
          title="保存思考过程"
          @click.stop="saveThinking"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0 0l-3-3m3 3l3-3"></path>
          </svg>
        </button>
      </span>
    </button>

    <!-- 步骤列表 -->
    <div v-show="expanded" class="px-3 pb-3 pt-1 space-y-2">
      <div
        v-for="step in steps"
        :key="step.step_id"
        class="flex gap-2 animate-card-in"
        :style="{ animationDelay: (step.step_id * 40) + 'ms' }"
      >
        <div class="flex flex-col items-center pt-1">
          <span class="w-2 h-2 rounded-full border border-accent/40 bg-accent/20"></span>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <span class="text-[11px] font-medium px-1.5 py-0.5 rounded bg-elevated" :class="phaseClass(step.phase)">
              {{ step.phase_label }}
            </span>
            <span class="text-sm font-medium text-primary">{{ step.title }}</span>
          </div>
          <!-- 思考过程内文：浅色 + 斜体，与最终回复的正文样式明显区分 -->
          <p class="mt-0.5 text-xs italic leading-relaxed text-muted break-words">{{ step.detail }}</p>
        </div>
      </div>

      <p v-if="!steps.length" class="text-xs italic text-muted">
        {{ streaming ? '正在分析您的问题，请稍候…' : '本次回答没有明显的思考过程。' }}
      </p>
    </div>
  </div>
</template>