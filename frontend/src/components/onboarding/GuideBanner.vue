<script setup lang="ts">
defineEmits<{ (e: 'close'): void; (e: 'goto', tab: string): void }>()

const steps = [
  { tab: 'chat', no: '1', title: '智能问答', desc: '普通咨询直接回答；攻击输入会被多层检测拦截并给出原因' },
  { tab: 'approval', no: '2', title: '高危操作走审批', desc: '导出等高危操作自动生成审批单，管理员放行后一键“重新发送”即执行' },
  { tab: 'audit', no: '3', title: '审计追溯', desc: '全过程留痕、哈希链可验；评测页可导出报告' },
]
</script>

<template>
  <div class="px-4 sm:px-6 pb-0 pt-3 flex-shrink-0">
    <div class="bg-gradient-to-r from-accent/10 to-low/10 border border-accent/20 rounded-2xl p-3.5 animate-card-in">
      <div class="flex items-start gap-3">
        <div class="text-xl leading-none mt-0.5 flex-shrink-0">🚀</div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-sm font-bold text-primary">三步快速上手</span>
            <span class="text-[10px] px-2 py-0.5 rounded-full bg-accent/10 text-accent font-medium">首次使用引导</span>
          </div>
          <div class="mt-2 grid grid-cols-1 md:grid-cols-3 gap-2">
            <button
              v-for="s in steps"
              :key="s.no"
              @click="$emit('goto', s.tab)"
              class="text-left rounded-xl bg-surface/70 border border-border-default hover:border-accent/50 p-2.5 transition-colors group"
            >
              <div class="flex items-center gap-2">
                <span class="w-5 h-5 rounded-full bg-gradient-to-br from-accent to-low text-white text-[11px] font-bold flex items-center justify-center flex-shrink-0">{{ s.no }}</span>
                <span class="text-xs font-semibold text-primary group-hover:text-accent transition-colors">{{ s.title }}</span>
              </div>
              <p class="text-[11px] text-muted mt-1.5 leading-relaxed">{{ s.desc }}</p>
            </button>
          </div>
        </div>
        <button
          @click="$emit('close')"
          class="flex-shrink-0 px-2.5 py-1.5 rounded-lg text-xs bg-elevated border border-border-default text-muted hover:text-secondary hover:border-hover transition-colors"
        >知道了，不再显示</button>
      </div>
    </div>
  </div>
</template>
