<script setup lang="ts">
/**
 * P1-2 导航收敛：系统状态 + 运维监控 合并为单一导航入口「系统与运维」
 * - 系统状态（自检 / 数据维护 / 模型接入 / 安全策略摘要）与运维监控（性能 / 可用性）
 *   信息有交叉（服务健康、运行状态），合并后可减少一个 Tab，降低导航密度。
 * - 两个子面板保持独立组件、独立数据源，仅在此处聚合展示。
 */
import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'
import OpsMetricsPanel from '@/components/ops/OpsMetricsPanel.vue'
</script>

<template>
  <div class="space-y-6">
    <SystemStatusPanel />
    <div class="border-t border-border-default pt-4">
      <OpsMetricsPanel />
    </div>
  </div>
</template>
