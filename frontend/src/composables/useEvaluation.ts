/**
 * 评测生成状态 Composable（模块级单例）
 *
 * - generating 为全局共享状态：切换页面/组件重建不丢失
 * - 轮询由页面驱动（startPolling/stopPolling），完成后自动置回 false
 * - syncFromBackend：进入页面时对照后端持久化状态恢复"生成中"展示
 */
import { ref } from 'vue'
import axios from 'axios'

const generating = ref(false)

let pollTimer: ReturnType<typeof setInterval> | null = null
/** 后端 running=false 时由页面执行的回调（拉取新报告等）；返回 true 表示真正完成，可停止轮询 */
let onFinished: (() => boolean | Promise<boolean>) | null = null

/** 进入页面时对照后端状态恢复生成中展示；返回当前是否仍在生成 */
async function syncFromBackend(): Promise<boolean> {
  try {
    const { data } = await axios.get('/api/evaluation/status')
    generating.value = !!data.running
    return generating.value
  } catch {
    return generating.value
  }
}

function begin() {
  generating.value = true
}

function finish() {
  generating.value = false
}

function startPolling(finished: () => boolean | Promise<boolean>) {
  stopPolling()
  onFinished = finished
  pollTimer = setInterval(async () => {
    try {
      const { data: st } = await axios.get('/api/evaluation/status')
      if (!st.running) {
        const done = onFinished ? await onFinished() : true
        // 仅当页面确认真正完成（报告时间戳已刷新）才停止轮询
        if (done) stopPolling()
      }
    } catch { /* 轮询容错 */ }
  }, 5000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  onFinished = null
}

export function useEvaluation() {
  return { generating, syncFromBackend, begin, finish, startPolling, stopPolling }
}
