/**
 * WebSocket 连接管理 Composable
 *
 * 用法:
 *   const { connect, disconnect, subscribe, onEvent, connectionStatus } = useWebSocket()
 *
 *   onEvent('approval_update', (data) => { ... })
 *   onEvent('risk_alert', (data) => { ... })
 *
 *   // 自动连接
 *   connect()
 *   // 手动断开
 *   disconnect()
 */

import { ref, onUnmounted } from 'vue'

export type WsEventType = 'approval_update' | 'risk_alert' | 'detection_event' | 'system' | 'pong'

export interface WsEvent {
  type: WsEventType | string
  timestamp: string
  data: Record<string, any>
}

export function useWebSocket() {
  const ws = ref<WebSocket | null>(null)
  const connectionStatus = ref<'disconnected' | 'connecting' | 'connected'>('disconnected')
  const reconnectAttempts = ref(0)
  const maxReconnectAttempts = 5
  const reconnectDelay = 2000  // ms

  const listeners = new Map<string, Set<(data: Record<string, any>) => void>>()
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let heartbeatTimer: ReturnType<typeof setInterval> | null = null

  /**
   * 获取当前 WebSocket URL
   */
  function getWsUrl(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    return `${protocol}//${host}/ws/events`
  }

  /**
   * 发送 JSON 消息
   */
  function send(data: Record<string, any>) {
    if (ws.value?.readyState === WebSocket.OPEN) {
      ws.value.send(JSON.stringify(data))
    }
  }

  /**
   * 订阅频道
   */
  function subscribe(channel: string) {
    send({ action: 'subscribe', channel })
  }

  /**
   * 取消订阅频道
   */
  function unsubscribe(channel: string) {
    send({ action: 'unsubscribe', channel })
  }

  /**
   * 注册事件监听
   */
  function onEvent(eventType: string, callback: (data: Record<string, any>) => void) {
    if (!listeners.has(eventType)) {
      listeners.set(eventType, new Set())
    }
    listeners.get(eventType)!.add(callback)

    // 返回取消监听函数
    return () => {
      listeners.get(eventType)?.delete(callback)
    }
  }

  /**
   * 触发事件监听器
   */
  function emit(eventType: string, data: Record<string, any>) {
    listeners.get(eventType)?.forEach(cb => {
      try { cb(data) } catch (e) { console.warn('[WS] Listener error:', e) }
    })
  }

  /**
   * 建立 WebSocket 连接
   */
  function connect() {
    if (ws.value?.readyState === WebSocket.OPEN || ws.value?.readyState === WebSocket.CONNECTING) {
      return
    }

    connectionStatus.value = 'connecting'
    const url = getWsUrl()

    try {
      const socket = new WebSocket(url)
      ws.value = socket

      socket.onopen = () => {
        console.log('[WS] Connected:', url)
        connectionStatus.value = 'connected'
        reconnectAttempts.value = 0

        // 启动心跳（每30秒）
        heartbeatTimer = setInterval(() => {
          send({ action: 'ping' })
        }, 30000)
      }

      socket.onmessage = (event) => {
        try {
          const msg: WsEvent = JSON.parse(event.data)
          emit(msg.type, msg.data || {})
          // 同时触发通用的 'message' 事件
          emit('message', msg)
        } catch (e) {
          console.warn('[WS] Failed to parse message:', e)
        }
      }

      socket.onerror = (error) => {
        console.warn('[WS] Error:', error)
      }

      socket.onclose = (event) => {
        console.log('[WS] Disconnected:', event.code, event.reason)
        connectionStatus.value = 'disconnected'
        ws.value = null

        // 停止心跳
        if (heartbeatTimer) {
          clearInterval(heartbeatTimer)
          heartbeatTimer = null
        }

        // 自动重连
        if (reconnectAttempts.value < maxReconnectAttempts && event.code !== 1000) {
          reconnectAttempts.value++
          console.log(`[WS] Reconnecting in ${reconnectDelay}ms (attempt ${reconnectAttempts.value}/${maxReconnectAttempts})...`)
          reconnectTimer = setTimeout(() => {
            connect()
          }, reconnectDelay)
        }
      }
    } catch (e) {
      console.warn('[WS] Connection failed:', e)
      connectionStatus.value = 'disconnected'
    }
  }

  /**
   * 断开 WebSocket 连接
   */
  function disconnect() {
    // 停止重连
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    // 停止心跳
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }

    if (ws.value) {
      ws.value.close(1000, 'User disconnected')
      ws.value = null
    }
    connectionStatus.value = 'disconnected'
    reconnectAttempts.value = maxReconnectAttempts // 阻止自动重连
  }

  // 组件卸载时自动断开
  onUnmounted(() => {
    disconnect()
  })

  return {
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    onEvent,
    send,
    connectionStatus,
  }
}
