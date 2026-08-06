<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'

// ======== 全局 axios 拦截器 ========
axios.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('x_api_key') || ''
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }
  return config
})

axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const msg = error.response?.status === 401
      ? '认证失败,请在设置中配置 API Key'
      : error.response?.status === 429
      ? '请求过于频繁,请稍后再试'
      : error.response?.data?.detail || error.message || '网络错误'
    console.error(`[${error.response?.status || 'NET'}] ${msg}`)
    return Promise.reject(error)
  }
)

interface Message {
  id: number
  content: string
  role: 'user' | 'assistant'
  timestamp: Date
  riskLevel?: string
  type?: 'text' | 'image' | 'file'
  fileName?: string
  imageUrl?: string
}

// 对齐 SQLite 返回格式
interface SessionItem {
  session_id: string
  title: string | null
  created_at: string
  updated_at: string
  message_count: number
}

const messages = ref<Message[]>([
  {
    id: 1,
    content: '您好！我是面向政企场景的大模型智能体安全平台。\n\n发送消息即可开始体验安全检测流程，您的每条输入都会经过多层安全引擎扫描。',
    role: 'assistant',
    timestamp: new Date(),
    riskLevel: 'none',
    type: 'text'
  }
])

const inputMessage = ref('')
const isLoading = ref(false)
const messageIdCounter = ref(2)
const sessionId = ref<string | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
const imageInput = ref<HTMLInputElement | null>(null)
const sessions = ref<SessionItem[]>([])
const isLoadingSessions = ref(false)
const showSessionSidebar = ref(false)

const createNewSession = async () => {
  try {
    const response = await axios.post('/ai/agent/new_session')
    sessionId.value = response.data.session_id
    messages.value = [
      {
        id: messageIdCounter.value++,
        content: '新会话已创建。请问有什么可以帮助您的？',
        role: 'assistant',
        timestamp: new Date(),
        riskLevel: 'none',
        type: 'text'
      }
    ]
  } catch (error) {
    console.error('Failed to create session:', error)
  }
}

const sendMessage = async () => {
  if (!inputMessage.value.trim() || isLoading.value) return

  const userMessage: Message = {
    id: messageIdCounter.value++,
    content: inputMessage.value,
    role: 'user',
    timestamp: new Date(),
    type: 'text'
  }
  messages.value.push(userMessage)
  inputMessage.value = ''
  isLoading.value = true

  try {
    const response = await axios.post('/ai/agent/chat', null, {
      params: {
        user_input: userMessage.content,
        input_source: 'user_input',
        session_id: sessionId.value
      }
    })

    const result = response.data
    sessionId.value = result.session_id

    const assistantMessage: Message = {
      id: messageIdCounter.value++,
      content: result.final_response || '抱歉，无法处理您的请求',
      role: 'assistant',
      timestamp: new Date(),
      riskLevel: result.risk_level,
      type: 'text'
    }
    messages.value.push(assistantMessage)
  } catch (error) {
    const errorMessage: Message = {
      id: messageIdCounter.value++,
      content: '网络错误，请稍后重试',
      role: 'assistant',
      timestamp: new Date(),
      riskLevel: 'error',
      type: 'text'
    }
    messages.value.push(errorMessage)
  } finally {
    isLoading.value = false
  }
}

const handleFileUpload = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  
  if (!file || isLoading.value) {
    target.value = ''
    return
  }

  isLoading.value = true

  try {
    const reader = new FileReader()
    
    reader.onload = async (e) => {
      const base64Data = e.target?.result as string
      const fileData = base64Data.split(',')[1]
      
      const userMessage: Message = {
        id: messageIdCounter.value++,
        content: `[文件上传] ${file.name}`,
        role: 'user',
        timestamp: new Date(),
        type: 'file',
        fileName: file.name
      }
      messages.value.push(userMessage)

      try {
        const response = await axios.post('/ai/agent/file_upload', {
          file_data: fileData,
          file_type: file.type,
          filename: file.name,
          session_id: sessionId.value
        })

        const result = response.data
        sessionId.value = result.session_id

        const assistantMessage: Message = {
          id: messageIdCounter.value++,
          content: result.final_response || result.message || '文件处理完成',
          role: 'assistant',
          timestamp: new Date(),
          riskLevel: result.risk_level,
          type: 'text'
        }
        messages.value.push(assistantMessage)
      } catch (error) {
        const errorMessage: Message = {
          id: messageIdCounter.value++,
          content: '文件上传失败，请稍后重试',
          role: 'assistant',
          timestamp: new Date(),
          riskLevel: 'error',
          type: 'text'
        }
        messages.value.push(errorMessage)
      } finally {
        isLoading.value = false
      }
    }

    reader.readAsDataURL(file)
  } catch (error) {
    console.error('File upload failed:', error)
    isLoading.value = false
  }

  target.value = ''
}

const handleImageUpload = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  
  if (!file || isLoading.value || !file.type.startsWith('image/')) {
    target.value = ''
    return
  }

  isLoading.value = true

  try {
    const reader = new FileReader()
    
    reader.onload = async (e) => {
      const base64Data = e.target?.result as string
      const fileData = base64Data.split(',')[1]
      
      const userMessage: Message = {
        id: messageIdCounter.value++,
        content: `[图片上传] ${file.name}`,
        role: 'user',
        timestamp: new Date(),
        type: 'image',
        fileName: file.name,
        imageUrl: base64Data
      }
      messages.value.push(userMessage)

      try {
        const response = await axios.post('/ai/agent/file_upload', {
          file_data: fileData,
          file_type: file.type,
          filename: file.name,
          session_id: sessionId.value
        })

        const result = response.data
        sessionId.value = result.session_id

        const assistantMessage: Message = {
          id: messageIdCounter.value++,
          content: result.final_response || result.message || '图片识别完成',
          role: 'assistant',
          timestamp: new Date(),
          riskLevel: result.risk_level,
          type: 'text'
        }
        messages.value.push(assistantMessage)
      } catch (error) {
        const errorMessage: Message = {
          id: messageIdCounter.value++,
          content: '图片上传失败，请稍后重试',
          role: 'assistant',
          timestamp: new Date(),
          riskLevel: 'error',
          type: 'text'
        }
        messages.value.push(errorMessage)
      } finally {
        isLoading.value = false
      }
    }

    reader.readAsDataURL(file)
  } catch (error) {
    console.error('Image upload failed:', error)
    isLoading.value = false
  }

  target.value = ''
}

const getRiskLevelColor = (riskLevel?: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'bg-red-100 text-red-700'
    case 'medium':
      return 'bg-yellow-100 text-yellow-700'
    case 'low':
      return 'bg-blue-100 text-blue-700'
    case 'error':
      return 'bg-gray-100 text-gray-700'
    default:
      return 'bg-green-100 text-green-700'
  }
}

const getRiskLevelText = (riskLevel?: string) => {
  switch (riskLevel) {
    case 'high':
      return '高风险'
    case 'critical':
      return '严重风险'
    case 'medium':
      return '中风险'
    case 'low':
      return '低风险'
    case 'error':
      return '错误'
    default:
      return '安全'
  }
}

const clearChat = () => {
  createNewSession()
}

const loadSessions = async () => {
  isLoadingSessions.value = true
  try {
    const response = await axios.get('/ai/agent/sessions')
    sessions.value = response.data.sessions || []
  } catch (error) {
    console.error('Failed to load sessions:', error)
  } finally {
    isLoadingSessions.value = false
  }
}

const switchSession = async (sessionItem: SessionItem) => {
  isLoading.value = true
  showSessionSidebar.value = false
  try {
    const response = await axios.get('/ai/agent/history', {
      params: {
        session_id: sessionItem.session_id
      }
    })
    
    const history = response.data.messages || []
    sessionId.value = sessionItem.session_id
    messageIdCounter.value = history.length + 1
    
    messages.value = history.map((msg: any, index: number) => ({
      id: index + 1,
      content: msg.content,
      role: msg.role === 'user' ? 'user' : 'assistant',
      timestamp: new Date(msg.timestamp || Date.now()),
      type: msg.type || 'text',
      fileName: msg.fileName,
      imageUrl: msg.imageUrl
    }))
    
    if (messages.value.length === 0) {
      messages.value = [{
        id: 1,
        content: '会话已创建。请问有什么可以帮助您的？',
        role: 'assistant',
        timestamp: new Date(),
        riskLevel: 'none',
        type: 'text'
      }]
    }
  } catch (error) {
    console.error('Failed to switch session:', error)
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  // 不在加载时自动创建会话，首次发送消息时才创建
})
</script>

<template>
  <div class="h-full flex">
    <!-- 会话列表侧边栏 -->
    <div
      v-if="showSessionSidebar"
      class="w-72 bg-white border-r border-gray-200 flex flex-col"
    >
      <div class="p-4 border-b border-gray-100 flex items-center justify-between">
        <h3 class="font-semibold text-gray-800">历史会话</h3>
        <button
          @click="showSessionSidebar = false"
          class="p-1 hover:bg-gray-100 rounded-lg transition-colors"
        >
          <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
          </svg>
        </button>
      </div>
      <div class="flex-1 overflow-y-auto p-2">
        <button
          @click="createNewSession(); showSessionSidebar = false"
          class="w-full p-3 mb-2 text-left bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 transition-colors flex items-center gap-2"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
          </svg>
          <span class="font-medium">新建会话</span>
        </button>
        <div v-if="isLoadingSessions" class="text-center py-8">
          <div class="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
        </div>
        <div v-else-if="sessions.length === 0" class="text-center py-8 text-gray-500">
          暂无历史会话
        </div>
        <div v-else class="space-y-1">
          <button
            v-for="session in sessions"
            :key="session.session_id"
            @click="switchSession(session)"
            :class="[
              'w-full p-3 text-left rounded-lg transition-colors',
              sessionId === session.session_id
                ? 'bg-blue-100 border border-blue-200'
                : 'hover:bg-gray-50 border border-transparent'
            ]"
          >
            <div class="font-medium text-gray-800 text-sm truncate">
              {{ session.title || '会话 ' + session.session_id.slice(0, 8) }}
            </div>
            <div class="text-xs text-gray-500 mt-1">
              {{ session.message_count }} 条消息
            </div>
            <div class="flex items-center justify-between mt-2">
              <span class="text-xs text-gray-400">
                {{ session.updated_at ? session.updated_at.slice(0, 10) : '' }}
              </span>
              <span class="text-xs text-gray-400">
                {{ session.updated_at ? session.updated_at.slice(11, 16) : '' }}
              </span>
            </div>
          </button>
        </div>
      </div>
    </div>

    <!-- 主聊天区域 -->
    <div class="flex-1 flex flex-col">
      <!-- 聊天区域 -->
      <div class="flex-1 overflow-y-auto space-y-4 p-4 bg-gray-50 rounded-lg mb-4">
      <div
        v-for="message in messages"
        :key="message.id"
        :class="[
          'flex gap-3',
          message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
        ]"
      >
        <div
          :class="[
            'w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center text-white font-bold',
            message.role === 'user' ? 'bg-blue-600' : 'bg-indigo-600'
          ]"
        >
          {{ message.role === 'user' ? '用' : '智' }}
        </div>
        
        <div :class="['max-w-[70%]', message.role === 'user' ? 'text-right' : 'text-left']">
          <!-- 图片消息 -->
          <div
            v-if="message.type === 'image' && message.imageUrl"
            :class="[
              'px-4 py-3 rounded-xl shadow-sm',
              message.role === 'user'
                ? 'bg-blue-600 rounded-tr-sm'
                : 'bg-white rounded-tl-sm border border-gray-100'
            ]"
          >
            <img :src="message.imageUrl" alt="上传的图片" class="max-w-full rounded-lg" />
            <p class="text-xs mt-2" :class="message.role === 'user' ? 'text-blue-200' : 'text-gray-500'">
              {{ message.fileName }}
            </p>
          </div>
          
          <!-- 文件消息 -->
          <div
            v-else-if="message.type === 'file'"
            :class="[
              'px-4 py-3 rounded-xl shadow-sm',
              message.role === 'user'
                ? 'bg-blue-600 rounded-tr-sm'
                : 'bg-white rounded-tl-sm border border-gray-100'
            ]"
          >
            <div class="flex items-center gap-2">
              <svg class="w-6 h-6" :class="message.role === 'user' ? 'text-blue-200' : 'text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
              <span :class="message.role === 'user' ? 'text-white' : 'text-gray-800'">{{ message.fileName }}</span>
            </div>
          </div>
          
          <!-- 文本消息 -->
          <div
            v-else
            :class="[
              'px-4 py-3 rounded-xl shadow-sm',
              message.role === 'user'
                ? 'bg-blue-600 text-white rounded-tr-sm'
                : 'bg-white text-gray-800 rounded-tl-sm border border-gray-100'
            ]"
          >
            <p class="whitespace-pre-wrap break-words">{{ message.content }}</p>
          </div>
          
          <!-- 风险标签 -->
          <div class="flex items-center gap-2 mt-1" :class="message.role === 'user' ? 'justify-end' : 'justify-start'">
            <span
              v-if="message.riskLevel"
              :class="[
                'px-2 py-0.5 rounded-full text-xs font-medium',
                getRiskLevelColor(message.riskLevel)
              ]"
            >
              {{ getRiskLevelText(message.riskLevel) }}
            </span>
            <span class="text-xs text-gray-400">
              {{ new Date(message.timestamp).toLocaleTimeString() }}
            </span>
          </div>
        </div>
      </div>

      <!-- 加载状态 -->
      <div v-if="isLoading" class="flex gap-3">
        <div class="w-10 h-10 rounded-full bg-indigo-600 flex-shrink-0 flex items-center justify-center text-white font-bold">
          智
        </div>
        <div class="bg-white px-4 py-3 rounded-xl rounded-tl-sm border border-gray-100">
          <div class="flex gap-1">
            <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0ms"></span>
            <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 150ms"></span>
            <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 300ms"></span>
          </div>
        </div>
      </div>
    </div>

    <!-- 工具栏 -->
    <div class="bg-white border-t border-gray-100 p-4">
      <!-- 功能按钮 -->
      <div class="flex items-center gap-2 mb-3">
        <button
          @click="showSessionSidebar = !showSessionSidebar; loadSessions()"
          :disabled="isLoading"
          class="p-2 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50"
          title="历史会话"
        >
          <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
          </svg>
        </button>
        <button
          @click="imageInput?.click()"
          :disabled="isLoading"
          class="p-2 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50"
          title="上传图片"
        >
          <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
          </svg>
        </button>
        <button
          @click="fileInput?.click()"
          :disabled="isLoading"
          class="p-2 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50"
          title="上传文件"
        >
          <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
          </svg>
        </button>
        <button
          @click="clearChat"
          :disabled="isLoading"
          class="p-2 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50"
          title="清空对话"
        >
          <svg class="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
          </svg>
        </button>
        <span v-if="sessionId" class="ml-auto text-xs text-gray-400">
          会话ID: {{ sessionId.slice(0, 8) }}...
        </span>
      </div>
      
      <!-- 输入框 -->
      <div class="flex gap-3">
        <textarea
          v-model="inputMessage"
          @keydown.enter.exact.prevent="sendMessage"
          placeholder="请输入您的问题..."
          class="flex-1 px-4 py-3 border border-gray-200 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows="2"
          :disabled="isLoading"
        ></textarea>
        <button
          @click="sendMessage"
          :disabled="isLoading || !inputMessage.trim()"
          :class="[
            'px-6 py-3 rounded-xl font-medium transition-all duration-200 flex-shrink-0',
            isLoading || !inputMessage.trim()
              ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700 shadow-md hover:shadow-lg'
          ]"
        >
          <span v-if="isLoading">发送中...</span>
          <span v-else>发送</span>
        </button>
      </div>
      <p class="text-xs text-gray-400 mt-2">按 Enter 键发送，Shift + Enter 换行 | 支持图片和文件上传</p>
    </div>

    <!-- 隐藏的文件输入 -->
    <input
      ref="fileInput"
      type="file"
      class="hidden"
      accept=".txt,.json,.md"
      @change="handleFileUpload"
    />
    <input
      ref="imageInput"
      type="file"
      class="hidden"
      accept="image/*"
      @change="handleImageUpload"
    />
    </div> <!-- 主聊天区域结束 -->
  </div> <!-- 主容器结束 -->
</template>