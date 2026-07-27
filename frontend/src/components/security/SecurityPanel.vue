<script setup lang="ts">
import { ref } from 'vue'
import axios from 'axios'

interface DetectionResult {
  risk_level: string
  attack_type: string | null
  confidence: number
  evidence: string
  source: string
  processed_text: string
}

interface FileDetectionResult {
  success: boolean
  detection_result?: DetectionResult
  file_info?: {
    filename: string
    file_type: string
    content_preview: string
  }
  message?: string
}

const inputText = ref('')
const detectionResults = ref<DetectionResult[]>([])
const isLoading = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const imageInput = ref<HTMLInputElement | null>(null)
const fileInfo = ref<{ filename: string; content_preview: string } | null>(null)

const detectInput = async () => {
  if (!inputText.value.trim()) return
  isLoading.value = true
  detectionResults.value = []
  fileInfo.value = null
  try {
    const response = await axios.post('/ai/security/detect_single', null, {
      params: {
        text: inputText.value,
        source: 'user_input'
      }
    })
    detectionResults.value = [response.data]
  } catch (error) {
    console.error('Detection failed:', error)
  } finally {
    isLoading.value = false
  }
}

const detectFile = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  
  if (!file || isLoading.value) {
    target.value = ''
    return
  }

  isLoading.value = true
  detectionResults.value = []
  fileInfo.value = null

  try {
    const reader = new FileReader()
    
    reader.onload = async (e) => {
      const base64Data = e.target?.result as string
      const fileData = base64Data.split(',')[1]
      
      try {
        const response = await axios.post('/ai/security/detect_file', {
          file_data: fileData,
          file_type: file.type,
          filename: file.name
        })
        
        const result: FileDetectionResult = response.data
        
        if (result.success && result.detection_result) {
          detectionResults.value = [result.detection_result]
          fileInfo.value = {
            filename: result.file_info?.filename || file.name,
            content_preview: result.file_info?.content_preview || ''
          }
        } else {
          console.error('File detection failed:', result.message)
        }
      } catch (error) {
        console.error('File detection failed:', error)
      } finally {
        isLoading.value = false
      }
    }
    
    reader.readAsDataURL(file)
  } catch (error) {
    console.error('File reading failed:', error)
    isLoading.value = false
  }
  
  target.value = ''
}

const detectImage = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  
  if (!file || isLoading.value || !file.type.startsWith('image/')) {
    target.value = ''
    return
  }

  isLoading.value = true
  detectionResults.value = []
  fileInfo.value = null

  try {
    const reader = new FileReader()
    
    reader.onload = async (e) => {
      const base64Data = e.target?.result as string
      const fileData = base64Data.split(',')[1]
      
      try {
        const response = await axios.post('/ai/security/detect_file', {
          file_data: fileData,
          file_type: file.type,
          filename: file.name
        })
        
        const result: FileDetectionResult = response.data
        
        if (result.success && result.detection_result) {
          detectionResults.value = [result.detection_result]
          fileInfo.value = {
            filename: result.file_info?.filename || file.name,
            content_preview: result.file_info?.content_preview || '图片内容'
          }
        } else {
          console.error('Image detection failed:', result.message)
        }
      } catch (error) {
        console.error('Image detection failed:', error)
      } finally {
        isLoading.value = false
      }
    }
    
    reader.readAsDataURL(file)
  } catch (error) {
    console.error('Image reading failed:', error)
    isLoading.value = false
  }
  
  target.value = ''
}

const getRiskColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'bg-red-50 border-red-200'
    case 'medium':
      return 'bg-yellow-50 border-yellow-200'
    case 'low':
      return 'bg-blue-50 border-blue-200'
    default:
      return 'bg-green-50 border-green-200'
  }
}

const getRiskBadgeColor = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
    case 'critical':
      return 'bg-red-100 text-red-700'
    case 'medium':
      return 'bg-yellow-100 text-yellow-700'
    case 'low':
      return 'bg-blue-100 text-blue-700'
    default:
      return 'bg-green-100 text-green-700'
  }
}

const getRiskText = (riskLevel: string) => {
  switch (riskLevel) {
    case 'high':
      return '高风险'
    case 'critical':
      return '严重风险'
    case 'medium':
      return '中风险'
    case 'low':
      return '低风险'
    default:
      return '安全'
  }
}

const exampleInputs = [
  { text: 'rm -rf /', desc: '命令注入攻击' },
  { text: 'SELECT * FROM users WHERE password=1 OR 1=1', desc: 'SQL注入攻击' },
  { text: '你好，请问今天天气怎么样？', desc: '正常对话' },
  { text: '&lt;script&gt;alert("XSS")&lt;/script&gt;', desc: 'XSS攻击' },
]

const loadExample = (text: string) => {
  inputText.value = text
}
</script>

<template>
  <div class="h-full">
    <h2 class="text-xl font-bold text-gray-900 mb-4">输入安全检测</h2>
    
    <!-- 上传检测 -->
    <div class="bg-gray-50 rounded-xl p-4 mb-6">
      <label class="block text-sm font-medium text-gray-700 mb-2">上传文件检测</label>
      <div class="flex gap-3 mb-4">
        <button
          @click="fileInput?.click()"
          :disabled="isLoading"
          class="flex-1 flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-gray-300 rounded-xl hover:border-blue-500 hover:bg-blue-50 transition-all duration-200 disabled:opacity-50"
        >
          <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
          </svg>
          <span class="text-sm text-gray-600">上传文件 (.txt, .json, .md)</span>
        </button>
        <button
          @click="imageInput?.click()"
          :disabled="isLoading"
          class="flex-1 flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-gray-300 rounded-xl hover:border-blue-500 hover:bg-blue-50 transition-all duration-200 disabled:opacity-50"
        >
          <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
          </svg>
          <span class="text-sm text-gray-600">上传图片</span>
        </button>
      </div>
      <div v-if="fileInfo" class="bg-white border border-gray-200 rounded-lg p-3">
        <div class="flex items-center gap-2 mb-2">
          <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
          </svg>
          <span class="font-medium text-gray-800">{{ fileInfo.filename }}</span>
        </div>
        <p class="text-sm text-gray-600">{{ fileInfo.content_preview }}</p>
      </div>
    </div>
    
    <!-- 文本检测 -->
    <div class="bg-gray-50 rounded-xl p-4 mb-6">
      <label class="block text-sm font-medium text-gray-700 mb-2">待检测文本</label>
      <textarea
        v-model="inputText"
        placeholder="请输入需要检测的文本..."
        class="w-full px-4 py-3 border border-gray-200 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        rows="4"
      ></textarea>
      <div class="flex flex-wrap gap-2 mt-3">
        <span class="text-xs text-gray-500">示例：</span>
        <button
          v-for="example in exampleInputs"
          :key="example.text"
          @click="loadExample(example.text)"
          class="px-3 py-1 text-xs bg-white border border-gray-200 rounded-full hover:bg-blue-50 hover:text-blue-600 transition-colors"
          :title="example.desc"
        >
          {{ example.desc }}
        </button>
      </div>
      <button
        @click="detectInput"
        :disabled="isLoading || !inputText.trim()"
        :class="[
          'mt-4 px-6 py-2 rounded-xl font-medium transition-all duration-200',
          isLoading || !inputText.trim()
            ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
            : 'bg-blue-600 text-white hover:bg-blue-700'
        ]"
      >
        <span v-if="isLoading">检测中...</span>
        <span v-else>开始检测</span>
      </button>
    </div>
    <div v-if="detectionResults.length > 0" class="space-y-4">
      <h3 class="text-lg font-semibold text-gray-800">检测结果</h3>
      <div
        v-for="(result, index) in detectionResults"
        :key="index"
        :class="['p-4 rounded-xl border', getRiskColor(result.risk_level)]"
      >
        <div class="flex items-center justify-between mb-3">
          <span class="font-medium text-gray-800">检测项 {{ index + 1 }}</span>
          <span :class="['px-3 py-1 rounded-full text-sm font-medium', getRiskBadgeColor(result.risk_level)]">
            {{ getRiskText(result.risk_level) }}
          </span>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="text-xs text-gray-500">攻击类型</label>
            <p class="text-sm font-medium">{{ result.attack_type || '无' }}</p>
          </div>
          <div>
            <label class="text-xs text-gray-500">置信度</label>
            <p class="text-sm font-medium">{{ (result.confidence * 100).toFixed(0) }}%</p>
          </div>
          <div>
            <label class="text-xs text-gray-500">来源</label>
            <p class="text-sm font-medium">{{ result.source }}</p>
          </div>
          <div>
            <label class="text-xs text-gray-500">处理后文本</label>
            <p class="text-sm font-medium">{{ result.processed_text }}</p>
          </div>
        </div>
        <div v-if="result.evidence" class="mt-4">
          <label class="text-xs text-gray-500">风险证据</label>
          <p class="text-sm text-gray-700 bg-white p-2 rounded-lg">{{ result.evidence }}</p>
        </div>
      </div>
    </div>
    <div v-else class="text-center py-12">
      <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
        <svg class="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
        </svg>
      </div>
      <p class="text-gray-500">输入文本或上传文件/图片，点击检测按钮查看安全检测结果</p>
    </div>
    
    <!-- 隐藏的文件输入 -->
    <input
      ref="fileInput"
      type="file"
      class="hidden"
      accept=".txt,.json,.md"
      @change="detectFile"
    />
    <input
      ref="imageInput"
      type="file"
      class="hidden"
      accept="image/*"
      @change="detectImage"
    />
  </div>
</template>