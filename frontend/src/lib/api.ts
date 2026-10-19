// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – API client & query functions
// ──────────────────────────────────────────────────────────────────────────────
import axios from 'axios'
import { getToken, clearToken } from './auth'
import type {
  TokenResponse,
  DashboardStats,
  TimelineEntry,
  HistogramEntry,
  EmailSummary,
  EmailDetail,
  LogEntry,
  ModelMetrics,
  Key,
  KeyGenerateResponse,
  KeyType,
  ThresholdConfig,
  SimulationResult,
  SimulationScenario,
} from '../types'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

api.interceptors.request.use((config) => {
  const token = getToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      clearToken()
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

// ── Auth ──────────────────────────────────────────────────────────────────────
export async function login(email: string, password: string): Promise<TokenResponse> {
  const res = await api.post<TokenResponse>('/auth/login', { email, password })
  return res.data
}

export async function getCurrentUser(): Promise<any> {
  const res = await api.get('/auth/me')
  return res.data
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export async function getDashboardStats(): Promise<DashboardStats> {
  const res = await api.get<DashboardStats>('/dashboard/stats')
  return res.data
}

export async function getTimeline(days = 7): Promise<TimelineEntry[]> {
  const res = await api.get<TimelineEntry[]>('/dashboard/timeline', { params: { days } })
  return res.data
}

export async function getRiskHistogram(): Promise<HistogramEntry[]> {
  const res = await api.get<HistogramEntry[]>('/dashboard/risk-histogram')
  return res.data
}

// ── Emails ────────────────────────────────────────────────────────────────────
export interface GetEmailsParams {
  search?: string
  verdict?: string
  skip?: number
  limit?: number
  quarantine?: boolean
  is_simulation?: boolean
}

export async function getEmails(params?: GetEmailsParams): Promise<EmailSummary[]> {
  const res = await api.get<EmailSummary[]>('/emails/', { params })
  return res.data
}

export async function getEmail(id: string | number): Promise<EmailDetail> {
  const res = await api.get<EmailDetail>(`/emails/${id}`)
  return res.data
}

export async function releaseEmail(id: number): Promise<{ status: string; email_id: number }> {
  const res = await api.post(`/emails/${id}/release`)
  return res.data
}

export async function deleteEmail(id: number): Promise<{ status: string; email_id: number }> {
  const res = await api.delete(`/emails/${id}`)
  return res.data
}

export async function exportEmailsCsv(): Promise<void> {
  const res = await api.get('/emails/export/csv', { responseType: 'blob' })
  const url = window.URL.createObjectURL(new Blob([res.data]))
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', 'phishshield_emails.csv')
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

// ── Logs ──────────────────────────────────────────────────────────────────────
export interface GetLogsParams {
  severity?: string
  event_type?: string
  stage?: string
  search?: string
  skip?: number
  limit?: number
}

export async function getLogs(params?: GetLogsParams): Promise<LogEntry[]> {
  const res = await api.get<LogEntry[]>('/logs/', { params })
  return res.data
}

export async function exportLogsJson(): Promise<void> {
  const res = await api.get('/logs/export/json', { responseType: 'blob' })
  const url = window.URL.createObjectURL(new Blob([res.data]))
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', 'phishshield_logs.json')
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

// ── ML Model ──────────────────────────────────────────────────────────────────
export async function getModelMetrics(): Promise<ModelMetrics> {
  const res = await api.get<ModelMetrics>('/model/metrics')
  return res.data
}

export async function retrainModel(): Promise<any> {
  const res = await api.post('/model/retrain')
  return res.data
}

// ── Keys ──────────────────────────────────────────────────────────────────────
export async function getKeys(): Promise<Key[]> {
  const res = await api.get<Key[]>('/keys/')
  return res.data
}

export async function generateKey(
  label: string,
  domain: string,
  key_type: KeyType | string
): Promise<KeyGenerateResponse> {
  const res = await api.post<KeyGenerateResponse>('/keys/generate', { label, domain, key_type })
  return res.data
}

export async function revokeKey(keyId: number): Promise<any> {
  const res = await api.post(`/keys/${keyId}/revoke`)
  return res.data
}

export async function deleteKey(keyId: number): Promise<any> {
  const res = await api.delete(`/keys/${keyId}`)
  return res.data
}

// ── Settings ──────────────────────────────────────────────────────────────────
export async function getThresholds(): Promise<ThresholdConfig> {
  const res = await api.get<ThresholdConfig>('/settings/thresholds')
  return res.data
}

export async function updateThresholds(
  threshold_suspicious: number,
  threshold_malicious: number
): Promise<ThresholdConfig> {
  const res = await api.put<ThresholdConfig>('/settings/thresholds', {
    threshold_suspicious,
    threshold_malicious,
  })
  return res.data
}

// ── Simulation ────────────────────────────────────────────────────────────────
export async function runSimulation(
  scenario: SimulationScenario | string,
  iterations: number,
  include_benign = true
): Promise<SimulationResult> {
  const res = await api.post<SimulationResult>(`/simulate/${scenario}`, {
    scenario,
    iterations,
    include_benign,
  })
  return res.data
}

export default api
