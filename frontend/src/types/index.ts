// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – shared TypeScript interfaces
// ──────────────────────────────────────────────────────────────────────────────

export type VerdictType = 'LEGITIMATE' | 'SUSPICIOUS' | 'MALICIOUS'

// ── Auth ──────────────────────────────────────────────────────────────────────
export interface TokenResponse {
  access_token: string
  token_type: string
  role: string
  email: string
}

// ── Email summary (list view) ─────────────────────────────────────────────────
export interface EmailSummary {
  id: string
  sender: string
  subject: string
  received_at: string
  verdict: VerdictType
  risk_score: number
  tls_valid: boolean
  quarantined: boolean
  delivered: boolean
  warned: boolean
}

// ── URL feature detail ────────────────────────────────────────────────────────
export interface URLFeature {
  url: string
  is_ip: boolean
  uses_https: boolean
  domain_age_days: number | null
  suspicious_keywords: string[]
  redirect_count: number
  final_url: string | null
  ml_phishing_prob: number | null
}

// ── Attachment finding ────────────────────────────────────────────────────────
export interface AttachmentFinding {
  filename: string
  content_type: string
  size_bytes: number
  sha256: string
  is_suspicious: boolean
  reason: string | null
}

// ── Risk score breakdown ──────────────────────────────────────────────────────
export interface RiskBreakdown {
  ml_score: number
  url_score: number
  attachment_score: number
  auth_score: number
  tls_score: number
  replay_score: number
  signature_score: number
  total: number
}

export interface EmailDetail {
  id: number | string
  message_id?: string | null
  received_at?: string
  sender_address?: string | null
  sender_display_name?: string | null
  reply_to?: string | null
  subject?: string | null
  recipients?: string[] | null

  // TLS
  tls_protocol?: string | null
  tls_cipher?: string | null
  tls_established?: boolean

  // Auth
  spf_result?: string | null
  dkim_result?: string | null
  dmarc_result?: string | null
  auth_details?: any

  // Crypto
  sha256_hash?: string | null
  signature_valid?: boolean | null
  hmac_valid?: boolean | null
  replay_detected?: boolean
  crypto_details?: any

  // Findings
  url_findings?: any
  attachment_findings?: any
  header_findings?: any
  spoofing_findings?: any

  // ML
  ml_phishing_probability?: number | null
  ml_verdict?: string | null
  ml_top_features?: any[] | null

  // Verdict & Scoring
  risk_score?: number | null
  risk_breakdown?: any
  verdict?: VerdictType | string | null
  delivered?: boolean
  quarantined?: boolean
  warning_message?: string | null
  sanitized_html?: string | null
  pipeline_timing?: any
  explanation?: any
  is_simulation?: boolean
  simulation_scenario?: string | null
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export interface DashboardStats {
  total_emails: number
  legitimate: number
  suspicious: number
  malicious: number
  simulations?: number
  detections_today?: number
  avg_risk_score: number
  top_attack_types?: Array<{ scenario: string; count: number }>
  layer_catch_rates: Record<string, number>
  recent_verdicts: any[]
}

// ── Timeline ──────────────────────────────────────────────────────────────────
export interface TimelineEntry {
  date: string
  legitimate: number
  suspicious: number
  malicious: number
}

// ── Risk histogram ────────────────────────────────────────────────────────────
export interface HistogramEntry {
  range?: string
  bucket?: string
  count: number
}

// ── Logs ─────────────────────────────────────────────────────────────────────
export type LogSeverity = 'INFO' | 'WARNING' | 'CRITICAL'

export interface LogEntry {
  id: string
  timestamp: string
  event_type: string
  severity: LogSeverity
  stage: string
  message: string
  source_ip: string | null
  email_id: string | null
}

// ── ML Model metrics ──────────────────────────────────────────────────────────
export interface ConfusionMatrix {
  tp: number
  fp: number
  tn: number
  fn: number
}

export interface ModelMetrics {
  accuracy: number
  precision: number
  recall: number
  f1: number
  roc_auc: number
  confusion_matrix: any
  top_features: Array<any>
  training_samples?: number
  test_samples?: number
  trained_at?: string
  dataset_source?: string
}

// ── Simulation ────────────────────────────────────────────────────────────────
export type SimulationScenario =
  | 'phishing'
  | 'spoofing'
  | 'tampering'
  | 'replay'
  | 'mitm'

export interface SimulationResultEntry {
  iteration: number
  verdict: VerdictType
  risk_score: number
  catching_layers: string[]
  latency_ms: number
  extra?: Record<string, string | number | boolean | null>
}

export interface SimulationResult {
  scenario: string
  iterations: number
  detection_rate: number
  false_positive_rate?: number | null
  avg_latency_ms?: number
  results: any
  summary?: any
}

// ── Key management ────────────────────────────────────────────────────────────
export type KeyType = 'ED25519' | 'RSA_PSS' | 'HMAC' | 'Ed25519' | 'RSA-PSS'

export interface Key {
  id: string | number
  label: string
  domain: string
  key_type: string
  is_active?: boolean
  active?: boolean
  created_at: string
  revoked_at: string | null
}

export interface KeyGenerateResponse {
  key: Key
  private_key_pem?: string | null   // Ed25519 / RSA-PSS private key (PEM)
  hmac_secret?: string | null        // HMAC secret
  hmac_secret_b64?: string | null
  warning?: string
}

// ── Thresholds ────────────────────────────────────────────────────────────────
export interface ThresholdConfig {
  threshold_suspicious: number   // default 41
  threshold_malicious: number    // default 71
  suspicious?: number
  malicious?: number
}

// ── Analyse ───────────────────────────────────────────────────────────────────
export interface AnalyzeResponse extends EmailDetail {}
