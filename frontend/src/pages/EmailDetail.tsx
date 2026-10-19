// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – EmailDetail page (Comprehensive forensic breakdown)
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Globe,
  Paperclip,
  BrainCircuit,
  FileText,
  KeyRound,
  Trash2,
  Unlock,
  AlertTriangle,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { getEmail, releaseEmail, deleteEmail } from '../lib/api'
import VerdictBadge from '../components/VerdictBadge'
import RiskScore from '../components/RiskScore'

export default function EmailDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'explanation' | 'forensics' | 'content'>('explanation')

  const { data: email, isLoading } = useQuery({
    queryKey: ['email', id],
    queryFn: () => getEmail(id!),
    enabled: !!id,
  })

  const releaseMutation = useMutation({
    mutationFn: () => releaseEmail(Number(id)),
    onSuccess: () => {
      toast.success('Email released from quarantine')
      queryClient.invalidateQueries({ queryKey: ['email', id] })
      queryClient.invalidateQueries({ queryKey: ['quarantine'] })
      queryClient.invalidateQueries({ queryKey: ['inbox'] })
    },
    onError: () => toast.error('Failed to release email'),
  })

  const deleteMutation = useMutation({
    mutationFn: () => deleteEmail(Number(id)),
    onSuccess: () => {
      toast.success('Email permanently deleted')
      queryClient.invalidateQueries({ queryKey: ['quarantine'] })
      queryClient.invalidateQueries({ queryKey: ['inbox'] })
      navigate('/inbox')
    },
    onError: () => toast.error('Failed to delete email'),
  })

  if (isLoading) {
    return <div className="p-12 text-center text-gray-500">Loading email forensics...</div>
  }

  if (!email) {
    return (
      <div className="p-12 text-center text-gray-500 space-y-4">
        <p className="font-semibold text-lg">Email record not found</p>
        <Link to="/inbox" className="inline-flex items-center gap-2 text-indigo-600 text-sm font-medium">
          <ArrowLeft size={16} /> Return to Inbox
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top action row */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <Link
          to={email.quarantined ? '/quarantine' : '/inbox'}
          className="inline-flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-300 hover:text-indigo-600 transition"
        >
          <ArrowLeft size={16} /> Back to {email.quarantined ? 'Quarantine' : 'Inbox'}
        </Link>

        <div className="flex items-center gap-2">
          {email.quarantined && (
            <button
              onClick={() => releaseMutation.mutate()}
              disabled={releaseMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-medium transition shadow-sm"
            >
              <Unlock size={14} /> Release to Inbox
            </button>
          )}

          <button
            onClick={() => {
              if (confirm('Permanently delete this email record?')) {
                deleteMutation.mutate()
              }
            }}
            disabled={deleteMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-medium transition shadow-sm"
          >
            <Trash2 size={14} /> Delete
          </button>
        </div>
      </div>

      {/* Main summary card */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-6">
          <div className="space-y-3 flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={email.verdict as any} />
              {email.quarantined ? (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                  Quarantined (Encrypted)
                </span>
              ) : email.warning_message ? (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                  Warning Injected
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                  Delivered Clean
                </span>
              )}

              {email.is_simulation && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
                  Simulation: {email.simulation_scenario}
                </span>
              )}
            </div>

            <h1 className="text-xl md:text-2xl font-bold text-gray-900 dark:text-white break-words">
              {email.subject || '(No Subject)'}
            </h1>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-100 dark:border-gray-700">
              <div>
                <span className="font-semibold text-gray-700 dark:text-gray-300">From: </span>
                {email.sender_display_name ? `"${email.sender_display_name}" <${email.sender_address}>` : email.sender_address}
              </div>
              <div>
                <span className="font-semibold text-gray-700 dark:text-gray-300">Date: </span>
                {email.received_at ? new Date(email.received_at).toLocaleString() : '–'}
              </div>
              <div>
                <span className="font-semibold text-gray-700 dark:text-gray-300">Reply-To: </span>
                {email.reply_to || '–'}
              </div>
              <div>
                <span className="font-semibold text-gray-700 dark:text-gray-300">TLS: </span>
                {email.tls_established ? (
                  <span className="text-green-600 dark:text-green-400">
                    {email.tls_protocol || 'TLS 1.3'} ({email.tls_cipher || 'AES-GCM'})
                  </span>
                ) : (
                  <span className="text-red-500">Unencrypted (No TLS)</span>
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-col items-center justify-center p-4 bg-gray-50 dark:bg-gray-900 rounded-xl border border-gray-100 dark:border-gray-700/60 min-w-[140px]">
            <RiskScore score={email.risk_score || 0} size="lg" />
          </div>
        </div>
      </div>

      {/* Warning banner preview if present */}
      {email.warning_message && (
        <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700 rounded-xl p-4 text-sm text-amber-900 dark:text-amber-200 flex items-start gap-3">
          <AlertTriangle className="text-amber-600 flex-shrink-0 mt-0.5" size={20} />
          <div>
            <p className="font-semibold">Security Warning Banner Injected</p>
            <p className="text-xs mt-1 text-amber-800 dark:text-amber-300">{email.warning_message}</p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700 flex gap-4">
        {[
          { key: 'explanation', label: 'Security Explanation', icon: <Shield size={16} /> },
          { key: 'forensics', label: 'Inspection Layers', icon: <BrainCircuit size={16} /> },
          { key: 'content', label: 'Email Content', icon: <FileText size={16} /> },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`flex items-center gap-2 pb-3 text-sm font-semibold border-b-2 transition ${
              activeTab === tab.key
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            }`}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Educational explanation */}
      {activeTab === 'explanation' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {email.explanation && Object.keys(email.explanation).length > 0 ? (
            Object.entries(email.explanation).map(([k, item]: [string, any]) => (
              <div
                key={k}
                className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold text-gray-900 dark:text-white text-sm">{item.title}</h3>
                    {item.passed ? (
                      <CheckCircle className="text-green-500" size={18} />
                    ) : (
                      <XCircle className="text-red-500" size={18} />
                    )}
                  </div>
                  <p className="text-xs text-gray-600 dark:text-gray-300 mt-2 leading-relaxed">
                    {item.explanation}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <div className="col-span-2 p-8 text-center text-gray-500 bg-white dark:bg-gray-800 rounded-xl border">
              Explanation details will appear once processed through the risk engine.
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Forensic breakdown */}
      {activeTab === 'forensics' && (
        <div className="space-y-6">
          {/* Email Authentication */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm flex items-center gap-2 mb-4">
              <ShieldCheck className="text-indigo-500" size={18} /> Sender Authentication (SPF / DKIM / DMARC)
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <p className="text-xs text-gray-500 uppercase font-semibold">SPF Result</p>
                <p className={`text-base font-bold mt-1 ${email.spf_result === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                  {email.spf_result?.toUpperCase() || 'NONE'}
                </p>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <p className="text-xs text-gray-500 uppercase font-semibold">DKIM Result</p>
                <p className={`text-base font-bold mt-1 ${email.dkim_result === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                  {email.dkim_result?.toUpperCase() || 'NONE'}
                </p>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <p className="text-xs text-gray-500 uppercase font-semibold">DMARC Result</p>
                <p className={`text-base font-bold mt-1 ${email.dmarc_result === 'pass' ? 'text-green-500' : 'text-red-500'}`}>
                  {email.dmarc_result?.toUpperCase() || 'NONE'}
                </p>
              </div>
            </div>
          </div>

          {/* Cryptographic integrity */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm flex items-center gap-2 mb-4">
              <KeyRound className="text-indigo-500" size={18} /> Cryptography & Replay Protection
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <p className="text-gray-500 font-semibold">SHA-256 Message Hash</p>
                <p className="font-mono text-gray-700 dark:text-gray-300 break-all mt-1">{email.sha256_hash || '–'}</p>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <p className="text-gray-500 font-semibold">Digital Signature Status</p>
                <p className="font-semibold text-gray-900 dark:text-white mt-1">
                  {email.signature_valid === true
                    ? '✓ Valid Ed25519 / RSA Signature'
                    : email.signature_valid === false
                    ? '✗ Signature FAILED or untrusted'
                    : 'No gateway signature claimed'}
                </p>
              </div>
            </div>
          </div>

          {/* Machine Learning */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm flex items-center gap-2 mb-3">
              <BrainCircuit className="text-indigo-500" size={18} /> Machine Learning Threat Verdict
            </h3>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <div>
                <p className="text-xs text-gray-500">Phishing Probability</p>
                <p className="text-xl font-bold text-gray-900 dark:text-white mt-0.5">
                  {((email.ml_phishing_probability || 0) * 100).toFixed(1)}%
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500">ML Verdict</p>
                <span className="font-semibold text-sm">{email.ml_verdict || 'LEGITIMATE'}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Content preview */}
      {activeTab === 'content' && (
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
          <h3 className="font-bold text-gray-900 dark:text-white text-sm mb-4">Sanitized HTML Body Preview</h3>
          <div
            className="p-4 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-800 dark:text-gray-200 max-h-96 overflow-y-auto"
            dangerouslySetInnerHTML={{ __html: email.sanitized_html || '<p>(No content)</p>' }}
          />
        </div>
      )}
    </div>
  )
}
