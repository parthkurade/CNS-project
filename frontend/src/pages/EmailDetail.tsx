// PhishShield – Email Detail page (full analysis + educational panel)
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getEmail } from '../lib/api'
import { ChevronDown, ChevronRight, ArrowLeft, AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react'
import VerdictBadge from '../components/VerdictBadge'

function Section({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border dark:border-gray-700 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center justify-between px-5 py-3 bg-gray-50 dark:bg-gray-700/60 hover:bg-gray-100 dark:hover:bg-gray-700 text-left">
        <span className="font-semibold text-gray-800 dark:text-gray-200">{title}</span>
        {open ? <ChevronDown size={18}/> : <ChevronRight size={18}/>}
      </button>
      {open && <div className="px-5 py-4 bg-white dark:bg-gray-800">{children}</div>}
    </div>
  )
}

function Badge({ pass }: { pass: boolean }) {
  return pass
    ? <span className="flex items-center gap-1 text-xs text-green-600 font-medium"><CheckCircle size={13}/> PASS</span>
    : <span className="flex items-center gap-1 text-xs text-red-600 font-medium"><XCircle size={13}/> FAIL</span>
}

function AuthRow({ label, result }: { label: string; result: string }) {
  const pass = result?.toLowerCase() === 'pass'
  return (
    <div className="flex items-center justify-between py-1.5 border-b dark:border-gray-700 last:border-0">
      <span className="text-sm font-medium">{label}</span>
      <span className={`text-sm font-mono px-2 py-0.5 rounded ${pass ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{result || 'none'}</span>
    </div>
  )
}

export default function EmailDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [showExplain, setShowExplain] = useState(false)

  const { data: email, isLoading } = useQuery({ queryKey: ['email', id], queryFn: () => getEmail(Number(id)) })

  if (isLoading) return <div className="flex items-center justify-center h-64 text-gray-500">Loading analysis…</div>
  if (!email) return <div className="text-center py-20 text-gray-500">Email not found</div>

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"><ArrowLeft size={16}/> Back</button>
        <h1 className="text-xl font-bold text-gray-900 dark:text-white truncate">{email.subject || '(no subject)'}</h1>
        <VerdictBadge verdict={email.verdict as any} />
      </div>

      {/* Warning banners */}
      {email.verdict === 'SUSPICIOUS' && (
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-400 rounded-lg p-3 flex gap-2 text-amber-800 dark:text-amber-300">
          <AlertTriangle size={18} className="shrink-0 mt-0.5"/>
          <div><strong>Suspicious Email</strong> — {email.warning_message}</div>
        </div>
      )}
      {email.verdict === 'MALICIOUS' && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-400 rounded-lg p-3 flex gap-2 text-red-800 dark:text-red-300">
          <XCircle size={18} className="shrink-0 mt-0.5"/>
          <div><strong>MALICIOUS — Quarantined.</strong> Risk score: {email.risk_score?.toFixed(1)}</div>
        </div>
      )}

      {/* Risk score summary */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow flex flex-wrap gap-6 items-center">
        <div className="text-center">
          <div className={`text-4xl font-bold ${email.risk_score! >= 71 ? 'text-red-600' : email.risk_score! >= 41 ? 'text-amber-600' : 'text-green-600'}`}>
            {email.risk_score?.toFixed(0) ?? '—'}
          </div>
          <div className="text-xs text-gray-500 mt-1">Risk Score /100</div>
        </div>
        {email.risk_breakdown && (
          <div className="flex-1 grid grid-cols-3 gap-2 text-xs">
            {Object.entries(email.risk_breakdown).filter(([k]) => !['hard_override','override_reason'].includes(k)).map(([k,v]) => (
              <div key={k} className="bg-gray-50 dark:bg-gray-700 rounded p-2">
                <div className="text-gray-500 capitalize">{k.replace('_score','')}</div>
                <div className="font-bold text-base">{typeof v === 'number' ? v.toFixed(1) : String(v)}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Sections */}
      <Section title="📧 Email Headers" defaultOpen>
        <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
          <div className="text-gray-500">From</div><div className="truncate">{email.sender_display_name ? `${email.sender_display_name} <${email.sender_address}>` : email.sender_address}</div>
          <div className="text-gray-500">Reply-To</div><div>{email.reply_to || '—'}</div>
          <div className="text-gray-500">Subject</div><div>{email.subject}</div>
          <div className="text-gray-500">Message-ID</div><div className="text-xs font-mono truncate">{email.message_id}</div>
          <div className="text-gray-500">TLS</div>
          <div>{email.tls_established ? <span className="text-green-600 font-medium">✓ {email.tls_protocol} / {email.tls_cipher}</span> : <span className="text-red-600">✗ Not encrypted</span>}</div>
          <div className="text-gray-500">SHA-256</div><div className="text-xs font-mono truncate">{email.sha256_hash}</div>
        </div>
      </Section>

      <Section title="🔐 Sender Authentication (SPF / DKIM / DMARC)" defaultOpen>
        <AuthRow label="SPF" result={email.spf_result || 'none'} />
        <AuthRow label="DKIM" result={email.dkim_result || 'none'} />
        <AuthRow label="DMARC" result={email.dmarc_result || 'none'} />
        {email.spoofing_findings?.is_spoofed && (
          <div className="mt-3 bg-red-50 dark:bg-red-900/20 rounded p-2 text-sm text-red-700">
            ⚠ Spoofing detected: {JSON.stringify(email.spoofing_findings?.checks)}
          </div>
        )}
      </Section>

      <Section title="🔒 Cryptographic Verification">
        <div className="space-y-2 text-sm">
          <div className="flex justify-between"><span>Message Hash (SHA-256)</span><span className="font-mono text-xs truncate max-w-[260px]">{email.sha256_hash}</span></div>
          <div className="flex justify-between"><span>Digital Signature</span>{email.signature_valid === true ? <Badge pass={true}/> : email.signature_valid === false ? <Badge pass={false}/> : <span className="text-xs text-gray-400">Not claimed</span>}</div>
          <div className="flex justify-between"><span>HMAC Integrity</span>{email.hmac_valid === true ? <Badge pass={true}/> : email.hmac_valid === false ? <Badge pass={false}/> : <span className="text-xs text-gray-400">Not claimed</span>}</div>
          <div className="flex justify-between"><span>Replay Attack</span>{email.replay_detected ? <span className="text-red-600 font-medium text-xs">DETECTED 🚨</span> : <span className="text-green-600 text-xs">Clean</span>}</div>
        </div>
      </Section>

      <Section title="🌐 URL Analysis">
        {email.url_findings ? (
          <div>
            <div className="flex gap-6 mb-3 text-sm">
              <div><span className="text-gray-500">URLs found:</span> <strong>{email.url_findings.count}</strong></div>
              <div><span className="text-gray-500">URL risk score:</span> <strong className={email.url_findings.risk_score > 50 ? 'text-red-600' : 'text-green-600'}>{email.url_findings.risk_score?.toFixed(0)}</strong></div>
            </div>
            {email.url_findings.top_risks?.length > 0 && (
              <div className="mb-3"><strong className="text-sm">Top risks:</strong> {email.url_findings.top_risks.join(', ')}</div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-gray-500 border-b dark:border-gray-700">
                  <th className="pb-1 text-left">URL</th><th className="pb-1">IP</th><th className="pb-1">Shortener</th><th className="pb-1">Sus.TLD</th><th className="pb-1">HTTPS</th>
                </tr></thead>
                <tbody>
                  {email.url_findings.urls?.map((u: any, i: number) => (
                    <tr key={i} className="border-b dark:border-gray-700/50">
                      <td className="py-1 truncate max-w-[240px] text-blue-600">{u.url}</td>
                      <td className="py-1 text-center">{u.is_ip ? '⚠' : '✓'}</td>
                      <td className="py-1 text-center">{u.shortener ? '⚠' : '✓'}</td>
                      <td className="py-1 text-center">{u.suspicious_tld ? '⚠' : '✓'}</td>
                      <td className="py-1 text-center">{u.uses_https ? '✓' : '⚠'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : <p className="text-sm text-gray-500">No URL findings</p>}
      </Section>

      <Section title="🤖 ML Phishing Detection">
        {email.ml_phishing_probability !== null ? (
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <div>
                <div className="text-3xl font-bold" style={{color: email.ml_phishing_probability! > 0.5 ? '#ef4444' : '#10b981'}}>
                  {(email.ml_phishing_probability! * 100).toFixed(1)}%
                </div>
                <div className="text-xs text-gray-500">Phishing probability</div>
              </div>
              <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                <div className="h-3 rounded-full" style={{width: `${email.ml_phishing_probability! * 100}%`, background: email.ml_phishing_probability! > 0.5 ? '#ef4444' : '#10b981'}}/>
              </div>
            </div>
            {email.ml_top_features && email.ml_top_features.length > 0 && (
              <div>
                <div className="text-sm font-medium mb-2">Top phishing indicators:</div>
                <div className="space-y-1">
                  {email.ml_top_features.slice(0, 8).map((f: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="w-36 truncate text-gray-600">{f.feature}</span>
                      <div className="flex-1 bg-gray-100 dark:bg-gray-700 rounded h-2">
                        <div className="h-2 rounded bg-red-400" style={{width: `${Math.min(Math.abs(f.weight)*100, 100)}%`}}/>
                      </div>
                      <span className="w-12 text-right font-mono">{f.weight?.toFixed(3)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : <p className="text-sm text-gray-500">ML analysis not available</p>}
      </Section>

      {/* Educational panel */}
      <div className="border dark:border-gray-700 rounded-xl overflow-hidden">
        <button onClick={() => setShowExplain(o => !o)} className="w-full flex items-center justify-between px-5 py-3 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/30 text-left">
          <span className="font-semibold text-blue-700 dark:text-blue-300 flex items-center gap-2"><Info size={18}/> Explain This (Educational Mode)</span>
          {showExplain ? <ChevronDown size={18}/> : <ChevronRight size={18}/>}
        </button>
        {showExplain && email.explanation && (
          <div className="px-5 py-4 bg-blue-50/40 dark:bg-blue-900/10 space-y-4">
            {Object.entries(email.explanation).map(([key, check]: [string, any]) => (
              <div key={key} className="border dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800">
                <div className="flex items-center gap-2 mb-1">
                  {check.passed ? <CheckCircle size={16} className="text-green-600"/> : <XCircle size={16} className="text-red-600"/>}
                  <strong className="text-sm">{check.title}</strong>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{check.explanation}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pipeline timing */}
      {email.pipeline_timing && (
        <Section title="⚡ Pipeline Timing">
          <div className="grid grid-cols-3 gap-3 text-sm">
            {Object.entries(email.pipeline_timing).map(([stage, ms]: [string, any]) => (
              <div key={stage} className="bg-gray-50 dark:bg-gray-700 rounded p-2">
                <div className="text-gray-500 text-xs capitalize">{stage}</div>
                <div className="font-bold">{typeof ms === 'number' ? ms.toFixed(1) : ms}ms</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Safe HTML preview */}
      {email.sanitized_html && (
        <Section title="📄 Message Preview (Sanitized)">
          <div className="prose dark:prose-invert max-w-none text-sm border dark:border-gray-700 rounded p-4 bg-gray-50 dark:bg-gray-700/40"
            dangerouslySetInnerHTML={{ __html: email.sanitized_html }} />
        </Section>
      )}
    </div>
  )
}
