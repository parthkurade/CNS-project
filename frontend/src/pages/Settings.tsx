// PhishShield – Settings page
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getThresholds, updateThresholds } from '../lib/api'
import { Sliders, Save, AlertCircle, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'

export default function Settings() {
  const qc = useQueryClient()
  const [suspicious, setSuspicious] = useState<number>(41)
  const [malicious, setMalicious] = useState<number>(71)

  const { data: config, isLoading } = useQuery({
    queryKey: ['thresholds'],
    queryFn: getThresholds,
  })

  useEffect(() => {
    if (config) {
      setSuspicious(config.threshold_suspicious)
      setMalicious(config.threshold_malicious)
    }
  }, [config])

  const mutation = useMutation({
    mutationFn: () => updateThresholds(suspicious, malicious),
    onSuccess: () => {
      toast.success('Thresholds updated successfully')
      qc.invalidateQueries({ queryKey: ['thresholds'] })
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || 'Failed to update thresholds')
    },
  })

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    if (suspicious >= malicious) {
      toast.error('Suspicious threshold must be strictly less than Malicious threshold.')
      return
    }
    mutation.mutate()
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Sliders className="text-blue-600" /> Security Thresholds & Settings
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Configure risk scoring boundaries that dictate the pipeline verdict (Legitimate, Suspicious, Malicious).
        </p>
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading settings…</div>
      ) : (
        <form onSubmit={handleSave} className="space-y-6">
          {/* Visual Zone Diagram */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow space-y-4">
            <h2 className="font-semibold text-gray-800 dark:text-gray-200 text-sm">
              Current Verdict Tiers (0 – 100 Scale)
            </h2>

            <div className="flex h-10 w-full rounded-lg overflow-hidden font-semibold text-xs text-white text-center leading-10 shadow-inner">
              <div
                style={{ width: `${suspicious}%` }}
                className="bg-emerald-500 transition-all duration-200"
              >
                Legitimate (0 – {suspicious - 1})
              </div>
              <div
                style={{ width: `${malicious - suspicious}%` }}
                className="bg-amber-500 transition-all duration-200"
              >
                Suspicious ({suspicious} – {malicious - 1})
              </div>
              <div
                style={{ width: `${100 - malicious}%` }}
                className="bg-rose-600 transition-all duration-200"
              >
                Malicious ({malicious} – 100)
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 text-xs text-gray-600 dark:text-gray-400">
              <div className="border border-emerald-200 dark:border-emerald-800/40 rounded-lg p-3 bg-emerald-50/30 dark:bg-emerald-950/20">
                <span className="font-bold text-emerald-700 dark:text-emerald-400 block mb-1">
                  🟢 LEGITIMATE
                </span>
                Delivered cleanly directly to recipient inbox without modification.
              </div>
              <div className="border border-amber-200 dark:border-amber-800/40 rounded-lg p-3 bg-amber-50/30 dark:bg-amber-950/20">
                <span className="font-bold text-amber-700 dark:text-amber-400 block mb-1">
                  🟡 SUSPICIOUS
                </span>
                Delivered with an inline security advisory banner. Links neutralized.
              </div>
              <div className="border border-rose-200 dark:border-rose-800/40 rounded-lg p-3 bg-rose-50/30 dark:bg-rose-950/20">
                <span className="font-bold text-rose-700 dark:text-rose-400 block mb-1">
                  🔴 MALICIOUS
                </span>
                Blocked from delivery. AES-256-GCM encrypted and quarantined.
              </div>
            </div>
          </div>

          {/* Sliders Configuration Card */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow space-y-6">
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  Suspicious Threshold (Trigger Warning Banner)
                </label>
                <span className="font-mono text-sm px-2.5 py-0.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300 font-bold">
                  {suspicious}
                </span>
              </div>
              <input
                type="range"
                min={1}
                max={98}
                value={suspicious}
                onChange={(e) => setSuspicious(Number(e.target.value))}
                className="w-full accent-amber-500 cursor-pointer"
              />
              <p className="text-xs text-gray-400 mt-1">
                Emails scoring at or above this threshold (and below malicious) receive warning headers.
              </p>
            </div>

            <div className="pt-2 border-t dark:border-gray-700">
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  Malicious Threshold (Trigger Quarantine)
                </label>
                <span className="font-mono text-sm px-2.5 py-0.5 rounded bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-300 font-bold">
                  {malicious}
                </span>
              </div>
              <input
                type="range"
                min={2}
                max={99}
                value={malicious}
                onChange={(e) => setMalicious(Number(e.target.value))}
                className="w-full accent-rose-600 cursor-pointer"
              />
              <p className="text-xs text-gray-400 mt-1">
                Emails scoring at or above this threshold are halted and quarantined.
              </p>
            </div>

            {suspicious >= malicious && (
              <div className="flex items-center gap-2 p-3 text-sm text-red-700 bg-red-50 dark:bg-red-950/30 border border-red-200 rounded-lg">
                <AlertCircle size={16} />
                Suspicious threshold must be strictly lower than Malicious threshold.
              </div>
            )}

            <div className="flex justify-end pt-4">
              <button
                type="submit"
                disabled={mutation.isPending || suspicious >= malicious}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-lg shadow disabled:opacity-50 transition"
              >
                <Save size={16} />
                {mutation.isPending ? 'Saving…' : 'Save Thresholds'}
              </button>
            </div>
          </div>

          {/* Hard Overrides Reference */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow">
            <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-200 flex items-center gap-2 mb-2">
              <ShieldCheck size={16} className="text-blue-500" />
              Cryptographic Hard Overrides
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">
              Regardless of threshold values, the gateway enforces unconditional overrides:
              <br />• <strong>Detected Replay Attacks:</strong> Nonce collision or stale timestamp forces risk score to 100 (MALICIOUS).
              <br />• <strong>Signature Tampering:</strong> A message with a registered key that fails digital signature verification forces risk score to 100 (MALICIOUS).
              <br />• <strong>Known Malicious Attachment:</strong> Hash match against threat intelligence forces score to 100 (MALICIOUS).
            </p>
          </div>
        </form>
      )}
    </div>
  )
}
