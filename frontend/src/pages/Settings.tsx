// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Settings page (Thresholds and gateway configuration)
// ──────────────────────────────────────────────────────────────────────────────
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Settings as SettingsIcon, Save, Sliders, ShieldAlert, CheckCircle2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { getThresholds, updateThresholds } from '../lib/api'

export default function SettingsPage() {
  const queryClient = useQueryClient()
  const { data: config, isLoading } = useQuery({
    queryKey: ['settings-thresholds'],
    queryFn: getThresholds,
  })

  const [suspicious, setSuspicious] = useState<number>(41)
  const [malicious, setMalicious] = useState<number>(71)

  useEffect(() => {
    if (config) {
      setSuspicious(config.threshold_suspicious ?? config.suspicious ?? 41)
      setMalicious(config.threshold_malicious ?? config.malicious ?? 71)
    }
  }, [config])

  const mutation = useMutation({
    mutationFn: () => updateThresholds(suspicious, malicious),
    onSuccess: () => {
      toast.success('Risk score thresholds updated successfully!')
      queryClient.invalidateQueries({ queryKey: ['settings-thresholds'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to update thresholds')
    },
  })

  if (isLoading) {
    return <div className="p-12 text-center text-gray-500">Loading system settings...</div>
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <SettingsIcon className="text-indigo-600 dark:text-indigo-400" /> Gateway Settings
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Adjust risk score boundary thresholds for automatic delivery, warning banners, and quarantine
        </p>
      </div>

      {/* Thresholds Card */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700 space-y-6">
        <h2 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Sliders size={18} className="text-indigo-600 dark:text-indigo-400" /> Decision Boundaries
        </h2>

        {/* Visual Spectrum Bar */}
        <div className="space-y-2">
          <div className="h-6 w-full rounded-lg overflow-hidden flex text-xs font-bold text-white text-center shadow-inner">
            <div
              className="bg-green-500 flex items-center justify-center transition-all"
              style={{ width: `${suspicious}%` }}
            >
              Legitimate (0–{suspicious - 1})
            </div>
            <div
              className="bg-amber-500 flex items-center justify-center transition-all"
              style={{ width: `${malicious - suspicious}%` }}
            >
              Suspicious ({suspicious}–{malicious - 1})
            </div>
            <div
              className="bg-red-500 flex items-center justify-center transition-all"
              style={{ width: `${100 - malicious}%` }}
            >
              Malicious ({malicious}–100)
            </div>
          </div>
          <div className="flex justify-between text-xs text-gray-400">
            <span>0 (Safe)</span>
            <span>50 (Moderate)</span>
            <span>100 (Critical)</span>
          </div>
        </div>

        {/* Sliders */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          <div className="space-y-2 p-4 bg-gray-50 dark:bg-gray-900 rounded-xl border border-gray-100 dark:border-gray-800">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                Suspicious Threshold (Warning Banner)
              </label>
              <span className="font-bold text-sm text-amber-600 dark:text-amber-400">{suspicious}</span>
            </div>
            <input
              type="range"
              min={10}
              max={malicious - 5}
              value={suspicious}
              onChange={(e) => setSuspicious(Number(e.target.value))}
              className="w-full accent-amber-500"
            />
            <p className="text-xs text-gray-500">
              Emails scoring between {suspicious} and {malicious - 1} will be delivered with an educational warning header banner.
            </p>
          </div>

          <div className="space-y-2 p-4 bg-gray-50 dark:bg-gray-900 rounded-xl border border-gray-100 dark:border-gray-800">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                Malicious Threshold (Quarantine)
              </label>
              <span className="font-bold text-sm text-red-600 dark:text-red-400">{malicious}</span>
            </div>
            <input
              type="range"
              min={suspicious + 5}
              max={95}
              value={malicious}
              onChange={(e) => setMalicious(Number(e.target.value))}
              className="w-full accent-red-500"
            />
            <p className="text-xs text-gray-500">
              Emails scoring {malicious} or higher are automatically quarantined and encrypted with AES-256-GCM.
            </p>
          </div>
        </div>

        {/* Save button */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-semibold transition shadow-sm"
          >
            <Save size={16} /> {mutation.isPending ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  )
}
