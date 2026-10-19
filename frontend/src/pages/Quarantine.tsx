// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Quarantine page (Blocked/quarantined emails)
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ShieldAlert, RefreshCw, Trash2, Unlock, ArrowUpRight, Search } from 'lucide-react'
import toast from 'react-hot-toast'
import { getEmails, releaseEmail, deleteEmail } from '../lib/api'
import VerdictBadge from '../components/VerdictBadge'
import RiskScore from '../components/RiskScore'

export default function Quarantine() {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')

  const { data: emails, refetch, isLoading } = useQuery({
    queryKey: ['quarantine', searchTerm],
    queryFn: () =>
      getEmails({
        quarantine: true,
        search: searchTerm || undefined,
      }),
  })

  const releaseMutation = useMutation({
    mutationFn: (id: number) => releaseEmail(id),
    onSuccess: (_, id) => {
      toast.success(`Email #${id} released to inbox`)
      queryClient.invalidateQueries({ queryKey: ['quarantine'] })
      queryClient.invalidateQueries({ queryKey: ['inbox'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: () => toast.error('Failed to release email'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteEmail(id),
    onSuccess: (_, id) => {
      toast.success(`Email #${id} permanently deleted`)
      queryClient.invalidateQueries({ queryKey: ['quarantine'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: () => toast.error('Failed to delete email'),
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldAlert className="text-red-600 dark:text-red-400" /> Quarantine
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Blocked malicious and high-risk emails safely isolated with AES-256-GCM encryption
          </p>
        </div>

        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
        >
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {/* Search */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 text-gray-400" size={18} />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search quarantined emails by subject or sender..."
            className="w-full pl-9 pr-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500"
          />
        </div>
      </div>

      {/* Table list */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading quarantined emails...</div>
        ) : !emails || emails.length === 0 ? (
          <div className="p-12 text-center text-gray-500 space-y-2">
            <ShieldAlert size={36} className="mx-auto text-green-500" />
            <p className="font-medium text-gray-700 dark:text-gray-300">Quarantine is empty</p>
            <p className="text-xs text-gray-400">No malicious emails are currently held in quarantine.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="py-3 px-4">Subject & Sender</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4 text-center">Risk Score</th>
                  <th className="py-3 px-4">Blocked At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {emails.map((email) => (
                  <tr
                    key={email.id}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors"
                  >
                    <td className="py-3.5 px-4 max-w-xs sm:max-w-md">
                      <div className="font-semibold text-gray-900 dark:text-white truncate">
                        {email.subject || '(No Subject)'}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 truncate mt-0.5">
                        {email.sender}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <VerdictBadge verdict={email.verdict} />
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <RiskScore score={email.risk_score} size="sm" showLabel={false} />
                    </td>
                    <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                      {email.received_at ? new Date(email.received_at).toLocaleString() : '–'}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2 whitespace-nowrap">
                      <Link
                        to={`/email/${email.id}`}
                        className="inline-flex items-center gap-1 text-xs text-gray-600 dark:text-gray-300 hover:text-indigo-600 dark:hover:text-indigo-400 px-2 py-1 rounded bg-gray-100 dark:bg-gray-700"
                        title="View Full Forensic Details"
                      >
                        Inspect <ArrowUpRight size={13} />
                      </Link>

                      <button
                        onClick={() => releaseMutation.mutate(Number(email.id))}
                        disabled={releaseMutation.isPending}
                        className="inline-flex items-center gap-1 text-xs text-amber-700 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/40 px-2 py-1 rounded bg-amber-50 dark:bg-amber-900/20"
                        title="Release email to recipient"
                      >
                        <Unlock size={13} /> Release
                      </button>

                      <button
                        onClick={() => {
                          if (confirm(`Permanently delete quarantined email #${email.id}?`)) {
                            deleteMutation.mutate(Number(email.id))
                          }
                        }}
                        disabled={deleteMutation.isPending}
                        className="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 px-2 py-1 rounded bg-red-50 dark:bg-red-900/20"
                        title="Delete permanently"
                      >
                        <Trash2 size={13} /> Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
