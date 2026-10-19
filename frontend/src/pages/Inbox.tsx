// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Inbox page (Delivered and warned emails)
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Search, RefreshCw, Mail, ShieldCheck, AlertCircle, ArrowUpRight } from 'lucide-react'
import { getEmails } from '../lib/api'
import VerdictBadge from '../components/VerdictBadge'
import RiskScore from '../components/RiskScore'

export default function Inbox() {
  const [searchTerm, setSearchTerm] = useState('')
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL')

  const { data: emails, refetch, isLoading } = useQuery({
    queryKey: ['inbox', searchTerm, verdictFilter],
    queryFn: () =>
      getEmails({
        quarantine: false,
        search: searchTerm || undefined,
        verdict: verdictFilter !== 'ALL' ? verdictFilter : undefined,
      }),
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Mail className="text-indigo-600 dark:text-indigo-400" /> Inbox
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Delivered emails, security verifications, and warning-flagged messages
          </p>
        </div>

        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
        >
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {/* Filters & Search */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm border border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 text-gray-400" size={18} />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by subject, sender, or address..."
            className="w-full pl-9 pr-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>

        <div className="flex items-center gap-2">
          {['ALL', 'LEGITIMATE', 'SUSPICIOUS'].map((v) => (
            <button
              key={v}
              onClick={() => setVerdictFilter(v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                verdictFilter === v
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Table list */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading emails...</div>
        ) : !emails || emails.length === 0 ? (
          <div className="p-12 text-center text-gray-500 space-y-2">
            <ShieldCheck size={36} className="mx-auto text-gray-400" />
            <p className="font-medium text-gray-700 dark:text-gray-300">No delivered emails found</p>
            <p className="text-xs text-gray-400">Incoming emails processed through the gateway will appear here.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="py-3 px-4">Subject & Sender</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4 text-center">Risk Score</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Date</th>
                  <th className="py-3 px-4 text-right">Action</th>
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
                    <td className="py-3.5 px-4">
                      {email.warned ? (
                        <span className="inline-flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400 font-medium">
                          <AlertCircle size={14} /> Warning Injected
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400 font-medium">
                          <ShieldCheck size={14} /> Delivered
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                      {email.received_at ? new Date(email.received_at).toLocaleString() : '–'}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        to={`/email/${email.id}`}
                        className="inline-flex items-center gap-1 text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 font-medium text-xs"
                      >
                        Details <ArrowUpRight size={14} />
                      </Link>
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
