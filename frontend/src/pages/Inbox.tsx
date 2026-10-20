// PhishShield – Inbox page
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getEmails, exportEmailsCsv } from '../lib/api'
import { Download, Search } from 'lucide-react'
import VerdictBadge from '../components/VerdictBadge'

export default function Inbox() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [verdict, setVerdict] = useState('')
  const [page, setPage] = useState(0)
  const limit = 50

  const { data: emails = [], isLoading } = useQuery({
    queryKey: ['emails', search, verdict, page],
    queryFn: () => getEmails({ search: search || undefined, verdict: verdict || undefined, skip: page * limit, limit, quarantine: false }),
  })

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Inbox</h1>
        <button onClick={exportEmailsCsv} className="flex items-center gap-1.5 text-sm bg-blue-600 text-white px-3 py-1.5 rounded-lg hover:bg-blue-700">
          <Download size={15} /> Export CSV
        </button>
      </div>

      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={search} onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search sender, subject…"
            className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
          />
        </div>
        <select
          value={verdict} onChange={e => { setVerdict(e.target.value); setPage(0) }}
          className="border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
        >
          <option value="">All Verdicts</option>
          <option value="LEGITIMATE">Legitimate</option>
          <option value="SUSPICIOUS">Suspicious</option>
        </select>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-gray-500">Loading…</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700/60">
              <tr className="text-left text-gray-500 dark:text-gray-400">
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Verdict</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">TLS</th>
                <th className="px-4 py-3">Received</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {emails.map((e: any) => (
                <tr
                  key={e.id}
                  onClick={() => navigate(`/email/${e.id}`)}
                  className="cursor-pointer hover:bg-blue-50 dark:hover:bg-gray-700/50 transition"
                >
                  <td className="px-4 py-2.5 truncate max-w-[160px]">{e.sender_address || '—'}</td>
                  <td className="px-4 py-2.5 truncate max-w-[240px]">{e.subject || '—'}</td>
                  <td className="px-4 py-2.5"><VerdictBadge verdict={e.verdict} /></td>
                  <td className="px-4 py-2.5 font-mono">{e.risk_score?.toFixed(1) ?? '—'}</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-xs font-medium ${e.tls_established ? 'text-green-600' : 'text-red-500'}`}>
                      {e.tls_established ? 'TLS ✓' : 'Plain ✗'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-gray-400 text-xs">{e.received_at ? new Date(e.received_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
              {emails.length === 0 && (
                <tr><td colSpan={6} className="text-center py-12 text-gray-500">No emails found</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex gap-2 justify-end">
        <button onClick={() => setPage(p => Math.max(0, p-1))} disabled={page === 0} className="px-3 py-1.5 rounded border text-sm disabled:opacity-40">← Prev</button>
        <span className="px-3 py-1.5 text-sm text-gray-600">Page {page+1}</span>
        <button onClick={() => setPage(p => p+1)} disabled={emails.length < limit} className="px-3 py-1.5 rounded border text-sm disabled:opacity-40">Next →</button>
      </div>
    </div>
  )
}
