// PhishShield – Logs page
import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getLogs, exportLogsJson } from '../lib/api'
import { Search, Download, RefreshCw } from 'lucide-react'

const SEVERITY_COLORS: Record<string, string> = {
  INFO: 'bg-blue-100 text-blue-700',
  WARNING: 'bg-amber-100 text-amber-700',
  CRITICAL: 'bg-red-100 text-red-700',
  ERROR: 'bg-red-100 text-red-700',
}

export default function Logs() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)

  const { data: logs = [], refetch, isLoading } = useQuery({
    queryKey: ['logs', search, severity],
    queryFn: () => getLogs({ search: search || undefined, severity: severity || undefined }),
    refetchInterval: autoRefresh ? 30000 : false,
  })

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Security Logs</h1>
        <div className="flex gap-2">
          <label className="flex items-center gap-1.5 text-sm cursor-pointer">
            <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} className="rounded"/>
            Auto-refresh (30s)
          </label>
          <button onClick={() => refetch()} className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"><RefreshCw size={14}/> Refresh</button>
          <button onClick={exportLogsJson} className="flex items-center gap-1.5 text-sm bg-blue-600 text-white px-3 py-1.5 rounded-lg hover:bg-blue-700">
            <Download size={14}/> Export JSON
          </button>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"/>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events…"
            className="w-full pl-8 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm focus:ring-2 focus:ring-blue-500 outline-none"/>
        </div>
        <select value={severity} onChange={e => setSeverity(e.target.value)}
          className="border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-sm outline-none">
          <option value="">All Severities</option>
          <option value="INFO">Info</option>
          <option value="WARNING">Warning</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
        {isLoading ? <div className="text-center py-16 text-gray-500">Loading…</div> : (
          <table className="w-full text-xs">
            <thead className="bg-gray-50 dark:bg-gray-700/60">
              <tr className="text-left text-gray-500 dark:text-gray-400">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Stage</th>
                <th className="px-4 py-3">Event</th>
                <th className="px-4 py-3">Message</th>
                <th className="px-4 py-3">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700 font-mono">
              {logs.map((log: any) => (
                <tr key={log.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30">
                  <td className="px-4 py-2 whitespace-nowrap text-gray-400">{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '—'}</td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${SEVERITY_COLORS[log.severity] || 'bg-gray-100 text-gray-700'}`}>{log.severity}</span>
                  </td>
                  <td className="px-4 py-2 text-gray-500">{log.stage || '—'}</td>
                  <td className="px-4 py-2 text-blue-600">{log.event_type}</td>
                  <td className="px-4 py-2 text-gray-700 dark:text-gray-300 max-w-[300px] truncate">{log.message}</td>
                  <td className="px-4 py-2 text-gray-400">{log.source_ip || '—'}</td>
                </tr>
              ))}
              {logs.length === 0 && <tr><td colSpan={6} className="text-center py-12 text-gray-500">No log entries</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
