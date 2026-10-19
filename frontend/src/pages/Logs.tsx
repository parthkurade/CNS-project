// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Security Logs page
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ScrollText, RefreshCw, Download, Search, AlertCircle, Info, AlertTriangle } from 'lucide-react'
import { getLogs, exportLogsJson } from '../lib/api'

export default function Logs() {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')

  const { data: logs, refetch, isLoading } = useQuery({
    queryKey: ['logs', searchTerm, severityFilter],
    queryFn: () =>
      getLogs({
        search: searchTerm || undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
      }),
  })

  function getSeverityBadge(severity: string) {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
            <AlertCircle size={12} /> CRITICAL
          </span>
        )
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
            <AlertTriangle size={12} /> WARNING
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
            <Info size={12} /> INFO
          </span>
        )
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ScrollText className="text-indigo-600 dark:text-indigo-400" /> Security Event Logs
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Audit trail of gateway events, threat detections, crypto verification, and policy decisions
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => exportLogsJson()}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
          >
            <Download size={15} /> Export JSON
          </button>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium transition shadow-sm"
          >
            <RefreshCw size={15} /> Refresh
          </button>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm border border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 text-gray-400" size={18} />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search logs by message, event type, or IP..."
            className="w-full pl-9 pr-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>

        <div className="flex items-center gap-2">
          {['ALL', 'CRITICAL', 'WARNING', 'INFO'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                severityFilter === sev
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading security logs...</div>
        ) : !logs || logs.length === 0 ? (
          <div className="p-12 text-center text-gray-500 space-y-2">
            <ScrollText size={36} className="mx-auto text-gray-400" />
            <p className="font-medium text-gray-700 dark:text-gray-300">No logs found</p>
            <p className="text-xs text-gray-400">Security events and threats detected will be recorded here.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Stage</th>
                  <th className="py-3 px-4">Message</th>
                  <th className="py-3 px-4">Source IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors">
                    <td className="py-3 px-4 text-xs font-mono text-gray-500 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">{getSeverityBadge(log.severity)}</td>
                    <td className="py-3 px-4 font-mono text-xs font-semibold text-gray-900 dark:text-white">
                      {log.event_type}
                    </td>
                    <td className="py-3 px-4 text-xs text-gray-500 font-mono">{log.stage || '–'}</td>
                    <td className="py-3 px-4 text-xs text-gray-800 dark:text-gray-200 max-w-md break-words">
                      {log.message}
                    </td>
                    <td className="py-3 px-4 text-xs font-mono text-gray-500">{log.source_ip || '–'}</td>
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
