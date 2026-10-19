// PhishShield – Dashboard page
import { useQuery } from '@tanstack/react-query'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { getDashboardStats, getTimeline, getRiskHistogram } from '../lib/api'
import { RefreshCw, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

const VERDICT_COLORS = { LEGITIMATE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' }

function StatCard({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color: string }) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl p-5 shadow border-l-4 ${color}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">{value.toLocaleString()}</p>
        </div>
        <div className="text-gray-400">{icon}</div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: stats, refetch, isLoading } = useQuery({ queryKey: ['stats'], queryFn: getDashboardStats })
  const { data: timeline } = useQuery({ queryKey: ['timeline'], queryFn: () => getTimeline(7) })
  const { data: histogram } = useQuery({ queryKey: ['histogram'], queryFn: getRiskHistogram })

  if (isLoading) return <div className="flex items-center justify-center h-64 text-gray-500">Loading dashboard…</div>
  if (!stats) return null

  const pieData = [
    { name: 'Legitimate', value: stats.legitimate },
    { name: 'Suspicious', value: stats.suspicious },
    { name: 'Malicious', value: stats.malicious },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <button onClick={() => refetch()} className="flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700">
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Emails" value={stats.total_emails} icon={<Shield size={28}/>} color="border-blue-500" />
        <StatCard label="Legitimate" value={stats.legitimate} icon={<CheckCircle size={28} className="text-green-500"/>} color="border-green-500" />
        <StatCard label="Suspicious" value={stats.suspicious} icon={<AlertTriangle size={28} className="text-amber-500"/>} color="border-amber-500" />
        <StatCard label="Malicious" value={stats.malicious} icon={<XCircle size={28} className="text-red-500"/>} color="border-red-500" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline chart */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Verdicts Over Time (7 days)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={timeline || []}>
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend />
              <Bar dataKey="legitimate" fill="#10b981" name="Legitimate" />
              <Bar dataKey="suspicious" fill="#f59e0b" name="Suspicious" />
              <Bar dataKey="malicious" fill="#ef4444" name="Malicious" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Pie chart */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Verdict Distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={VERDICT_COLORS[entry.name as keyof typeof VERDICT_COLORS] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Risk histogram */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Risk Score Distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={histogram || []}>
              <XAxis dataKey="range" tick={{ fontSize: 10 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="count" fill="#3b82f6" name="Emails" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Layer catch rates */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Detection Layer Rates (%)</h2>
          <div className="space-y-2">
            {Object.entries(stats.layer_catch_rates).map(([layer, rate]) => (
              <div key={layer} className="flex items-center gap-3">
                <span className="text-xs text-gray-500 w-32 shrink-0">{layer.replace('_', ' ')}</span>
                <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${rate}%` }} />
                </div>
                <span className="text-xs font-medium w-10 text-right">{rate}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent verdicts */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
        <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Recent Activity</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b dark:border-gray-700">
                <th className="pb-2 pr-4">Sender</th>
                <th className="pb-2 pr-4">Subject</th>
                <th className="pb-2 pr-4">Verdict</th>
                <th className="pb-2 pr-4">Score</th>
                <th className="pb-2">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {stats.recent_verdicts.map((r: any) => (
                <tr key={r.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="py-2 pr-4 truncate max-w-[140px]">{r.sender || '—'}</td>
                  <td className="py-2 pr-4 truncate max-w-[200px]">{r.subject || '—'}</td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                      r.verdict === 'LEGITIMATE' ? 'bg-green-100 text-green-700' :
                      r.verdict === 'SUSPICIOUS' ? 'bg-amber-100 text-amber-700' :
                      'bg-red-100 text-red-700'
                    }`}>{r.verdict || '—'}</span>
                  </td>
                  <td className="py-2 pr-4">{r.risk_score?.toFixed(1) || '—'}</td>
                  <td className="py-2 text-gray-500 text-xs">{r.received_at ? new Date(r.received_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
