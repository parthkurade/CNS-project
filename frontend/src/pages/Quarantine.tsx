// PhishShield – Quarantine page
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getEmails, releaseEmail, deleteEmail } from '../lib/api'
import { Lock, Unlock, Trash2 } from 'lucide-react'
import toast from 'react-hot-toast'
import VerdictBadge from '../components/VerdictBadge'

export default function Quarantine() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [confirmId, setConfirmId] = useState<number|null>(null)
  const [action, setAction] = useState<'release'|'delete'|null>(null)

  const { data: emails = [], isLoading } = useQuery({
    queryKey: ['quarantine'],
    queryFn: () => getEmails({ quarantine: true }),
  })

  const releaseMut = useMutation({ mutationFn: releaseEmail, onSuccess: () => { toast.success('Email released'); qc.invalidateQueries({queryKey:['quarantine']}) } })
  const deleteMut  = useMutation({ mutationFn: deleteEmail,  onSuccess: () => { toast.success('Email deleted'); qc.invalidateQueries({queryKey:['quarantine']}) } })

  function confirmAction() {
    if (!confirmId) return
    if (action === 'release') releaseMut.mutate(confirmId)
    else deleteMut.mutate(confirmId)
    setConfirmId(null); setAction(null)
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Quarantine</h1>
      <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg p-3 text-sm text-amber-800 dark:text-amber-300 flex items-start gap-2">
        <Lock size={16} className="shrink-0 mt-0.5" />
        All quarantined emails are stored <strong>AES-256-GCM encrypted at rest</strong>. Admins can preview safe content or permanently delete them.
      </div>

      {isLoading ? <div className="text-center py-20 text-gray-500">Loading…</div> : (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700/60">
              <tr className="text-left text-gray-500 dark:text-gray-400">
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Subject</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Received</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {emails.map((e: any) => (
                <tr key={e.id} className="hover:bg-red-50/40 dark:hover:bg-gray-700/30">
                  <td className="px-4 py-2.5 cursor-pointer text-blue-600 hover:underline" onClick={() => navigate(`/email/${e.id}`)}>{e.sender_address || '—'}</td>
                  <td className="px-4 py-2.5 truncate max-w-[240px]">{e.subject || '—'}</td>
                  <td className="px-4 py-2.5 font-mono text-red-600">{e.risk_score?.toFixed(1) ?? '—'}</td>
                  <td className="px-4 py-2.5 text-gray-400 text-xs">{e.received_at ? new Date(e.received_at).toLocaleString() : '—'}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-2">
                      <button onClick={() => { setConfirmId(e.id); setAction('release') }}
                        className="flex items-center gap-1 text-xs bg-amber-100 text-amber-700 hover:bg-amber-200 px-2 py-1 rounded">
                        <Unlock size={12} /> Release
                      </button>
                      <button onClick={() => { setConfirmId(e.id); setAction('delete') }}
                        className="flex items-center gap-1 text-xs bg-red-100 text-red-700 hover:bg-red-200 px-2 py-1 rounded">
                        <Trash2 size={12} /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {emails.length === 0 && <tr><td colSpan={5} className="text-center py-12 text-gray-500">No quarantined emails 🎉</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* Confirmation dialog */}
      {confirmId && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Confirm {action}</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-5">
              {action === 'release' ? 'This will move the email to the inbox with a warning banner.' : 'This will permanently delete the email. This action cannot be undone.'}
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => { setConfirmId(null); setAction(null) }} className="px-4 py-2 text-sm border rounded-lg">Cancel</button>
              <button onClick={confirmAction} className={`px-4 py-2 text-sm text-white rounded-lg ${action === 'delete' ? 'bg-red-600 hover:bg-red-700' : 'bg-amber-600 hover:bg-amber-700'}`}>
                Confirm {action}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
