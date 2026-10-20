// PhishShield – Key Manager page
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getKeys, generateKey, revokeKey } from '../lib/api'
import { Plus, Copy, AlertTriangle, KeyRound } from 'lucide-react'
import toast from 'react-hot-toast'

export default function Keys() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [generatedKey, setGeneratedKey] = useState<any>(null)
  const [form, setForm] = useState({ label: '', domain: '', key_type: 'ED25519' })

  const { data: keys = [], isLoading } = useQuery({ queryKey: ['keys'], queryFn: getKeys })

  const generateMut = useMutation({
    mutationFn: () => generateKey(form.label, form.domain, form.key_type as any),
    onSuccess: (data) => { setGeneratedKey(data); qc.invalidateQueries({ queryKey: ['keys'] }) },
    onError: () => toast.error('Key generation failed'),
  })

  const revokeMut = useMutation({
    mutationFn: revokeKey,
    onSuccess: () => { toast.success('Key revoked'); qc.invalidateQueries({ queryKey: ['keys'] }) },
  })

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Key Manager</h1>
        <button onClick={() => { setShowModal(true); setGeneratedKey(null) }}
          className="flex items-center gap-1.5 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700">
          <Plus size={16}/> Generate Key
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
        {[{type:'ED25519',desc:'EdDSA over Curve25519. 64-byte sigs, 32-byte keys. Fastest and most secure. Recommended.'},{type:'RSA_PSS',desc:'RSA-PSS 2048-bit. Compatible with legacy systems. SHA-256 hash + MGF1 mask.'},{type:'HMAC',desc:'Shared-secret 256-bit key for partner gateway authentication (constant-time verification).'}].map(k=>(
          <div key={k.type} className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 border dark:border-gray-700">
            <div className="font-medium flex items-center gap-2"><KeyRound size={15}/> {k.type}</div>
            <p className="text-gray-500 text-xs mt-1">{k.desc}</p>
          </div>
        ))}
      </div>

      {isLoading ? <div className="text-center py-10 text-gray-500">Loading keys…</div> : (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700/60">
              <tr className="text-left text-gray-500 dark:text-gray-400">
                <th className="px-4 py-3">Label</th><th className="px-4 py-3">Domain</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Created</th><th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {keys.map((k: any) => (
                <tr key={k.id}>
                  <td className="px-4 py-2.5 font-medium">{k.label}</td>
                  <td className="px-4 py-2.5 text-gray-500">{k.domain || '—'}</td>
                  <td className="px-4 py-2.5"><span className="bg-blue-100 text-blue-700 px-2 py-0.5 rounded text-xs">{k.key_type}</span></td>
                  <td className="px-4 py-2.5"><span className={`px-2 py-0.5 rounded text-xs ${k.is_active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>{k.is_active ? 'Active' : 'Revoked'}</span></td>
                  <td className="px-4 py-2.5 text-gray-400 text-xs">{k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}</td>
                  <td className="px-4 py-2.5">
                    {k.is_active && <button onClick={() => revokeMut.mutate(k.id)} className="text-xs text-red-600 hover:underline">Revoke</button>}
                  </td>
                </tr>
              ))}
              {keys.length === 0 && <tr><td colSpan={6} className="text-center py-12 text-gray-500">No keys registered</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* Generate modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-md w-full shadow-xl space-y-4">
            <h3 className="font-semibold text-lg text-gray-900 dark:text-white">Generate New Key</h3>
            {!generatedKey ? (
              <>
                <div className="space-y-3">
                  <div><label className="text-sm font-medium">Label</label><input value={form.label} onChange={e=>setForm(f=>({...f,label:e.target.value}))} className="w-full mt-1 border dark:border-gray-600 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-700 outline-none focus:ring-2 focus:ring-blue-500"/></div>
                  <div><label className="text-sm font-medium">Domain (optional)</label><input value={form.domain} onChange={e=>setForm(f=>({...f,domain:e.target.value}))} placeholder="example.com" className="w-full mt-1 border dark:border-gray-600 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-700 outline-none focus:ring-2 focus:ring-blue-500"/></div>
                  <div><label className="text-sm font-medium">Key Type</label>
                    <select value={form.key_type} onChange={e=>setForm(f=>({...f,key_type:e.target.value}))} className="w-full mt-1 border dark:border-gray-600 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-700 outline-none">
                      <option value="ED25519">Ed25519</option><option value="RSA_PSS">RSA-PSS 2048</option><option value="HMAC">HMAC-SHA256</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-3 justify-end">
                  <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm border rounded-lg">Cancel</button>
                  <button onClick={() => generateMut.mutate()} disabled={!form.label || generateMut.isPending} className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-60">Generate</button>
                </div>
              </>
            ) : (
              <>
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 rounded-lg p-3 flex gap-2 text-sm text-amber-800 dark:text-amber-300">
                  <AlertTriangle size={16} className="shrink-0 mt-0.5"/>
                  Save this key now — it will <strong>never be shown again</strong>.
                </div>
                {generatedKey.private_key_pem && (
                  <div>
                    <label className="text-xs text-gray-500">Private Key (PEM)</label>
                    <div className="relative mt-1">
                      <textarea readOnly rows={5} value={generatedKey.private_key_pem} className="w-full font-mono text-xs border dark:border-gray-600 rounded-lg p-2 bg-gray-50 dark:bg-gray-700 resize-none"/>
                      <button onClick={() => { navigator.clipboard.writeText(generatedKey.private_key_pem); toast.success('Copied!') }} className="absolute top-2 right-2 text-xs bg-white dark:bg-gray-600 border rounded px-2 py-0.5 flex items-center gap-1"><Copy size={11}/> Copy</button>
                    </div>
                  </div>
                )}
                {generatedKey.hmac_secret_b64 && (
                  <div>
                    <label className="text-xs text-gray-500">HMAC Shared Secret (base64)</label>
                    <div className="relative mt-1">
                      <input readOnly value={generatedKey.hmac_secret_b64} className="w-full font-mono text-xs border dark:border-gray-600 rounded-lg px-3 py-2 bg-gray-50 dark:bg-gray-700"/>
                      <button onClick={() => { navigator.clipboard.writeText(generatedKey.hmac_secret_b64); toast.success('Copied!') }} className="absolute right-2 top-1/2 -translate-y-1/2 text-xs bg-white dark:bg-gray-600 border rounded px-2 py-0.5 flex items-center gap-1"><Copy size={11}/> Copy</button>
                    </div>
                  </div>
                )}
                <button onClick={() => { setShowModal(false); setGeneratedKey(null) }} className="w-full py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700">Done</button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
