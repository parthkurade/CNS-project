// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Key Manager page (Ed25519 / RSA-PSS / HMAC)
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, Trash2, Ban, ShieldCheck, Copy, Check, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getKeys, generateKey, revokeKey, deleteKey } from '../lib/api'
import type { KeyGenerateResponse, KeyType } from '../types'

export default function Keys() {
  const queryClient = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [label, setLabel] = useState('')
  const [domain, setDomain] = useState('')
  const [keyType, setKeyType] = useState<KeyType>('ED25519')
  const [generatedKey, setGeneratedKey] = useState<KeyGenerateResponse | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys, isLoading, refetch } = useQuery({
    queryKey: ['keys'],
    queryFn: getKeys,
  })

  const createMutation = useMutation({
    mutationFn: () => generateKey(label, domain, keyType),
    onSuccess: (data) => {
      setGeneratedKey(data)
      setShowModal(false)
      setLabel('')
      setDomain('')
      toast.success('Keypair generated successfully!')
      queryClient.invalidateQueries({ queryKey: ['keys'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Key generation failed')
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (id: number) => revokeKey(id),
    onSuccess: () => {
      toast.success('Key revoked')
      queryClient.invalidateQueries({ queryKey: ['keys'] })
    },
    onError: () => toast.error('Failed to revoke key'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteKey(id),
    onSuccess: () => {
      toast.success('Key deleted')
      queryClient.invalidateQueries({ queryKey: ['keys'] })
    },
    onError: () => toast.error('Failed to delete key'),
  })

  function handleCopy(text: string) {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('Copied to clipboard')
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <KeyRound className="text-indigo-600 dark:text-indigo-400" /> Cryptographic Key Manager
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Manage Ed25519, RSA-PSS, and HMAC signing keys for authenticated partner gateways
          </p>
        </div>

        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold transition shadow-sm"
        >
          <Plus size={16} /> Generate Keypair
        </button>
      </div>

      {/* Generated key alert modal/banner */}
      {generatedKey && (
        <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-sm text-amber-900 dark:text-amber-200 flex items-center gap-2">
              <AlertCircle size={18} className="text-amber-600" /> Save Your Private Key / Secret (Shown Once)
            </h3>
            <button
              onClick={() => setGeneratedKey(null)}
              className="text-xs text-amber-700 dark:text-amber-400 hover:underline"
            >
              Dismiss
            </button>
          </div>

          <p className="text-xs text-amber-800 dark:text-amber-300">
            For security, private keys are never stored on PhishShield servers. If lost, you must generate a new keypair.
          </p>

          {generatedKey.private_key_pem && (
            <div className="relative">
              <pre className="p-3 bg-gray-900 text-gray-100 rounded-lg text-xs font-mono overflow-x-auto max-h-40">
                {generatedKey.private_key_pem}
              </pre>
              <button
                onClick={() => handleCopy(generatedKey.private_key_pem!)}
                className="absolute top-2 right-2 p-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs flex items-center gap-1"
              >
                {copied ? <Check size={13} /> : <Copy size={13} />} Copy PEM
              </button>
            </div>
          )}

          {generatedKey.hmac_secret_b64 && (
            <div className="relative">
              <pre className="p-3 bg-gray-900 text-gray-100 rounded-lg text-xs font-mono overflow-x-auto">
                {generatedKey.hmac_secret_b64}
              </pre>
              <button
                onClick={() => handleCopy(generatedKey.hmac_secret_b64!)}
                className="absolute top-2 right-2 p-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs flex items-center gap-1"
              >
                {copied ? <Check size={13} /> : <Copy size={13} />} Copy Secret
              </button>
            </div>
          )}
        </div>
      )}

      {/* Keys Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading registered keys...</div>
        ) : !keys || keys.length === 0 ? (
          <div className="p-12 text-center text-gray-500 space-y-2">
            <KeyRound size={36} className="mx-auto text-gray-400" />
            <p className="font-medium text-gray-700 dark:text-gray-300">No public keys registered</p>
            <p className="text-xs text-gray-400">Generate a keypair to allow partner gateways to sign emails.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <th className="py-3 px-4">Label & ID</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Key Type</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {keys.map((k) => (
                  <tr key={k.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/40 transition-colors">
                    <td className="py-3 px-4">
                      <span className="font-semibold text-gray-900 dark:text-white">{k.label}</span>
                      <span className="text-xs text-gray-400 ml-2 font-mono">#{k.id}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-gray-600 dark:text-gray-300">{k.domain}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-400">
                        {k.key_type}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {k.is_active || k.active ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400 font-medium">
                          <ShieldCheck size={14} /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-gray-400 font-medium">
                          <Ban size={14} /> Revoked
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-gray-500 whitespace-nowrap">
                      {k.created_at ? new Date(k.created_at).toLocaleDateString() : '–'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      {(k.is_active || k.active) && (
                        <button
                          onClick={() => {
                            if (confirm(`Revoke key #${k.id}?`)) {
                              revokeMutation.mutate(Number(k.id))
                            }
                          }}
                          className="text-xs text-amber-600 hover:text-amber-800"
                        >
                          Revoke
                        </button>
                      )}
                      <button
                        onClick={() => {
                          if (confirm(`Delete key #${k.id}?`)) {
                            deleteMutation.mutate(Number(k.id))
                          }
                        }}
                        className="text-xs text-red-600 hover:text-red-800"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Key Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-md w-full shadow-xl border border-gray-200 dark:border-gray-700 space-y-4">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white">Generate Cryptographic Key</h3>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Label</label>
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. Finance Gateway Gateway 1"
                  className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Domain</label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="e.g. partner.corp"
                  className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Key Algorithm</label>
                <select
                  value={keyType}
                  onChange={(e) => setKeyType(e.target.value as any)}
                  className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-900 dark:text-white"
                >
                  <option value="ED25519">Ed25519 (Fast, Modern Edwards-curve)</option>
                  <option value="RSA_PSS">RSA-PSS (2048-bit with PSS padding)</option>
                  <option value="HMAC">HMAC-SHA256 (Shared secret)</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 border rounded-lg text-sm text-gray-700 dark:text-gray-300"
              >
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate()}
                disabled={!label || !domain || createMutation.isPending}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-semibold"
              >
                {createMutation.isPending ? 'Generating...' : 'Generate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
