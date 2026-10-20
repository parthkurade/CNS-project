// PhishShield – Attack Simulation page
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { runSimulation } from '../lib/api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Play, Zap, Shield, Mail, RefreshCw, Lock, Wifi } from 'lucide-react'
import toast from 'react-hot-toast'

const SCENARIOS = [
  { id: 'phishing', label: 'Phishing Attack', icon: <Mail size={20}/>, color: 'red',
    desc: 'Credential-harvesting email with malicious URL, spoofed branding, and urgency language. Tests ML + URL analysis.' },
  { id: 'spoofing', label: 'Sender Spoofing', icon: <Shield size={20}/>, color: 'orange',
    desc: 'Email forging a legitimate domain (paypal.com, google.com). Tests SPF/DKIM/DMARC + lookalike detection.' },
  { id: 'tampering', label: 'Message Tampering', icon: <RefreshCw size={20}/>, color: 'purple',
    desc: 'Signs a real email, then modifies the body (MitM). Tests Ed25519 signature verification + SHA-256 hash.' },
  { id: 'replay', label: 'Replay Attack', icon: <Zap size={20}/>, color: 'yellow',
    desc: 'Sends a valid signed message twice with same nonce. Tests nonce cache replay protection.' },
  { id: 'mitm', label: 'Man-in-the-Middle', icon: <Wifi size={20}/>, color: 'blue',
    desc: 'Forged signature with non-existent key ID, no TLS. Tests sig verification + TLS status checks.' },
]

const COLOR_MAP: Record<string, string> = { red:'border-red-500 bg-red-50 dark:bg-red-900/20', orange:'border-orange-500 bg-orange-50 dark:bg-orange-900/20', purple:'border-purple-500 bg-purple-50 dark:bg-purple-900/20', yellow:'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20', blue:'border-blue-500 bg-blue-50 dark:bg-blue-900/20' }

function ResultsPanel({ result }: { result: any }) {
  if (!result) return null
  const isBatch = result.scenario === 'batch'

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow space-y-4">
      <div className="flex flex-wrap gap-6">
        <div className="text-center">
          <div className={`text-4xl font-bold ${result.detection_rate >= 80 ? 'text-green-600' : result.detection_rate >= 50 ? 'text-amber-600' : 'text-red-600'}`}>
            {result.detection_rate?.toFixed(1)}%
          </div>
          <div className="text-xs text-gray-500">Detection Rate</div>
        </div>
        {result.false_positive_rate !== null && result.false_positive_rate !== undefined && (
          <div className="text-center">
            <div className="text-4xl font-bold text-blue-600">{result.false_positive_rate?.toFixed(1)}%</div>
            <div className="text-xs text-gray-500">False Positive Rate</div>
          </div>
        )}
        <div className="text-center">
          <div className="text-4xl font-bold text-gray-700 dark:text-gray-200">{result.avg_latency_ms?.toFixed(0)}ms</div>
          <div className="text-xs text-gray-500">Avg Latency</div>
        </div>
      </div>

      {isBatch && result.results && (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={Object.entries(result.results as Record<string,any>).map(([k,v])=>({name:k,rate:v.detection_rate}))}>
            <XAxis dataKey="name" tick={{fontSize:11}}/>
            <YAxis domain={[0,100]} tick={{fontSize:11}}/>
            <Tooltip formatter={(v:any)=>`${v}%`}/>
            <Bar dataKey="rate" fill="#3b82f6" name="Detection Rate (%)"/>
          </BarChart>
        </ResponsiveContainer>
      )}

      {!isBatch && Array.isArray(result.results) && (
        <table className="w-full text-xs">
          <thead><tr className="text-gray-500 border-b dark:border-gray-700 text-left">
            <th className="pb-1">Iter</th><th className="pb-1">Verdict</th><th className="pb-1">Score</th><th className="pb-1">Detected</th><th className="pb-1">Catching Layers</th><th className="pb-1">Latency</th>
          </tr></thead>
          <tbody>
            {result.results.map((r: any, i: number) => (
              <tr key={i} className="border-b dark:border-gray-700/50">
                <td className="py-1">{i+1}</td>
                <td className="py-1"><span className={`px-1.5 py-0.5 rounded text-xs ${r.verdict==='MALICIOUS'?'bg-red-100 text-red-700':r.verdict==='SUSPICIOUS'?'bg-amber-100 text-amber-700':'bg-green-100 text-green-700'}`}>{r.verdict||'—'}</span></td>
                <td className="py-1 font-mono">{r.risk_score != null ? Number(r.risk_score).toFixed(1) : '—'}</td>
                <td className="py-1">{r.detected||r.replay_detected?<span className="text-green-600 font-medium">✓ Yes</span>:<span className="text-red-600">✗ No</span>}</td>
                <td className="py-1 text-gray-500">{(r.catching_layers||[]).join(', ').slice(0,60)}</td>
                <td className="py-1 text-gray-500">{r.latency_ms?.toFixed(0)}ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function Simulate() {
  const [iterations, setIterations] = useState(1)
  const [includeBenign, setIncludeBenign] = useState(true)
  const [results, setResults] = useState<Record<string, any>>({})

  const mutation = useMutation({
    mutationFn: ({ scenario }: { scenario: string }) => runSimulation(scenario as any, iterations, includeBenign),
    onSuccess: (data, vars) => {
      setResults(prev => ({ ...prev, [vars.scenario]: data }))
      toast.success(`${vars.scenario} simulation complete`)
    },
    onError: (err: any) => toast.error(`Simulation failed: ${err.message}`)
  })

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Attack Simulations</h1>
      <p className="text-sm text-gray-600 dark:text-gray-400">Each scenario generates real crafted emails sent through the live pipeline. Results show actual detections, risk scores, and which layer caught the attack.</p>

      <div className="flex flex-wrap gap-4 items-center bg-white dark:bg-gray-800 rounded-xl p-4 shadow">
        <div className="flex items-center gap-2">
          <label className="text-sm font-medium">Iterations:</label>
          <input type="range" min={1} max={10} value={iterations} onChange={e=>setIterations(+e.target.value)} className="w-24"/>
          <span className="text-sm font-bold w-4">{iterations}</span>
        </div>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={includeBenign} onChange={e=>setIncludeBenign(e.target.checked)} className="rounded"/>
          Include benign emails (measure false-positive rate)
        </label>
        <button onClick={() => mutation.mutate({ scenario: 'batch' })} disabled={mutation.isPending}
          className="ml-auto flex items-center gap-1.5 bg-gray-800 dark:bg-gray-200 text-white dark:text-gray-900 px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-60 hover:bg-gray-700">
          <Zap size={15}/> Run All (Batch)
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {SCENARIOS.map(s => (
          <div key={s.id} className={`border-l-4 rounded-xl p-4 shadow ${COLOR_MAP[s.color]} space-y-3`}>
            <div className="flex items-center gap-2 font-semibold">{s.icon} {s.label}</div>
            <p className="text-xs text-gray-600 dark:text-gray-400">{s.desc}</p>
            <button
              onClick={() => mutation.mutate({ scenario: s.id })}
              disabled={mutation.isPending}
              className="flex items-center gap-1.5 bg-white dark:bg-gray-700 border dark:border-gray-600 px-3 py-1.5 rounded-lg text-sm font-medium hover:shadow disabled:opacity-60 w-full justify-center"
            >
              <Play size={13}/> {mutation.isPending && mutation.variables?.scenario === s.id ? 'Running…' : 'Run'}
            </button>
          </div>
        ))}
        {/* Batch results card */}
        <div className="border-l-4 border-gray-400 bg-gray-50 dark:bg-gray-800 rounded-xl p-4 shadow space-y-3 col-span-full md:col-span-1">
          <div className="flex items-center gap-2 font-semibold"><Lock size={20}/> Batch Mode</div>
          <p className="text-xs text-gray-500">Runs all 5 scenarios × iterations and shows aggregate detection rates in a chart.</p>
        </div>
      </div>

      {/* Results */}
      {Object.entries(results).map(([scenario, result]) => (
        <div key={scenario}>
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2 capitalize">Results: {scenario}</h3>
          <ResultsPanel result={result} />
        </div>
      ))}
    </div>
  )
}
