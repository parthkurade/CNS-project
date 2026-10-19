// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Attack Simulation page
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Swords, Play, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, ArrowRight, Activity } from 'lucide-react'
import toast from 'react-hot-toast'
import { runSimulation } from '../lib/api'
import type { SimulationResult, SimulationScenario } from '../types'

interface ScenarioInfo {
  id: SimulationScenario
  title: string
  description: string
  threatModel: string
  expectedOutcome: string
}

const SCENARIOS: ScenarioInfo[] = [
  {
    id: 'phishing',
    title: 'Credential Harvesting Phishing',
    description: 'Generates urgent deceptive emails containing spoofed branding and credential-stealing links.',
    threatModel: 'Social engineering and credential extraction',
    expectedOutcome: 'High risk score, caught by URL Analyzer & ML Classifier',
  },
  {
    id: 'spoofing',
    title: 'Sender Identity Spoofing',
    description: 'Forges From headers imitating executive addresses while sending from unauthorized IP.',
    threatModel: 'CEO fraud, Business Email Compromise (BEC)',
    expectedOutcome: 'SPF/DMARC alignment failure, caught by SPF & Spoofing Detector',
  },
  {
    id: 'tampering',
    title: 'In-Transit Message Tampering',
    description: 'Generates a legitimately signed message, then alters body text in flight before delivery.',
    threatModel: 'Man-in-the-middle message modification',
    expectedOutcome: 'SHA-256 and Ed25519/RSA signature check fail, hard override to 100',
  },
  {
    id: 'replay',
    title: 'Replay Attack',
    description: 'Captures and resends an already-delivered signed message reusing the previous nonce and timestamp.',
    threatModel: 'Replay of authentic tokens and commands',
    expectedOutcome: 'Nonce cache collision caught, rejected as REPLAY_ATTACK',
  },
  {
    id: 'mitm',
    title: 'Untrusted Gateway / MitM',
    description: 'Sends email claiming valid gateway signature with forged or revoked key ID.',
    threatModel: 'Untrusted partner gateway or key forgery',
    expectedOutcome: 'Unregistered key lookup failure, signature check rejected',
  },
]

export default function Simulate() {
  const [selectedScenario, setSelectedScenario] = useState<SimulationScenario>('phishing')
  const [iterations, setIterations] = useState<number>(3)
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null)

  const mutation = useMutation({
    mutationFn: () => runSimulation(selectedScenario, iterations, true),
    onSuccess: (data) => {
      setSimulationResult(data)
      toast.success(`Simulation completed: ${data.detection_rate}% detection rate`)
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Simulation execution failed')
    },
  })

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <Swords className="text-indigo-600 dark:text-indigo-400" /> Attack Simulation Engine
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Benchmark and validate PhishShield’s defensive pipeline against realistic synthetic cyber threats
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scenario selection */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">Select Threat Scenario</h2>
          <div className="space-y-3">
            {SCENARIOS.map((scenario) => {
              const isSelected = selectedScenario === scenario.id
              return (
                <div
                  key={scenario.id}
                  onClick={() => setSelectedScenario(scenario.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-indigo-50/70 dark:bg-indigo-950/40 border-indigo-600 dark:border-indigo-500 shadow-sm'
                      : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-3 h-3 rounded-full ${isSelected ? 'bg-indigo-600' : 'bg-gray-300 dark:bg-gray-600'}`}
                        />
                        <h3 className="font-bold text-sm text-gray-900 dark:text-white">{scenario.title}</h3>
                      </div>
                      <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 pl-5">{scenario.description}</p>
                      <div className="mt-2 pl-5 flex flex-wrap gap-2 text-xs">
                        <span className="text-gray-400">Target: {scenario.threatModel}</span>
                        <span className="text-indigo-600 dark:text-indigo-400 font-medium">
                          Expected: {scenario.expectedOutcome}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Control and execution panel */}
        <div className="space-y-6">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700 space-y-4">
            <h3 className="font-bold text-sm text-gray-900 dark:text-white">Execution Parameters</h3>

            <div>
              <div className="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
                <span>Iterations</span>
                <span className="font-bold text-indigo-600 dark:text-indigo-400">{iterations} emails</span>
              </div>
              <input
                type="range"
                min={1}
                max={10}
                value={iterations}
                onChange={(e) => setIterations(Number(e.target.value))}
                className="w-full accent-indigo-600"
              />
            </div>

            <button
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition shadow-sm"
            >
              {mutation.isPending ? (
                <>
                  <Cpu className="animate-spin" size={16} /> Running Pipeline...
                </>
              ) : (
                <>
                  <Play size={16} /> Run {selectedScenario} Simulation
                </>
              )}
            </button>
          </div>

          {/* Quick stats on last simulation */}
          {simulationResult && (
            <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700 space-y-4">
              <h3 className="font-bold text-sm text-gray-900 dark:text-white flex items-center gap-1.5">
                <Activity size={16} className="text-green-500" /> Simulation Results
              </h3>

              <div className="grid grid-cols-2 gap-3 text-center">
                <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <p className="text-xs text-gray-500">Detection Rate</p>
                  <p className="text-2xl font-bold text-indigo-600 dark:text-indigo-400">
                    {simulationResult.detection_rate}%
                  </p>
                </div>
                <div className="p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                  <p className="text-xs text-gray-500">Avg Latency</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {simulationResult.avg_latency_ms ? Math.round(simulationResult.avg_latency_ms) : 0}ms
                  </p>
                </div>
              </div>

              {simulationResult.summary && (
                <div className="text-xs text-gray-600 dark:text-gray-300 space-y-1 pt-2 border-t border-gray-100 dark:border-gray-700">
                  <p>
                    <span className="font-semibold">Simulated:</span> {simulationResult.scenario}
                  </p>
                  <p>
                    <span className="font-semibold">Samples:</span> {simulationResult.iterations}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
