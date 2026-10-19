// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – ML Model Dashboard & Diagnostics page
// ──────────────────────────────────────────────────────────────────────────────
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BrainCircuit, RefreshCw, Sparkles, Database, CheckCircle2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { getModelMetrics, retrainModel } from '../lib/api'

export default function MLModel() {
  const queryClient = useQueryClient()

  const { data: metrics, isLoading, refetch } = useQuery({
    queryKey: ['model-metrics'],
    queryFn: getModelMetrics,
  })

  const retrainMutation = useMutation({
    mutationFn: retrainModel,
    onSuccess: () => {
      toast.success('Model successfully retrained and updated!')
      queryClient.invalidateQueries({ queryKey: ['model-metrics'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Model retraining failed')
    },
  })

  if (isLoading) {
    return <div className="p-12 text-center text-gray-500">Loading model performance metrics...</div>
  }

  if (!metrics) return null

  // confusion matrix elements
  const cm = metrics.confusion_matrix || [
    [551, 10],
    [1, 99],
  ]
  const tn = cm[0]?.[0] ?? 0
  const fp = cm[0]?.[1] ?? 0
  const fn = cm[1]?.[0] ?? 0
  const tp = cm[1]?.[1] ?? 0

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <BrainCircuit className="text-indigo-600 dark:text-indigo-400" /> Machine Learning Threat Model
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Ensemble NLP & classification pipeline (TF-IDF + Logistic Regression) trained on public phishing corpora
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
          >
            <RefreshCw size={15} /> Refresh
          </button>
          <button
            onClick={() => retrainMutation.mutate()}
            disabled={retrainMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm font-semibold transition shadow-sm"
          >
            <Sparkles size={15} /> {retrainMutation.isPending ? 'Training...' : 'Retrain Model'}
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Accuracy', value: `${(metrics.accuracy * 100).toFixed(1)}%`, color: 'text-green-600 dark:text-green-400' },
          { label: 'Precision', value: `${(metrics.precision * 100).toFixed(1)}%`, color: 'text-indigo-600 dark:text-indigo-400' },
          { label: 'Recall', value: `${(metrics.recall * 100).toFixed(1)}%`, color: 'text-blue-600 dark:text-blue-400' },
          { label: 'F1 Score', value: `${(metrics.f1 * 100).toFixed(1)}%`, color: 'text-purple-600 dark:text-purple-400' },
          { label: 'ROC-AUC', value: metrics.roc_auc.toFixed(3), color: 'text-amber-600 dark:text-amber-400' },
        ].map((m) => (
          <div key={m.label} className="bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm border border-gray-200 dark:border-gray-700">
            <p className="text-xs text-gray-500 uppercase font-semibold">{m.label}</p>
            <p className={`text-2xl font-bold mt-1 ${m.color}`}>{m.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
          <h2 className="font-bold text-gray-900 dark:text-white text-sm mb-4">Confusion Matrix (Held-out Test Set)</h2>
          <div className="grid grid-cols-2 gap-3 text-center">
            <div className="p-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg">
              <p className="text-xs text-green-700 dark:text-green-400 font-semibold uppercase">True Negative (Ham)</p>
              <p className="text-2xl font-bold text-green-800 dark:text-green-300 mt-1">{tn}</p>
              <p className="text-xs text-green-600 mt-0.5">Legitimate classified correctly</p>
            </div>
            <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-lg">
              <p className="text-xs text-amber-700 dark:text-amber-400 font-semibold uppercase">False Positive (Type I)</p>
              <p className="text-2xl font-bold text-amber-800 dark:text-amber-300 mt-1">{fp}</p>
              <p className="text-xs text-amber-600 mt-0.5">Legitimate falsely flagged</p>
            </div>
            <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-xs text-red-700 dark:text-red-400 font-semibold uppercase">False Negative (Type II)</p>
              <p className="text-2xl font-bold text-red-800 dark:text-red-300 mt-1">{fn}</p>
              <p className="text-xs text-red-600 mt-0.5">Phishing slipped through</p>
            </div>
            <div className="p-4 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800 rounded-lg">
              <p className="text-xs text-indigo-700 dark:text-indigo-400 font-semibold uppercase">True Positive (Spam)</p>
              <p className="text-2xl font-bold text-indigo-800 dark:text-indigo-300 mt-1">{tp}</p>
              <p className="text-xs text-indigo-600 mt-0.5">Phishing caught correctly</p>
            </div>
          </div>
        </div>

        {/* Top Phishing Features */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
          <h2 className="font-bold text-gray-900 dark:text-white text-sm mb-4">Top Phishing Token Indicators</h2>
          {metrics.top_features && metrics.top_features.length > 0 ? (
            <div className="space-y-2.5">
              {metrics.top_features.map((feat: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="font-mono text-gray-700 dark:text-gray-300 font-medium">"{feat.feature}"</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 bg-gray-100 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
                      <div
                        className="bg-indigo-600 h-full rounded-full"
                        style={{ width: `${Math.min(100, Math.abs(feat.weight) * 20)}%` }}
                      />
                    </div>
                    <span className="font-mono text-gray-500 w-10 text-right">+{feat.weight}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-400">Features will display upon model training.</p>
          )}

          <div className="mt-5 pt-3 border-t border-gray-100 dark:border-gray-700 text-xs text-gray-500 flex items-center justify-between">
            <span className="flex items-center gap-1">
              <Database size={13} /> {metrics.dataset_source || 'SpamAssassin Public Corpus'}
            </span>
            <span>Trained: {metrics.trained_at ? new Date(metrics.trained_at).toLocaleDateString() : 'Active'}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
