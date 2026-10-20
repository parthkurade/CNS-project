// PhishShield – ML Model metrics page
import { useQuery, useMutation } from '@tanstack/react-query'
import { getModelMetrics, retrainModel } from '../lib/api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { RefreshCw, Brain } from 'lucide-react'
import toast from 'react-hot-toast'

function MetricCard({ label, value }: { label: string; value: number }) {
  const pct = (value * 100).toFixed(2)
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow text-center">
      <div className="text-3xl font-bold text-blue-600">{pct}%</div>
      <div className="text-sm text-gray-500 mt-1">{label}</div>
    </div>
  )
}

export default function MLModel() {
  const { data: metrics, isLoading, error } = useQuery({ queryKey: ['metrics'], queryFn: getModelMetrics })
  const retrain = useMutation({ mutationFn: retrainModel, onSuccess: () => toast.success('Retraining started in background'), onError: () => toast.error('Retrain failed') })

  if (isLoading) return <div className="text-center py-20 text-gray-500">Loading model metrics…</div>
  if (error || !metrics) return (
    <div className="text-center py-20 space-y-3">
      <Brain size={48} className="mx-auto text-gray-400"/>
      <p className="text-gray-500">Model not trained yet. Run <code className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">python -m backend.ml.train</code> first.</p>
    </div>
  )

  const featureData = (metrics.top_features || []).slice(0, 15).map((f: any) => ({ name: f.feature?.slice(0,20), weight: Math.abs(f.weight) }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">ML Phishing Detection Model</h1>
        <button onClick={() => retrain.mutate()} disabled={retrain.isPending}
          className="flex items-center gap-1.5 text-sm bg-blue-600 text-white px-3 py-1.5 rounded-lg hover:bg-blue-700 disabled:opacity-60">
          <RefreshCw size={14}/> Retrain
        </button>
      </div>

      {/* Dataset info */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded-xl p-4 text-sm text-blue-800 dark:text-blue-300">
        <strong>Dataset:</strong> {metrics.dataset_source || 'SpamAssassin'} · {((metrics as any).train_samples ?? metrics.training_samples)?.toLocaleString()} train / {metrics.test_samples?.toLocaleString()} test samples · Trained: {metrics.trained_at ? new Date(metrics.trained_at).toLocaleString() : '—'}
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard label="Accuracy" value={metrics.accuracy} />
        <MetricCard label="Precision" value={metrics.precision} />
        <MetricCard label="Recall" value={metrics.recall} />
        <MetricCard label="F1 Score" value={metrics.f1} />
        <MetricCard label="ROC-AUC" value={metrics.roc_auc} />
      </div>

      {/* Confusion matrix */}
      {metrics.confusion_matrix && (
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Confusion Matrix</h2>
          <div className="grid grid-cols-2 gap-2 max-w-xs">
            {['True Negative', 'False Positive', 'False Negative', 'True Positive'].map((label, i) => {
              const row = Math.floor(i / 2); const col = i % 2
              const val = metrics.confusion_matrix[row][col]
              const isGood = (i === 0 || i === 3)
              return (
                <div key={i} className={`rounded-lg p-4 text-center ${isGood ? 'bg-green-100 dark:bg-green-900/30' : 'bg-red-100 dark:bg-red-900/30'}`}>
                  <div className="text-2xl font-bold">{val}</div>
                  <div className="text-xs text-gray-500 mt-1">{label}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Top features */}
      {featureData.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow">
          <h2 className="font-semibold text-gray-700 dark:text-gray-200 mb-4">Top Phishing Indicators (Feature Importance)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={featureData} layout="vertical">
              <XAxis type="number" tick={{fontSize:11}}/>
              <YAxis type="category" dataKey="name" width={140} tick={{fontSize:10}}/>
              <Tooltip/>
              <Bar dataKey="weight" fill="#ef4444" name="Importance"/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
