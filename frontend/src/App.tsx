// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – App root (routing + dark mode)
// ──────────────────────────────────────────────────────────────────────────────
import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'

import { isAuthenticated } from './lib/auth'
import Layout from './components/Layout'

import Login       from './pages/Login'
import Dashboard   from './pages/Dashboard'
import Inbox       from './pages/Inbox'
import Quarantine  from './pages/Quarantine'
import EmailDetail from './pages/EmailDetail'
import Logs        from './pages/Logs'
import Simulate    from './pages/Simulate'
import MLModel     from './pages/MLModel'
import Keys        from './pages/Keys'
import SettingsPage from './pages/Settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
})

// ── Protected route wrapper ───────────────────────────────────────────────────
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const stored = localStorage.getItem('phishshield_dark')
    if (stored !== null) return stored === 'true'
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  useEffect(() => {
    const root = document.documentElement
    if (darkMode) {
      root.classList.add('dark')
    } else {
      root.classList.remove('dark')
    }
    localStorage.setItem('phishshield_dark', String(darkMode))
  }, [darkMode])

  function toggleDark() {
    setDarkMode((prev) => !prev)
  }

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            className: 'dark:bg-gray-800 dark:text-white',
          }}
        />
        <Routes>
          {/* Public */}
          <Route path="/login" element={<Login />} />

          {/* Protected – wrapped in Layout */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Dashboard />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/inbox"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Inbox />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/quarantine"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Quarantine />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/email/:id"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <EmailDetail />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/logs"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Logs />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/simulate"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Simulate />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/model"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <MLModel />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/keys"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <Keys />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Layout darkMode={darkMode} onToggleDark={toggleDark}>
                  <SettingsPage />
                </Layout>
              </ProtectedRoute>
            }
          />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
