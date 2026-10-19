// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Layout component (sidebar + top bar)
// ──────────────────────────────────────────────────────────────────────────────
import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Inbox,
  ShieldAlert,
  ScrollText,
  Swords,
  BrainCircuit,
  KeyRound,
  Settings,
  Shield,
  Menu,
  X,
  Sun,
  Moon,
  LogOut,
} from 'lucide-react'
import { clearToken, getUserEmail } from '../lib/auth'

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard',      icon: <LayoutDashboard size={18} /> },
  { to: '/inbox',     label: 'Inbox',          icon: <Inbox size={18} /> },
  { to: '/quarantine',label: 'Quarantine',     icon: <ShieldAlert size={18} /> },
  { to: '/logs',      label: 'Security Logs',  icon: <ScrollText size={18} /> },
  { to: '/simulate',  label: 'Simulate Attacks',icon: <Swords size={18} /> },
  { to: '/model',     label: 'ML Model',       icon: <BrainCircuit size={18} /> },
  { to: '/keys',      label: 'Key Manager',    icon: <KeyRound size={18} /> },
  { to: '/settings',  label: 'Settings',       icon: <Settings size={18} /> },
]

interface LayoutProps {
  children: React.ReactNode
  darkMode: boolean
  onToggleDark: () => void
}

export default function Layout({ children, darkMode, onToggleDark }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const navigate = useNavigate()
  const email = getUserEmail() ?? 'user@phishshield'

  function handleLogout() {
    clearToken()
    navigate('/login')
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
      isActive
        ? 'bg-indigo-700 text-white'
        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
    }`

  const Sidebar = () => (
    <div className="flex flex-col h-full bg-gray-900 text-white w-56">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-5 border-b border-gray-700">
        <Shield size={28} className="text-indigo-400" />
        <span className="font-bold text-lg tracking-tight">PhishShield</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={navLinkClass}
            onClick={() => setSidebarOpen(false)}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Bottom user strip */}
      <div className="px-4 py-3 border-t border-gray-700 text-xs text-gray-400 truncate">
        {email}
      </div>
    </div>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-gray-900">
      {/* ── Desktop sidebar ─────────────────────────────────────── */}
      <aside className="hidden md:flex flex-shrink-0">
        <Sidebar />
      </aside>

      {/* ── Mobile sidebar overlay ───────────────────────────────── */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 flex md:hidden">
          <div
            className="fixed inset-0 bg-black/50"
            onClick={() => setSidebarOpen(false)}
          />
          <aside className="relative z-50 flex flex-shrink-0">
            <Sidebar />
          </aside>
          <button
            className="absolute top-4 right-4 z-50 text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={24} />
          </button>
        </div>
      )}

      {/* ── Main area ───────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
          {/* Hamburger (mobile only) */}
          <button
            className="md:hidden p-1 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu size={22} />
          </button>

          <div className="hidden md:block" />

          <div className="flex items-center gap-3">
            {/* Dark mode toggle */}
            <button
              onClick={onToggleDark}
              className="p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            </button>

            {/* User email */}
            <span className="hidden sm:block text-sm text-gray-600 dark:text-gray-300">
              {email}
            </span>

            {/* Logout */}
            <button
              onClick={handleLogout}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 transition-colors"
            >
              <LogOut size={16} />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
