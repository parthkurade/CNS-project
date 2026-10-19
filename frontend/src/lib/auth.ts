// ──────────────────────────────────────────────────────────────────────────────
// PhishShield – Auth state management
// ──────────────────────────────────────────────────────────────────────────────

const TOKEN_KEY = 'phishshield_token'
const ROLE_KEY = 'phishshield_role'
const EMAIL_KEY = 'phishshield_email'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string, role?: string, email?: string): void {
  localStorage.setItem(TOKEN_KEY, token)
  if (role) localStorage.setItem(ROLE_KEY, role)
  if (email) localStorage.setItem(EMAIL_KEY, email)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(ROLE_KEY)
  localStorage.removeItem(EMAIL_KEY)
}

export function isAuthenticated(): boolean {
  return Boolean(getToken())
}

export function getUserEmail(): string | null {
  return localStorage.getItem(EMAIL_KEY) || 'admin@phishshield.com'
}

export function getUserRole(): string | null {
  return localStorage.getItem(ROLE_KEY)
}
