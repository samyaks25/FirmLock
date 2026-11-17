import { useState } from 'react';
import { Lock, Mail, AlertCircle } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { api } from '../api/client';
import type { UserLogin } from '../types/backend';

export function Login() {
  const { login, loadBusinesses } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const payload: UserLogin = { email, password };
      const token = await api.post<{ access_token: string; expires_in: number }>('/api/auth/login', payload);
      const user = await api.get<{ id: number; email: string; full_name: string | null; is_active: boolean; created_at: string; updated_at: string }>('/api/auth/me');
      login(token.access_token, user);
      try {
        await loadBusinesses();
      } catch {
        // Business list unavailable; onboarding screen handles recovery.
      }
      window.location.href = '/';
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F4F7FA] flex items-center justify-center">
      <div className="w-full max-w-md p-6">
        <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 md:p-10 shadow-sm">
          <div className="flex items-center gap-2 mb-6">
            <Lock className="w-6 h-6 text-[#36D6C4]" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-[#101B2C]">Sign in to FirmLock</h2>
          </div>
          <p className="text-sm text-[#718096] mb-6">Enter your email and password to access your security dashboard.</p>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-[#FEF2F2] border border-[#EF4444]/30 text-sm text-[#EF4444] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-[#172536] mb-1">Email address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] disabled:opacity-60"
                  disabled={submitting}
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-[#172536] mb-1">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;&#8222;"
                  className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] disabled:opacity-60"
                  disabled={submitting}
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full px-4 py-2 rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium disabled:opacity-50 hover:opacity-90 disabled:hover:opacity-100 transition-colors"
            >
              {submitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>

          <p className="mt-6 text-sm text-[#718096] text-center">
            Don't have an account?{' '}
            <a href="/register" className="text-[#36D6C4] hover:underline font-medium">Create an account</a>
          </p>
        </div>
        <p className="text-center text-xs text-[#718096] mt-4">FirmLock &mdash; Security Monitoring</p>
      </div>
    </div>
  );
}
