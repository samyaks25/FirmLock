import { useState } from 'react';
import { Mail, User, Lock, AlertCircle, ArrowLeft } from 'lucide-react';
import { api } from '../api/client';
import type { UserCreate } from '../types/backend';

export function Register() {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const payload: UserCreate = { email, password, full_name: fullName || undefined };
      await api.post<{ id: number; email: string }>('/api/auth/register', payload);
      window.location.href = '/login?registered=1';
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F4F7FA] flex items-center justify-center">
      <div className="w-full max-w-md p-6">
        <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 md:p-10 shadow-sm">
          <div className="flex items-center gap-2 mb-2">
            <ArrowLeft className="w-4 h-4 text-[#36D6C4] cursor-pointer hover:opacity-80" aria-hidden="true" onClick={() => { window.location.href = '/login'; }} />
            <span className="text-sm text-[#718096]">Back to sign in</span>
          </div>
          <div className="flex items-center gap-2 mt-2 mb-6">
            <img
              src="/firmlock-logo.png"
              alt="FirmLock"
              className="w-6 h-6"
            />
            <h2 className="text-xl font-semibold text-[#101B2C]">Create your FirmLock account</h2>
          </div>
          <p className="text-sm text-[#718096] mb-6">Join your organisation and start monitoring your websites.</p>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-[#FEF2F2] border border-[#EF4444]/30 text-sm text-[#EF4444] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-[#172536] mb-1">Full name</label>
              <div className="relative">
                <User className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="John Doe"
                  className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] disabled:opacity-60"
                  disabled={submitting}
                />
              </div>
            </div>
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
              <p className="text-xs text-[#718096] mb-1">Must be at least 12 characters</p>
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
              {submitting ? 'Creating account...' : 'Create account'}
            </button>
          </form>

          <p className="mt-6 text-sm text-[#718096] text-center">
            Already have an account?{' '}
            <a href="/login" className="text-[#36D6C4] hover:underline font-medium">Sign in</a>
          </p>
        </div>
      </div>
    </div>
  );
}
