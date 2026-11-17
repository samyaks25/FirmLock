import { useState } from 'react';
import { ArrowLeft, Building, Plus } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import type { BusinessCreate } from '../types/backend';

export function Onboarding() {
  const { businesses, createBusiness, selectBusiness } = useAuth();
  const [mode, setMode] = useState<'select' | 'create'>(businesses.length === 0 ? 'create' : 'select');
  const [name, setName] = useState('');
  const [industry, setIndustry] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSelect = async (id: number) => {
    setError('');
    try {
      await selectBusiness(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to select business.');
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) { setError('Business name is required.'); return; }
    setSubmitting(true);
    try {
      const payload: BusinessCreate = { name: name.trim(), industry: industry.trim() || undefined };
      await createBusiness(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create business.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F4F7FA] md:ml-64">
      <div className="p-4 md:p-6 md:ml-20">
        <div className="max-w-md mx-auto">
          <div className="flex items-center gap-2 mb-6">
            <Building className="w-6 h-6 text-[#36D6C4]" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-[#101B2C]">Set up your business</h2>
          </div>
          <p className="text-sm text-[#718096] mb-6">Select or create the business you want to monitor.</p>

          {mode === 'select' && (
            <>
              <h3 className="text-sm font-medium text-[#172536] mb-3">Your businesses</h3>
              <div className="space-y-2 mb-6">
                {businesses.map((b) => (
                  <button
                    key={b.id}
                    onClick={() => handleSelect(b.id)}
                    className="w-full flex items-center justify-between px-4 py-3 rounded-lg border border-[#E2E8F0] bg-white hover:bg-[#F4F7FA] text-left"
                  >
                    <span className="font-medium text-[#101B2C]">{b.name}</span>
                    <span className="text-xs text-[#718096]">{b.industry ?? '-'}</span>
                  </button>
                ))}
              </div>
              <button
                onClick={() => setMode('create')}
                className="inline-flex items-center gap-2 text-sm text-[#36D6C4] hover:underline"
              >
                <Plus className="w-4 h-4" /> Create another business
              </button>
            </>
          )}

          {mode === 'create' && (
            <>
              <button
                onClick={() => setMode('select')}
                className="mb-4 inline-flex items-center gap-2 text-sm text-[#718096] hover:text-[#36D6C4]"
              >
                <ArrowLeft className="w-4 h-4" /> Back to selection
              </button>
              <form onSubmit={handleCreate} className="space-y-4 bg-white p-6 rounded-xl border border-[#E2E8F0] shadow-sm">
                <div>
                  <label className="block text-sm font-medium text-[#172536] mb-1">Business name</label>
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Acme Corp"
                    className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] disabled:opacity-60"
                    disabled={submitting}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-[#172536] mb-1">Industry (optional)</label>
                  <input
                    value={industry}
                    onChange={(e) => setIndustry(e.target.value)}
                    placeholder="Technology"
                    className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] disabled:opacity-60"
                    disabled={submitting}
                  />
                </div>
                {error && <p className="text-sm text-[#EF4444]">{error}</p>}
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full px-4 py-2 rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium disabled:opacity-50 hover:opacity-90 disabled:hover:opacity-100 transition-colors"
                >
                  {submitting ? 'Creating...' : 'Create business'}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
