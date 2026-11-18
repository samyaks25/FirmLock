import { useCallback, useEffect, useState } from 'react';
import { Globe, ShieldCheck, AlertTriangle, Clock, Plus, Search } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { AssetSummaryCard } from '../components/assets/AssetSummaryCard';
import { AssetTable, type Asset } from '../components/assets/AssetTable';
import { AddAssetModal } from '../components/assets/AddAssetModal';
import type { AssetResponse } from '../types/backend';

export function MyAssets() {
  const { businessId } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [scanning, setScanning] = useState<number | null>(null);

  const loadAssets = useCallback(async () => {
    if (!businessId) return;
    setLoading(true);
    setError(null);
    try {
      const list = await api.get<AssetResponse[]>(`/api/businesses/${businessId}/assets`);
      setAssets(
        list.map((a) => ({
          id: a.id,
          name: a.domain,
          url: `https://${a.domain}`,
          status: a.status === 'active' ? 'active' : 'warning',
          ssl: undefined,
          score: null,
          lastScanned: a.last_scanned_at
            ? new Date(a.last_scanned_at).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
            : 'Never',
        })),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load assets.');
    } finally {
      setLoading(false);
    }
  }, [businessId]);

  useEffect(() => {
    if (!businessId) return;
    (async () => {
      await loadAssets();
    })();
  }, [businessId, loadAssets]);

  const addWebsite = async (domain: string): Promise<void> => {
    if (!businessId) throw new Error('No business selected.');
    await api.post(`/api/businesses/${businessId}/assets`, { domain, authorization_confirmed: true });
    await loadAssets();
  };

  const handleScan = async (id: number) => {
    setScanning(id);
    setError(null);
    try {
      await api.post(`/api/assets/${id}/scan`);
      await loadAssets();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan.');
    } finally {
      setScanning(null);
    }
  };

  const total = assets.length;
  const active = assets.filter((a) => a.status === 'active').length;
  const expiring = assets.filter((a) => a.ssl?.includes('Expiring')).length;
  const notScanned = assets.filter((a) => a.lastScanned.startsWith('Never')).length;

  if (!businessId) {
    return (
      <div className="min-h-screen bg-[#F4F7FA]">
        <div className="p-4 md:p-6">
          <h1 className="text-2xl font-semibold text-[#101B2C]">My Assets</h1>
          <p className="text-sm text-[#718096] mb-6">No business selected. Please select or create a business to manage assets.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="p-4 md:p-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">My Assets</h1>
              <p className="text-sm text-[#718096]">Manage and monitor your registered digital assets.</p>
            </div>
            <button onClick={() => setModalOpen(true)} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90">
              <Plus className="w-4 h-4" /> Add Website
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <AssetSummaryCard label="Total Websites" value={total} icon={Globe} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <AssetSummaryCard label="Active Websites" value={active} icon={ShieldCheck} iconBgColor="bg-[#22C55E]/10" iconColor="text-[#22C55E]" />
            <AssetSummaryCard label="SSL Certificates Expiring Soon" value={expiring} icon={AlertTriangle} iconBgColor="bg-[#F2B84B]/10" iconColor="text-[#F2B84B]" />
            <AssetSummaryCard label="Websites Not Yet Scanned" value={notScanned} icon={Clock} iconBgColor="bg-[#718096]/10" iconColor="text-[#718096]" />
          </div>

          <div className="mb-4">
            <div className="relative max-w-md">
              <Search className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search domains..." className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]" />
            </div>
          </div>

          {loading && <p className="text-[#718096] mb-4">Loading assets...</p>}
          {error && <p className="text-[#EF4444] mb-4">{error}</p>}
          {assets.length === 0 && !loading && !error && <p className="text-[#718096] mb-4">No assets registered yet. Add a website to start monitoring.</p>}

          <AssetTable assets={assets} search={search} onView={setSelected} onScan={handleScan} />

          {selected && (
            <div className="mt-4 bg-white rounded-xl border border-[#E2E8F0] p-4">
              <h3 className="font-semibold text-[#101B2C] mb-2">Website Details</h3>
              <p className="text-sm text-[#718096]">{selected.name} · {selected.url}</p>
              <p className="text-sm text-[#718096]">Status: {selected.status} | Score: {selected.score === null || selected.score === undefined ? 'Not scored' : `${selected.score}/100`} | SSL: {selected.ssl ?? 'Not available'}</p>
              <button onClick={() => setSelected(null)} className="mt-2 text-sm text-[#36D6C4] hover:underline">Close</button>
            </div>
          )}

          {scanning !== null && <p className="mt-4 text-sm text-[#718096]">Scan started for selected asset.</p>}

      </div>

      <AddAssetModal open={modalOpen} onClose={() => setModalOpen(false)} onAdd={addWebsite} />
    </div>
  );
}
