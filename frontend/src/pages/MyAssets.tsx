import { useState } from 'react';
import { Globe, ShieldCheck, AlertTriangle, Clock, Plus, Search } from 'lucide-react';
import { AssetSummaryCard } from '../components/assets/AssetSummaryCard';
import { AssetTable, type Asset } from '../components/assets/AssetTable';
import { AddAssetModal } from '../components/assets/AddAssetModal';

const initialAssets: Asset[] = [
  { id: 1, name: 'Primary Website', url: 'https://www.company.com', status: 'active', ssl: 'Valid (demo)', score: 94, lastScanned: '2 hours ago (demo)' },
  { id: 2, name: 'API Gateway', url: 'https://api.company.com', status: 'warning', ssl: 'Expiring soon (demo)', score: 72, lastScanned: '4 hours ago (demo)' },
  { id: 3, name: 'Customer Portal', url: 'https://portal.company.com', status: 'critical', ssl: 'Valid (demo)', score: 45, lastScanned: '1 hour ago (demo)' },
  { id: 4, name: 'Documentation Site', url: 'https://docs.company.com', status: 'pending', ssl: 'Not yet checked (demo)', score: 0, lastScanned: 'Never (demo)' },
];

export function MyAssets() {
  const [assets, setAssets] = useState<Asset[]>(initialAssets);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [loading] = useState(false);
  const [error] = useState<string | null>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [scanning, setScanning] = useState<number | null>(null);

  const addWebsite = (url: string) => {
    const newAsset: Asset = {
      id: Date.now(),
      name: new URL(url).hostname,
      url,
      status: 'pending',
      ssl: 'Not yet checked (demo)',
      score: 0,
      lastScanned: 'Never (demo)',
    };
    setAssets((prev) => [newAsset, ...prev]);
  };

  const handleScan = (id: number) => {
    setScanning(id);
    setTimeout(() => setScanning(null), 1200);
  };

  const total = assets.length;
  const active = assets.filter((a) => a.status === 'active').length;
  const expiring = assets.filter((a) => a.ssl.includes('Expiring')).length;
  const notScanned = assets.filter((a) => a.lastScanned.startsWith('Never')).length;

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="md:ml-64">
        <div className="p-4 md:p-6 md:ml-20 transition-all duration-300">
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
          {assets.length === 0 && !loading && <p className="text-[#718096] mb-4">No assets registered yet.</p>}

          <AssetTable assets={assets} search={search} onView={setSelected} onScan={handleScan} />

          {selected && (
            <div className="mt-4 bg-white rounded-xl border border-[#E2E8F0] p-4">
              <h3 className="font-semibold text-[#101B2C] mb-2">Website Details (demo)</h3>
              <p className="text-sm text-[#718096]">{selected.name} � {selected.url}</p>
              <p className="text-sm text-[#718096]">Status: {selected.status} | Score: {selected.score}/100 | SSL: {selected.ssl}</p>
              <button onClick={() => setSelected(null)} className="mt-2 text-sm text-[#36D6C4] hover:underline">Close</button>
            </div>
          )}

          {scanning !== null && <p className="mt-4 text-sm text-[#718096]">Initial scan queued (demo) � no actual scan performed.</p>}

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">All data shown is demonstration/mock data for preview purposes.</p>
        </div>
      </div>

      <AddAssetModal open={modalOpen} onClose={() => setModalOpen(false)} onAdd={addWebsite} />
    </div>
  );
}
