import { useCallback, useEffect, useRef, useState } from 'react';
import { ShieldCheck, AlertTriangle, AlertCircle, CheckCircle2 } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { ScanSummaryCard } from '../components/scans/ScanSummaryCard';
import { ScanHistoryTable, type Scan, StatusFilterBar } from '../components/scans/ScanHistoryTable';
import { StartScanModal } from '../components/scans/StartScanModal';
import type { Finding } from '../components/scans/FindingCard';
import { ScanDetails } from '../components/scans/ScanDetails';
import type { AssetResponse, RiskAssessmentResponse } from '../types/backend';

interface AssetOption { id: number; name: string; url: string; }

interface ScanView extends Scan {
  assetId: number;
  findings: Finding[];
}

function normalizeStatus(status: string): ScanView['status'] {
  if (status === 'completed') return 'Completed';
  if (status === 'failed') return 'Failed';
  return 'In Progress';
}

function normalizeSeverity(severity: string): Finding['severity'] {
  const cap = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
  return (['Critical', 'High', 'Medium', 'Low', 'Info'].includes(cap) ? cap : 'Info') as Finding['severity'];
}

export function SecurityScans() {
  const { businessId } = useAuth();
  const [assets, setAssets] = useState<AssetOption[]>([]);
  const [scans, setScans] = useState<ScanView[]>([]);
  const [risks, setRisks] = useState<Record<number, RiskAssessmentResponse>>({});
  const [modalOpen, setModalOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanView | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const mounted = useRef(true);

  const loadAssets = useCallback(async () => {
    if (!businessId) return;
    setLoading(true);
    try {
      const list = await api.get<AssetResponse[]>(`/api/businesses/${businessId}/assets`);
      setAssets(list.map((a) => ({ id: a.id, name: a.domain, url: `https://${a.domain}` })));
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

  useEffect(() => {
    return () => { mounted.current = false; };
  }, []);

  const handleStart = async (assetId: number) => {
    setError(null);
    try {
      const accepted = await api.post<{ scan_id: number; asset_id: number; status: string }>(`/api/assets/${assetId}/scan`);
      const scanId = accepted.scan_id;
      const asset = assets.find((a) => a.id === assetId);
      const domain = asset?.name ?? '';

      const entry: ScanView = {
        id: String(scanId),
        assetId: scanId,
        website: domain,
        domain,
        date: new Date().toISOString().slice(0, 10),
        status: 'In Progress',
        score: null,
        issues: 0,
        findings: [],
      };
      setScans((prev) => [entry, ...prev]);

      try {
        const scan = await api.pollScan(scanId, (status) => {
          if (!mounted.current) return;
          setScans((prev) => prev.map((s) => s.id === String(scanId) ? { ...s, status: normalizeStatus(status) } : s));
        });

        if (!mounted.current) return;

        const risk = await api.get<RiskAssessmentResponse>(`/api/scans/${scanId}/risk`);
        if (!mounted.current) return;

        setRisks((prev) => ({ ...prev, [scanId]: risk }));
        const findings: Finding[] = scan.findings.map((f) => ({
          id: f.id,
          title: f.title,
          website: domain,
          severity: normalizeSeverity(f.severity),
          description: f.description,
          remediation: f.recommendation,
        }));
        setScans((prev) => prev.map((s) => s.id === String(scanId)
          ? {
            ...s,
            status: normalizeStatus(scan.status),
            score: scan.security_score ?? null,
            issues: scan.findings.length,
            findings,
          }
          : s));
      } catch {
        if (!mounted.current) return;
        setScans((prev) => prev.map((s) => s.id === String(scanId) ? { ...s, status: 'Failed' } : s));
        setError('Scan failed or could not be completed.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan.');
    }
  };

  const total = scans.length;
  const completed = scans.filter((s) => s.status === 'Completed').length;
  const inProgress = scans.filter((s) => s.status === 'In Progress').length;
  const failed = scans.filter((s) => s.status === 'Failed').length;

  const selectedRisk = selectedScan ? risks[selectedScan.assetId] ?? null : null;

  if (!businessId) {
    return (
      <div className="min-h-screen bg-[#F4F7FA] md:ml-64">
        <div className="p-4 md:p-6 md:ml-20">
          <h1 className="text-2xl font-semibold text-[#101B2C]">Security Scans</h1>
          <p className="text-sm text-[#718096] mb-6">No business selected. Please select or create a business to run scans.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="md:ml-64">
        <div className="p-4 md:p-6 md:ml-20 transition-all duration-300">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">Security Scans</h1>
              <p className="text-sm text-[#718096]">Monitor website security assessments and findings.</p>
            </div>
            <button onClick={() => setModalOpen(true)} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90">
              <ShieldCheck className="w-4 h-4" /> Start New Scan
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <ScanSummaryCard label="Total Scans" value={total} icon={ShieldCheck} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ScanSummaryCard label="Completed" value={completed} icon={CheckCircle2} iconBgColor="bg-[#22C55E]/10" iconColor="text-[#22C55E]" />
            <ScanSummaryCard label="In Progress" value={inProgress} icon={AlertTriangle} iconBgColor="bg-[#F2B84B]/10" iconColor="text-[#F2B84B]" />
            <ScanSummaryCard label="Failed" value={failed} icon={AlertCircle} iconBgColor="bg-[#EF4444]/10" iconColor="text-[#EF4444]" />
          </div>

          {loading && <p className="text-[#718096] mb-4">Loading assets...</p>}
          {error && <p className="text-[#EF4444] mb-4">{error}</p>}
          {assets.length === 0 && !loading && <p className="text-[#718096] mb-4">No registered assets. Add an asset in My Assets first.</p>}
          {scans.length === 0 && !loading && !error && <p className="text-[#718096] mb-4">No scans yet.</p>}

          <StatusFilterBar search={search} setSearch={setSearch} statusFilter={statusFilter} setStatusFilter={setStatusFilter} />
          <ScanHistoryTable
            scans={scans}
            search={search}
            statusFilter={statusFilter}
            onView={(s) => {
              const full = scans.find((x) => x.id === s.id);
              setSelectedScan(full ?? null);
            }}
          />

          {selectedScan && (
            <ScanDetails
              scan={selectedScan}
              findings={selectedScan.findings}
              risk={selectedRisk}
              onClose={() => setSelectedScan(null)}
            />
          )}

        </div>
      </div>

      <StartScanModal open={modalOpen} onClose={() => setModalOpen(false)} assets={assets} onStart={handleStart} />
    </div>
  );
}
