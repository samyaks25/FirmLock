import { useState } from 'react';
import { ShieldCheck, AlertTriangle, AlertCircle, CheckCircle2 } from 'lucide-react';
import { ScanSummaryCard } from '../components/scans/ScanSummaryCard';
import { ScanHistoryTable, type Scan, StatusFilterBar } from '../components/scans/ScanHistoryTable';
import { StartScanModal } from '../components/scans/StartScanModal';
import { FindingCard, type Finding } from '../components/scans/FindingCard';
import { ScanDetails } from '../components/scans/ScanDetails';

const assets = [
  { id: 1, name: 'Primary Website', url: 'https://www.company.com' },
  { id: 2, name: 'API Gateway', url: 'https://api.company.com' },
  { id: 3, name: 'Customer Portal', url: 'https://portal.company.com' },
];

const initialScans: Scan[] = [
  { id: 'SCAN-001', website: 'Primary Website', domain: 'www.company.com', date: '2026-11-15', status: 'Completed', score: 94, issues: 2 },
  { id: 'SCAN-002', website: 'API Gateway', domain: 'api.company.com', date: '2026-11-14', status: 'Completed', score: 72, issues: 5 },
  { id: 'SCAN-003', website: 'Customer Portal', domain: 'portal.company.com', date: '2026-11-13', status: 'In Progress', score: 45, issues: 8 },
];

const findings: Finding[] = [
  { id: 1, title: 'Outdated TLS version', website: 'API Gateway', severity: 'Critical', description: 'Server supports TLS 1.0 (demo).', remediation: 'Disable TLS 1.0/1.1 and enable TLS 1.2+ (demo).' },
  { id: 2, title: 'Missing security headers', website: 'Primary Website', severity: 'High', description: 'CSP header not set (demo).', remediation: 'Add Content-Security-Policy header (demo).' },
  { id: 3, title: 'Cookie without Secure flag', website: 'Customer Portal', severity: 'Medium', description: 'Session cookie lacks Secure attribute (demo).', remediation: 'Set Secure and HttpOnly flags (demo).' },
  { id: 4, title: 'Verbose error messages', website: 'Primary Website', severity: 'Low', description: 'Stack traces exposed (demo).', remediation: 'Disable detailed errors in production (demo).' },
];

export function SecurityScans() {
  const [scans, setScans] = useState<Scan[]>(initialScans);
  const [modalOpen, setModalOpen] = useState(false);
  const [loading] = useState(false);
  const [error] = useState<string | null>(null);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');

  const handleStart = (assetId: number) => {
    const a = assets.find((x) => x.id === assetId)!;
    const newScan: Scan = {
      id: `SCAN-${String(scans.length + 1).padStart(3, '0')}`,
      website: a.name,
      domain: new URL(a.url).hostname,
      date: new Date().toISOString().slice(0, 10),
      status: 'In Progress',
      score: 0,
      issues: 0,
    };
    setScans((prev) => [newScan, ...prev]);
  };

  const total = scans.length;
  const passed = scans.reduce((acc, s) => acc + (s.score > 0 ? 1 : 0), 0);
  const warnings = scans.filter((s) => s.status !== 'Completed').length;
  const critical = findings.filter((f) => f.severity === 'Critical').length;

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

          <p className="text-xs text-[#718096] mb-4">All numbers and results below are demonstration data. No real scan performed.</p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <ScanSummaryCard label="Total Scans" value={total} icon={ShieldCheck} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ScanSummaryCard label="Passed Checks" value={passed} icon={CheckCircle2} iconBgColor="bg-[#22C55E]/10" iconColor="text-[#22C55E]" />
            <ScanSummaryCard label="Security Warnings" value={warnings} icon={AlertTriangle} iconBgColor="bg-[#F2B84B]/10" iconColor="text-[#F2B84B]" />
            <ScanSummaryCard label="Critical Issues" value={critical} icon={AlertCircle} iconBgColor="bg-[#EF4444]/10" iconColor="text-[#EF4444]" />
          </div>

          {loading && <p className="text-[#718096] mb-4">Loading scans...</p>}
          {error && <p className="text-[#EF4444] mb-4">{error}</p>}
          {scans.length === 0 && !loading && <p className="text-[#718096] mb-4">No scans yet.</p>}

          <StatusFilterBar search={search} setSearch={setSearch} statusFilter={statusFilter} setStatusFilter={setStatusFilter} />
          <ScanHistoryTable scans={scans} search={search} statusFilter={statusFilter} onView={setSelectedScan} />

          <div className="mt-8">
            <h2 className="text-lg font-semibold text-[#101B2C] mb-3">Vulnerability Findings (demo)</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(['Critical', 'High', 'Medium', 'Low'] as const).map((sev) => (
                <div key={sev}>
                  <h3 className="text-sm font-semibold text-[#718096] mb-2">{sev}</h3>
                  <div className="space-y-3">
                    {findings.filter((f) => f.severity === sev).map((f) => (
                      <FindingCard key={f.id} finding={f} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">All data shown is demonstration/mock data for preview purposes.</p>
        </div>
      </div>

      <StartScanModal open={modalOpen} onClose={() => setModalOpen(false)} assets={assets} onStart={handleStart} />
      {selectedScan && <ScanDetails scan={selectedScan} findings={findings} onClose={() => setSelectedScan(null)} />}
    </div>
  );
}
