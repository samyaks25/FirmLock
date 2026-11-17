import { useState } from 'react';
import { FileText, Plus, Globe, CheckCircle2, Award } from 'lucide-react';
import { ReportSummaryCard } from '../components/reports/ReportSummaryCard';
import { ReportTable, ReportFilterBar, type Report } from '../components/reports/ReportTable';
import { GenerateReportModal } from '../components/reports/GenerateReportModal';
import { ReportDetails } from '../components/reports/ReportDetails';

const assets = [
  { id: 1, name: 'Primary Website', url: 'https://www.company.com' },
  { id: 2, name: 'API Gateway', url: 'https://api.company.com' },
  { id: 3, name: 'Customer Portal', url: 'https://portal.company.com' },
  { id: 4, name: 'Documentation Site', url: 'https://docs.company.com' },
];

const initialReports: Report[] = [
  {
    id: 'RPT-001',
    name: 'Full Security Assessment - Primary Website',
    website: 'Primary Website',
    domain: 'www.company.com',
    date: '2026-11-15',
    status: 'Completed',
    score: 94,
    findings: 2,
  },
  {
    id: 'RPT-002',
    name: 'SSL & TLS Analysis - API Gateway',
    website: 'API Gateway',
    domain: 'api.company.com',
    date: '2026-11-14',
    status: 'Completed',
    score: 72,
    findings: 5,
  },
  {
    id: 'RPT-003',
    name: 'Vulnerability Summary - Customer Portal',
    website: 'Customer Portal',
    domain: 'portal.company.com',
    date: '2026-11-13',
    status: 'Completed',
    score: 45,
    findings: 8,
  },
  {
    id: 'RPT-004',
    name: 'Security Headers Audit - Documentation Site',
    website: 'Documentation Site',
    domain: 'docs.company.com',
    date: '2026-11-12',
    status: 'Completed',
    score: 68,
    findings: 4,
  },
  {
    id: 'RPT-005',
    name: 'Full Security Assessment - API Gateway',
    website: 'API Gateway',
    domain: 'api.company.com',
    date: '2026-11-10',
    status: 'Completed',
    score: 78,
    findings: 3,
  },
];

const websites = assets.map((a) => a.name);

export function Reports() {
  const [reports, setReports] = useState<Report[]>(initialReports);
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [search, setSearch] = useState('');
  const [websiteFilter, setWebsiteFilter] = useState('All');
  const [dateFilter, setDateFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');

  const handleGenerate = (data: { assetId: number; reportType: string; startDate: string; endDate: string; includeRecommendations: boolean }) => {
    const asset = assets.find((a) => a.id === data.assetId)!;
    const newReport: Report = {
      id: `RPT-${String(reports.length + 1).padStart(3, '0')}`,
      name: `${data.reportType} - ${asset.name}`,
      website: asset.name,
      domain: new URL(asset.url).hostname,
      date: new Date().toISOString().slice(0, 10),
      status: 'Completed',
      score: Math.floor(Math.random() * 40) + 50,
      findings: Math.floor(Math.random() * 8) + 1,
    };
    setReports((prev) => [newReport, ...prev]);
  };

  const total = reports.length;
  const generated = reports.filter((r) => r.status === 'Completed').length;
  const covered = new Set(reports.map((r) => r.website)).size;
  const avgScore = reports.length > 0 ? Math.round(reports.reduce((acc, r) => acc + r.score, 0) / reports.length) : 0;

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="md:ml-64">
        <div className="p-4 md:p-6 md:ml-20 transition-all duration-300">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">Security Reports</h1>
              <p className="text-sm text-[#718096]">Review and manage your website security assessment reports.</p>
            </div>
            <button onClick={() => setModalOpen(true)} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90">
              <Plus className="w-4 h-4" /> Generate Report
            </button>
          </div>

          <p className="text-xs text-[#718096] mb-4">All reports and data shown are demonstration data. No actual security assessments were performed.</p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <ReportSummaryCard label="Total Reports" value={total} icon={FileText} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ReportSummaryCard label="Reports Generated" value={generated} icon={CheckCircle2} iconBgColor="bg-[#22C55E]/10" iconColor="text-[#22C55E]" />
            <ReportSummaryCard label="Websites Covered" value={covered} icon={Globe} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ReportSummaryCard label="Average Security Score" value={`${avgScore}/100`} icon={Award} iconBgColor="bg-[#F2B84B]/10" iconColor="text-[#F2B84B]" />
          </div>

          <ReportFilterBar
            search={search}
            setSearch={setSearch}
            websiteFilter={websiteFilter}
            setWebsiteFilter={setWebsiteFilter}
            dateFilter={dateFilter}
            setDateFilter={setDateFilter}
            statusFilter={statusFilter}
            setStatusFilter={setStatusFilter}
            websites={websites}
          />

          <ReportTable
            reports={reports}
            search={search}
            websiteFilter={websiteFilter}
            dateFilter={dateFilter}
            statusFilter={statusFilter}
            onView={setSelectedReport}
          />

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">All data shown is demonstration/mock data for preview purposes.</p>
        </div>
      </div>

      <GenerateReportModal open={modalOpen} onClose={() => setModalOpen(false)} assets={assets} onGenerate={handleGenerate} />
      {selectedReport && <ReportDetails report={selectedReport} onClose={() => setSelectedReport(null)} />}
    </div>
  );
}