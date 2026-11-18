import { Search, Download } from 'lucide-react';

export type ReportStatus = 'Completed' | 'Generating' | 'Failed';

export interface Report {
  id: string;
  scanId: number;
  assetId: number;
  name: string;
  website: string;
  domain: string;
  date: string;
  status: ReportStatus;
  score: number | null;
  findings: number;
}

interface Props {
  reports: Report[];
  search: string;
  websiteFilter: string;
  dateFilter: string;
  statusFilter: string;
  onView: (r: Report) => void;
  onDownloadCsv: (scanId: number) => void;
}

const statusOptions = ['All', 'Completed', 'Generating', 'Failed'] as const;
const dateOptions = ['All', 'Today', 'This Week', 'This Month', 'Last Month'] as const;

export function ReportFilterBar({
  search,
  setSearch,
  websiteFilter,
  setWebsiteFilter,
  dateFilter,
  setDateFilter,
  statusFilter,
  setStatusFilter,
  websites,
}: {
  search: string;
  setSearch: (v: string) => void;
  websiteFilter: string;
  setWebsiteFilter: (v: string) => void;
  dateFilter: string;
  setDateFilter: (v: string) => void;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  websites: string[];
}) {
  return (
    <div className="flex flex-col sm:flex-row gap-3 mb-4">
      <div className="relative max-w-md flex-1">
        <Search className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search reports..."
          className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
        />
      </div>
      <div className="flex gap-2 flex-wrap">
        <select
          value={websiteFilter}
          onChange={(e) => setWebsiteFilter(e.target.value)}
          className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] min-w-[160px]"
        >
          <option value="All">All Websites</option>
          {websites.map((w) => (
            <option key={w} value={w}>{w}</option>
          ))}
        </select>
        <select
          value={dateFilter}
          onChange={(e) => setDateFilter(e.target.value)}
          className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] min-w-[140px]"
        >
          {dateOptions.map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] min-w-[140px]"
        >
          {statusOptions.map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
      </div>
    </div>
  );
}

export function ReportTable({
  reports,
  search,
  websiteFilter,
  dateFilter,
  statusFilter,
  onView,
  onDownloadCsv,
}: Props) {
  const filtered = reports.filter((r) => {
    const matchesSearch =
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.website.toLowerCase().includes(search.toLowerCase()) ||
      r.domain.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase());
    const matchesWebsite = websiteFilter === 'All' || r.website === websiteFilter;
    const matchesDate = dateFilter === 'All' || true;
    const matchesStatus = statusFilter === 'All' || r.status === statusFilter;
    return matchesSearch && matchesWebsite && matchesDate && matchesStatus;
  });

  if (filtered.length === 0) {
    return <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">No reports found.</div>;
  }

  const getStatusConfig = (status: ReportStatus) => {
    switch (status) {
      case 'Completed':
        return { color: 'bg-[#22C55E]/10 text-[#22C55E]', label: 'Completed' };
      case 'Generating':
        return { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', label: 'Generating' };
      case 'Failed':
        return { color: 'bg-[#EF4444]/10 text-[#EF4444]', label: 'Failed' };
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-[#22C55E]';
    if (score >= 60) return 'text-[#F2B84B]';
    return 'text-[#EF4444]';
  };

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full" role="table">
          <thead>
            <tr className="bg-[#F4F7FA] border-b border-[#E2E8F0]">
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Report Name</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">Website / Domain</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Report ID</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">Generated Date</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Security Score</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Findings</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-right text-xs font-semibold text-[#718096] uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0]/50">
            {filtered.map((r) => {
              const statusConfig = getStatusConfig(r.status);
              return (
                <tr key={r.id} className="hover:bg-[#F4F7FA]/50 transition-colors">
                  <td className="px-6 py-4">
                    <p className="font-medium text-[#101B2C]">{r.name}</p>
                  </td>
                  <td className="px-6 py-4 hidden md:table-cell text-sm">
                    <p className="font-medium text-[#172536]">{r.website}</p>
                    <p className="text-xs text-[#718096]">{r.domain}</p>
                  </td>
                  <td className="px-6 py-4 text-sm text-[#718096]">{r.id}</td>
                  <td className="px-6 py-4 hidden md:table-cell text-sm text-[#718096]">{r.date}</td>
                  <td className="px-6 py-4">
                    {r.score === null ? (
                      <span className="text-sm text-[#718096]">—</span>
                    ) : (
                      <span className={`font-medium ${getScoreColor(r.score)}`}>{r.score}/100</span>
                    )}
                  </td>
                  <td className="px-6 py-4 hidden lg:table-cell text-sm text-[#718096]">{r.findings}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${statusConfig.color}`}>
                      {statusConfig.label}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onView(r)}
                        className="px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20"
                      >
                        View Report
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDownloadCsv(r.scanId);
                        }}
                        className="p-1.5 rounded-lg hover:bg-[#E2E8F0] text-[#718096] transition-colors"
                        aria-label="Download CSV"
                        title="Download CSV"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}