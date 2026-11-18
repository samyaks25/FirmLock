import { Search } from 'lucide-react';

export interface Scan {
  id: string;
  website: string;
  domain: string;
  date: string;
  status: string;
  score: number | null;
  issues: number;
}

interface Props {
  scans: Scan[];
  search: string;
  statusFilter: string;
  onView: (s: Scan) => void;
}

export function ScanHistoryTable({ scans, search, statusFilter, onView }: Props) {
  const filtered = scans.filter((s) => {
    const matchesSearch = s.website.toLowerCase().includes(search.toLowerCase()) || s.domain.toLowerCase().includes(search.toLowerCase()) || s.id.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = statusFilter === 'All' || s.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  if (filtered.length === 0) {
    return <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">No scans found.</div>;
  }

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full" role="table">
          <thead>
            <tr className="bg-[#F4F7FA] border-b border-[#E2E8F0]">
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Website / Domain</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Scan ID</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">Scan Date</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Security Score</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Issues Found</th>
              <th className="px-6 py-3 text-right text-xs font-semibold text-[#718096] uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0]/50">
            {filtered.map((s) => (
              <tr key={s.id} className="hover:bg-[#F4F7FA]/50 transition-colors">
                <td className="px-6 py-4">
                  <p className="font-medium text-[#101B2C]">{s.website}</p>
                  <p className="text-xs text-[#718096]">{s.domain}</p>
                </td>
                <td className="px-6 py-4 text-sm text-[#718096]">{s.id}</td>
                <td className="px-6 py-4 hidden md:table-cell text-sm text-[#718096]">{s.date}</td>
                <td className="px-6 py-4 text-sm text-[#172536]">{s.status}</td>
                <td className="px-6 py-4 hidden lg:table-cell text-sm font-medium text-[#101B2C]">{s.score === null ? '—' : `${s.score}/100`}</td>
                <td className="px-6 py-4 hidden lg:table-cell text-sm text-[#718096]">{s.issues}</td>
                <td className="px-6 py-4 text-right">
                  <button onClick={() => onView(s)} className="px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20">View Details</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export const StatusFilterBar = ({ search, setSearch, statusFilter, setStatusFilter }: { search: string; setSearch: (v: string) => void; statusFilter: string; setStatusFilter: (v: string) => void; }) => (
  <div className="flex flex-col sm:flex-row gap-3 mb-4">
    <div className="relative max-w-md flex-1">
      <Search className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" />
      <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search scans..." className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]" />
    </div>
    <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]">
      <option>All</option>
      <option>Completed</option>
      <option>In Progress</option>
      <option>Failed</option>
    </select>
  </div>
);
