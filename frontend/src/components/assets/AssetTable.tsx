import { Globe, MoreHorizontal } from 'lucide-react';
import { AssetStatusBadge } from './AssetStatusBadge';

export interface Asset {
  id: number;
  name: string;
  url: string;
  status: 'active' | 'warning' | 'critical' | 'pending';
  ssl?: string;
  score?: number | null;
  lastScanned: string;
}

interface Props {
  assets: Asset[];
  search: string;
  onView: (a: Asset) => void;
  onScan: (id: number) => void;
}

export function AssetTable({ assets, search, onView, onScan }: Props) {
  const filtered = assets.filter((a) => a.name.toLowerCase().includes(search.toLowerCase()) || a.url.toLowerCase().includes(search.toLowerCase()));
  if (filtered.length === 0) {
    return <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">No assets found.</div>;
  }
  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full" role="table">
          <thead>
            <tr className="bg-[#F4F7FA] border-b border-[#E2E8F0]">
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Website / Domain</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">SSL Certificate</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Security Score</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Last Scanned</th>
              <th className="px-6 py-3 text-right text-xs font-semibold text-[#718096] uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0]/50">
            {filtered.map((a) => (
              <tr key={a.id} className="hover:bg-[#F4F7FA]/50 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-[#36D6C4]/10 flex items-center justify-center">
                      <Globe className="w-5 h-5 text-[#36D6C4]" />
                    </div>
                    <div>
                      <p className="font-medium text-[#101B2C]">{a.name}</p>
                      <p className="text-xs text-[#718096]">{a.url}</p>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4"><AssetStatusBadge status={a.status} /></td>
                <td className="px-6 py-4 hidden md:table-cell text-sm text-[#718096]">{a.ssl ?? 'Not available'}</td>
                <td className="px-6 py-4 hidden lg:table-cell text-sm font-medium text-[#101B2C]">{a.score === null || a.score === undefined ? 'Not scored' : `${a.score}/100`}</td>
                <td className="px-6 py-4 hidden lg:table-cell text-sm text-[#718096]">{a.lastScanned}</td>
                <td className="px-6 py-4 text-right flex items-center justify-end gap-1">
                  <button onClick={() => onView(a)} className="px-2 py-1 text-xs rounded border border-[#E2E8F0] hover:bg-[#F4F7FA]">View</button>
                  <button onClick={() => onScan(a.id)} className="px-2 py-1 text-xs rounded bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20">Scan</button>
                  <button className="p-2 rounded-lg hover:bg-[#F4F7FA] text-[#718096]" aria-label="More">
                    <MoreHorizontal className="w-5 h-5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
