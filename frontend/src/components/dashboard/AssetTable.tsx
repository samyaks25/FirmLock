import { Globe, CheckCircle, AlertCircle, MoreHorizontal, ExternalLink } from 'lucide-react';

export type AssetStatus = 'secure' | 'warning' | 'critical';

export interface AssetOverview {
  id: number;
  name: string;
  url: string;
  status: AssetStatus;
  lastScan: string;
  score: number | null;
}

interface Props {
  assets: AssetOverview[];
}

const getStatusConfig = (status: AssetStatus) => {
  switch (status) {
    case 'secure':
      return { label: 'Secure', color: 'bg-[#22C55E]/10 text-[#22C55E]', icon: CheckCircle };
    case 'warning':
      return { label: 'Warning', color: 'bg-[#F2B84B]/10 text-[#F2B84B]', icon: AlertCircle };
    case 'critical':
      return { label: 'Critical', color: 'bg-[#EF4444]/10 text-[#EF4444]', icon: AlertCircle };
  }
};

export function AssetTable({ assets }: Props) {
  if (assets.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">
        <div className="flex flex-col items-center gap-2">
          <Globe className="w-8 h-8 text-[#E2E8F0]" aria-hidden="true" />
          <p className="font-medium text-[#101B2C]">No websites registered yet</p>
          <p className="text-sm mt-1">Register your first website from My Assets to begin monitoring.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
        <h3 className="text-lg font-semibold text-[#101B2C]">Website Security Overview</h3>
        <button className="text-sm text-[#36D6C4] hover:underline flex items-center gap-1">
          View all assets
          <ExternalLink className="w-4 h-4" aria-hidden="true" />
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full" role="table">
          <thead>
            <tr className="bg-[#F4F7FA] border-b border-[#E2E8F0]">
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Asset</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">URL</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">Score</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">Last Scan</th>
              <th className="px-6 py-3 text-right text-xs font-semibold text-[#718096] uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0]/50">
            {assets.map((asset) => {
              const statusConfig = getStatusConfig(asset.status);
              const StatusIcon = statusConfig.icon;
              return (
                <tr key={asset.id} className="hover:bg-[#F4F7FA]/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#36D6C4]/10 flex items-center justify-center">
                        <Globe className="w-5 h-5 text-[#36D6C4]" aria-hidden="true" />
                      </div>
                      <div>
                        <p className="font-medium text-[#101B2C]">{asset.name}</p>
                        <p className="text-xs text-[#718096]">{asset.url.replace('https://', '')}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 hidden md:table-cell text-sm text-[#718096]">{asset.url}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${statusConfig.color}`}>
                      <StatusIcon className="w-3 h-3" aria-hidden="true" />
                      {statusConfig.label}
                    </span>
                  </td>
                  <td className="px-6 py-4 hidden lg:table-cell">
                    {asset.score === null ? (
                      <span className="text-sm text-[#718096]">Not scored</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-2 bg-[#E2E8F0] rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${asset.score}%`,
                              backgroundColor:
                                asset.score >= 80 ? '#22C55E' : asset.score >= 60 ? '#F2B84B' : '#EF4444',
                            }}
                            role="progressbar"
                            aria-valuenow={asset.score}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-label={`${asset.name} security score`}
                          />
                        </div>
                        <span className="text-sm font-medium text-[#101B2C]">{asset.score}</span>
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-[#718096] whitespace-nowrap">{asset.lastScan}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      className="p-2 rounded-lg hover:bg-[#F4F7FA] transition-colors text-[#718096] hover:text-[#101B2C]"
                      aria-label={`More options for ${asset.name}`}
                    >
                      <MoreHorizontal className="w-5 h-5" aria-hidden="true" />
                    </button>
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
