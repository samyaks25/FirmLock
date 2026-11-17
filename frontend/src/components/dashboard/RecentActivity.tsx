import { ShieldCheck, AlertTriangle, Globe, CheckCircle, Clock, XCircle, Info } from 'lucide-react';

export type ActivitySeverity = 'info' | 'warning' | 'critical' | 'success';

export interface ActivityItem {
  id: number;
  type: string;
  title: string;
  description: string;
  asset: string;
  time: string;
  severity: ActivitySeverity;
}

interface Props {
  activities: ActivityItem[];
}

const getActivityConfig = (severity: ActivityItem['severity']) => {
  switch (severity) {
    case 'success':
      return { icon: CheckCircle, color: 'text-[#22C55E]', bg: 'bg-[#22C55E]/10' };
    case 'warning':
      return { icon: AlertTriangle, color: 'text-[#F2B84B]', bg: 'bg-[#F2B84B]/10' };
    case 'critical':
      return { icon: XCircle, color: 'text-[#EF4444]', bg: 'bg-[#EF4444]/10' };
    case 'info':
    default:
      return { icon: Info, color: 'text-[#36D6C4]', bg: 'bg-[#36D6C4]/10' };
  }
};

const getTypeIcon = (type: string) => {
  const t = type.toLowerCase();
  if (t.includes('scan')) return ShieldCheck;
  if (t.includes('vulnerability')) return AlertTriangle;
  if (t.includes('certificate')) return Clock;
  if (t.includes('configuration')) return Globe;
  return ShieldCheck;
};

export function RecentActivity({ activities }: Props) {
  if (activities.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">
        <div className="flex flex-col items-center gap-2">
          <ShieldCheck className="w-8 h-8 text-[#E2E8F0]" aria-hidden="true" />
          <p className="font-medium text-[#101B2C]">No recent activity</p>
          <p className="text-sm mt-1">Activity will appear here as scans and alerts are generated.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
        <h3 className="text-lg font-semibold text-[#101B2C]">Recent Security Activity</h3>
        <button className="text-sm text-[#36D6C4] hover:underline">View all</button>
      </div>

      <div className="divide-y divide-[#E2E8F0]/50">
        {activities.map((item) => {
          const severityConfig = getActivityConfig(item.severity);
          const TypeIcon = getTypeIcon(item.type);
          const SeverityIcon = severityConfig.icon;

          return (
            <div key={item.id} className="px-6 py-4 hover:bg-[#F4F7FA]/50 transition-colors flex gap-4">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${severityConfig.bg}`}>
                <TypeIcon className="w-5 h-5" style={{ color: severityConfig.color.replace('text-', '') }} aria-hidden="true" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-medium text-[#101B2C]">{item.title}</p>
                    <p className="text-sm text-[#718096] mt-0.5">{item.description}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${severityConfig.bg} ${severityConfig.color}`}>
                      <SeverityIcon className="w-3 h-3" aria-hidden="true" />
                      {item.severity.charAt(0).toUpperCase() + item.severity.slice(1)}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-4 mt-2 text-xs text-[#718096]">
                  <span className="flex items-center gap-1">
                    <Globe className="w-3 h-3" aria-hidden="true" />
                    {item.asset}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" aria-hidden="true" />
                    {item.time}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
