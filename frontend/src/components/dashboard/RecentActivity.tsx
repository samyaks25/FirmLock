import { ShieldCheck, AlertTriangle, Globe, CheckCircle, Clock, XCircle, Info } from 'lucide-react';

interface ActivityItem {
  id: number;
  type: 'scan_completed' | 'vulnerability_found' | 'scan_started' | 'certificate_expiring' | 'configuration_change';
  title: string;
  description: string;
  asset: string;
  time: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
}

const mockActivity: ActivityItem[] = [
  {
    id: 1,
    type: 'scan_completed',
    title: 'Security scan completed',
    description: 'Full security scan completed for Primary Website with score 94/100',
    asset: 'Primary Website',
    time: '2 hours ago',
    severity: 'success',
  },
  {
    id: 2,
    type: 'vulnerability_found',
    title: 'Critical vulnerability detected',
    description: 'SQL injection vulnerability found in Customer Portal login form',
    asset: 'Customer Portal',
    time: '3 hours ago',
    severity: 'critical',
  },
  {
    id: 3,
    type: 'scan_started',
    title: 'Scheduled scan initiated',
    description: 'Weekly automated security scan started for API Gateway',
    asset: 'API Gateway',
    time: '4 hours ago',
    severity: 'info',
  },
  {
    id: 4,
    type: 'certificate_expiring',
    title: 'SSL certificate expiring soon',
    description: 'SSL certificate for api.company.com expires in 14 days',
    asset: 'API Gateway',
    time: '5 hours ago',
    severity: 'warning',
  },
  {
    id: 5,
    type: 'scan_completed',
    title: 'Security scan completed',
    description: 'Full security scan completed for Documentation Site with score 88/100',
    asset: 'Documentation Site',
    time: '6 hours ago',
    severity: 'success',
  },
  {
    id: 6,
    type: 'configuration_change',
    title: 'Security configuration updated',
    description: 'WAF rules updated for Customer Portal - new rate limiting applied',
    asset: 'Customer Portal',
    time: '8 hours ago',
    severity: 'info',
  },
  {
    id: 7,
    type: 'vulnerability_found',
    title: 'Medium severity issue found',
    description: 'Cross-site scripting (XSS) vulnerability in search parameter',
    asset: 'API Gateway',
    time: '12 hours ago',
    severity: 'warning',
  },
];

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

const getTypeIcon = (type: ActivityItem['type']) => {
  switch (type) {
    case 'scan_completed':
    case 'scan_started':
      return ShieldCheck;
    case 'vulnerability_found':
      return AlertTriangle;
    case 'certificate_expiring':
      return Clock;
    case 'configuration_change':
      return Globe;
    default:
      return ShieldCheck;
  }
};

export function RecentActivity() {
  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
        <h3 className="text-lg font-semibold text-[#101B2C]">Recent Security Activity</h3>
        <button className="text-sm text-[#36D6C4] hover:underline">View all</button>
      </div>

      <div className="divide-y divide-[#E2E8F0]/50">
        {mockActivity.map((item) => {
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