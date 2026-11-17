import {
  Globe,
  AlertTriangle,
  XCircle,
  ShieldCheck,
  ArrowRight,
  Shield,
  Zap,
  Lock,
  CheckCircle,
} from 'lucide-react';
import { StatCard } from '../components/dashboard/StatCard';
import { SecurityScore } from '../components/dashboard/SecurityScore';
import { AssetTable } from '../components/dashboard/AssetTable';
import { RecentActivity } from '../components/dashboard/RecentActivity';

interface Recommendation {
  id: number;
  title: string;
  description: string;
  priority: 'high' | 'medium' | 'low';
  action: string;
  icon: React.ComponentType<{ className?: string }>;
}

const mockRecommendations: Recommendation[] = [
  {
    id: 1,
    title: 'Patch Critical SQL Injection',
    description: 'Customer Portal has a critical SQL injection vulnerability in the login form. Immediate patching required.',
    priority: 'high',
    action: 'View Details',
    icon: AlertTriangle,
  },
  {
    id: 2,
    title: 'Renew Expiring SSL Certificate',
    description: 'API Gateway SSL certificate expires in 14 days. Schedule renewal to avoid service disruption.',
    priority: 'high',
    action: 'Renew Now',
    icon: Lock,
  },
  {
    id: 3,
    title: 'Enable WAF Rate Limiting',
    description: 'API Gateway would benefit from enhanced rate limiting rules to prevent abuse.',
    priority: 'medium',
    action: 'Configure',
    icon: Shield,
  },
  {
    id: 4,
    title: 'Update Outdated Dependencies',
    description: 'Primary Website has 3 npm packages with known vulnerabilities. Update to latest secure versions.',
    priority: 'medium',
    action: 'Update',
    icon: Zap,
  },
  {
    id: 5,
    title: 'Implement Security Headers',
    description: 'Documentation Site is missing CSP and HSTS headers. Add security headers for better protection.',
    priority: 'low',
    action: 'Implement',
    icon: CheckCircle,
  },
];

const getPriorityConfig = (priority: Recommendation['priority']) => {
  switch (priority) {
    case 'high':
      return { label: 'High', color: 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20', iconColor: 'text-[#EF4444]' };
    case 'medium':
      return { label: 'Medium', color: 'bg-[#F2B84B]/10 text-[#F2B84B] border-[#F2B84B]/20', iconColor: 'text-[#F2B84B]' };
    case 'low':
      return { label: 'Low', color: 'bg-[#36D6C4]/10 text-[#36D6C4] border-[#36D6C4]/20', iconColor: 'text-[#36D6C4]' };
  }
};

export function Dashboard() {
  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="md:ml-64">
        <header className="md:ml-20 transition-all duration-300">
          <div className="flex items-center justify-between h-16 px-4 md:px-6">
            <div>
              <h1 className="text-xl font-semibold text-[#101B2C]">Dashboard</h1>
              <p className="text-sm text-[#718096]">Security posture overview and recent activity</p>
            </div>
          </div>
        </header>

        <main className="p-4 md:p-6 md:ml-20 transition-all duration-300">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6 md:mb-8">
            <StatCard
              label="Websites Monitored"
              value="04"
              icon={Globe}
              iconBgColor="bg-[#36D6C4]/10"
              iconColor="text-[#36D6C4]"
              trend={{ value: 0, label: 'vs last month' }}
              trendDirection="neutral"
            />
            <StatCard
              label="Security Warnings"
              value="03"
              icon={AlertTriangle}
              iconBgColor="bg-[#F2B84B]/10"
              iconColor="text-[#F2B84B]"
              trend={{ value: 1, label: 'vs last week' }}
              trendDirection="up"
            />
            <StatCard
              label="Critical Issues"
              value="01"
              icon={XCircle}
              iconBgColor="bg-[#EF4444]/10"
              iconColor="text-[#EF4444]"
              trend={{ value: 0, label: 'vs last week' }}
              trendDirection="neutral"
            />
            <StatCard
              label="Security Score"
              value="82/100"
              icon={ShieldCheck}
              iconBgColor="bg-[#22C55E]/10"
              iconColor="text-[#22C55E]"
              trend={{ value: 5, label: 'vs last month' }}
              trendDirection="up"
            />
          </div>

          <SecurityScore score={82} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6 md:mt-8">
            <AssetTable />
            <RecentActivity />
          </div>

          <div className="mt-6 md:mt-8">
            <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
              <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
                <h3 className="text-lg font-semibold text-[#101B2C]">Security Recommendations</h3>
                <button className="text-sm text-[#36D6C4] hover:underline">View all</button>
              </div>
              <div className="p-6 space-y-4">
                {mockRecommendations.map((rec) => {
                  const priorityConfig = getPriorityConfig(rec.priority);
                  const RecIcon = rec.icon;
                  return (
                    <div
                      key={rec.id}
                      className={`p-4 rounded-xl border transition-all hover:border-[#36D6C4]/30 ${priorityConfig.color} border`}
                    >
                      <div className="flex items-start gap-4">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${priorityConfig.color.replace('text-', 'bg-').replace('border', '')}`}>
                          <RecIcon className={`w-5 h-5 ${priorityConfig.iconColor}`} aria-hidden="true" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <h4 className="font-medium text-[#101B2C]">{rec.title}</h4>
                              <p className="text-sm text-[#718096] mt-1">{rec.description}</p>
                            </div>
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${priorityConfig.color}`}>
                              {priorityConfig.label} Priority
                            </span>
                          </div>
                          <button className="mt-3 text-sm font-medium text-[#36D6C4] hover:underline flex items-center gap-1">
                            {rec.action}
                            <ArrowRight className="w-4 h-4" aria-hidden="true" />
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <p className="text-center text-sm text-[#718096] mt-8 md:mt-10 pb-8">
            All data shown is demonstration/mock data for preview purposes.
          </p>
        </main>
      </div>
    </div>
  );
}