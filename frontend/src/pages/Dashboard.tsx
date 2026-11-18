import { useEffect, useState } from 'react';
import { Globe, AlertTriangle, XCircle, ShieldCheck, ArrowRight } from 'lucide-react';
import { StatCard } from '../components/dashboard/StatCard';
import { SecurityScore } from '../components/dashboard/SecurityScore';
import { AssetTable, type AssetOverview } from '../components/dashboard/AssetTable';
import { RecentActivity, type ActivityItem } from '../components/dashboard/RecentActivity';
import { useAuth } from '../auth/AuthContext';
import { api } from '../api/client';
import type { DashboardResponse, AssetResponse } from '../types/backend';

interface Recommendation {
  id: number;
  title: string;
  description: string;
  priority: 'high' | 'medium' | 'low';
  action: string;
  icon: React.ComponentType<{ className?: string }>;
}

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
  const { businessId, loading: authLoading } = useAuth();
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [assets, setAssets] = useState<AssetOverview[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading || !businessId) return;
    let mounted = true;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [dash, assetList] = await Promise.all([
          api.get<DashboardResponse>(`/api/businesses/${businessId}/dashboard`),
          api.get<AssetResponse[]>(`/api/businesses/${businessId}/assets`),
        ]);
        if (!mounted) return;
        setData(dash);
        setAssets(
          assetList.map((a) => ({
            id: a.id,
            name: a.domain,
            url: `https://${a.domain}`,
            status: a.status === 'active' ? 'secure' : a.status === 'paused' ? 'warning' : 'critical',
            lastScan: a.last_scanned_at ? new Date(a.last_scanned_at).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : 'Never',
            score: null,
          })),
        );
        const recs: Recommendation[] = [];
        dash.critical_security_findings.forEach((f, idx) => {
          recs.push({
            id: idx + 1,
            title: f.title,
            description: `${f.check_code} on ${f.asset_domain}`,
            priority: f.severity.toLowerCase() === 'critical' ? 'high' : f.severity.toLowerCase() === 'high' ? 'medium' : 'low',
            action: 'View Details',
            icon: AlertTriangle,
          });
        });
        if (dash.latest_scan) {
          recs.push({
            id: recs.length + 1,
            title: 'Review latest scan recommendations',
            description: `Recommendations from the latest scan on ${dash.latest_scan.asset_domain} (${dash.latest_scan.status})`,
            priority: 'medium',
            action: 'View Details',
            icon: ShieldCheck,
          });
        }
        setRecommendations(recs);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load dashboard');
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
  }, [businessId, authLoading]);

  const activities: ActivityItem[] = (data?.recent_security_activity ?? []).map((a, idx) => ({
    id: idx,
    type: a.type,
    title: a.title,
    description: a.status ?? a.severity ?? '',
    asset: a.asset_domain ?? '-',
    time: a.occurred_at ? new Date(a.occurred_at).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : '-',
    severity: (a.severity ?? 'info') as ActivityItem['severity'],
  }));

  const score = data?.security_overview.average_security_score ?? null;

  const headerStats = data ? [
    {
      label: 'Websites Monitored',
      value: data.total_monitored_websites,
      icon: Globe,
      iconBgColor: 'bg-[#36D6C4]/10',
      iconColor: 'text-[#36D6C4]',
      trend: undefined,
      trendDirection: 'neutral' as const,
    },
    {
      label: 'Security Warnings',
      value: data.alert_counts.high + data.alert_counts.medium,
      icon: AlertTriangle,
      iconBgColor: 'bg-[#F2B84B]/10',
      iconColor: 'text-[#F2B84B]',
      trend: undefined,
      trendDirection: 'neutral' as const,
    },
    {
      label: 'Critical Issues',
      value: data.alert_counts.critical,
      icon: XCircle,
      iconBgColor: 'bg-[#EF4444]/10',
      iconColor: 'text-[#EF4444]',
      trend: undefined,
      trendDirection: 'neutral' as const,
    },
    {
      label: 'Security Score',
      value: score === null ? '—' : Math.round(score),
      icon: ShieldCheck,
      iconBgColor: 'bg-[#22C55E]/10',
      iconColor: 'text-[#22C55E]',
      trend: undefined,
      trendDirection: 'neutral' as const,
    },
  ] : [];

  if (authLoading) return null;

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <main className="p-4 md:p-6">
          {error && <div className="mb-4 p-3 rounded-lg bg-[#FEF2F2] border border-[#EF4444]/30 text-sm text-[#EF4444]">{error}</div>}
          {!data && !error && loading && <p className="text-[#718096] mb-4">Loading dashboard...</p>}

          {data && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6 md:mb-8">
                {headerStats.map((stat, idx) => (
                  <StatCard key={idx} {...stat} />
                ))}
              </div>

              <SecurityScore score={score ?? 0} scoreAvailable={score !== null} />

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6 md:mt-8">
                <AssetTable assets={assets} />
                <RecentActivity activities={activities} />
              </div>

              <div className="mt-6 md:mt-8">
                <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
                  <div className="px-6 py-4 border-b border-[#E2E8F0] flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-[#101B2C]">Security Recommendations</h3>
                    <button className="text-sm text-[#36D6C4] hover:underline">View all</button>
                  </div>
                  <div className="p-6 space-y-4">
                    {recommendations.length === 0 && (
                      <p className="text-[#718096] text-sm">No active recommendations. All monitored assets are within acceptable risk thresholds.</p>
                    )}
                    {recommendations.map((rec) => {
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
            </>
          )}
      </main>
    </div>
  );
}
