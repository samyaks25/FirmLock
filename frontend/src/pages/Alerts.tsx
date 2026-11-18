import { useCallback, useEffect, useState } from 'react';
import { Bell, AlertTriangle, ShieldCheck, XCircle } from 'lucide-react';
import { api, alertsApi } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { AlertSummaryCard } from '../components/alerts/AlertSummaryCard';
import { AlertList, AlertFilterBar, type Alert } from '../components/alerts/AlertList';
import { AlertDetails } from '../components/alerts/AlertDetails';
import type { AlertResponse, AlertSummary, AssetResponse } from '../types/backend';

function normalizeSeverity(severity: string): Alert['severity'] {
  const cap = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
  return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(cap) ? (cap as Alert['severity']) : 'Info';
}

function mapAlert(alert: AlertResponse, domains: Map<number, string>): Alert {
  const created = new Date(alert.created_at);
  const domain = domains.get(alert.asset_id) ?? `Asset #${alert.asset_id}`;
  const status: Alert['status'] = alert.status === 'resolved' ? 'resolved' : alert.status === 'read' ? 'read' : 'unread';
  return {
    id: String(alert.id),
    backendId: alert.id,
    title: alert.title,
    website: domain,
    domain,
    category: '—',
    severity: normalizeSeverity(alert.severity),
    status,
    read: status !== 'unread',
    resolved: status === 'resolved',
    date: created.toISOString().slice(0, 10),
    time: created.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: true }),
    description: alert.message,
    impact: '—',
    remediation: '—',
  };
}

export function Alerts() {
  const { businessId } = useAuth();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [domains, setDomains] = useState<Map<number, string>>(new Map());
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedAlert, setSelectedAlert] = useState<AlertResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!businessId) return;
    setLoading(true);
    setError(null);
    try {
      const [assetList, alertList, alertSummary] = await Promise.all([
        api.get<AssetResponse[]>(`/api/businesses/${businessId}/assets`),
        alertsApi.list(businessId, { page: 1, page_size: 100 }),
        alertsApi.summary(businessId),
      ]);
      setDomains(new Map(assetList.map((a) => [a.id, a.domain])));
      setAlerts(alertList.items.map((a) => mapAlert(a, new Map(assetList.map((x) => [x.id, x.domain])))));
      setSummary(alertSummary);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts.');
    } finally {
      setLoading(false);
    }
  }, [businessId]);

  useEffect(() => {
    if (!businessId) return;
    (async () => {
      await loadData();
    })();
  }, [businessId, loadData]);

  const handleUpdate = async (backendId: number, updates: { read?: boolean; resolved?: boolean }) => {
    setError(null);
    try {
      const updated = await alertsApi.update(backendId, updates);
      setAlerts((prev) =>
        prev.map((a) => (a.backendId === backendId ? mapAlert(updated, domains) : a)),
      );
      const alertSummary = await alertsApi.summary(businessId!);
      setSummary(alertSummary);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update alert.');
    }
  };

  const handleMarkRead = (backendId: number) => handleUpdate(backendId, { read: true });
  const handleMarkUnread = (backendId: number) => handleUpdate(backendId, { read: false });
  const handleResolve = (backendId: number) => handleUpdate(backendId, { resolved: true });

  const handleView = async (backendId: number) => {
    setDetailLoading(true);
    setError(null);
    try {
      const alert = await alertsApi.get(backendId);
      setSelectedAlert(alert);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alert details.');
    } finally {
      setDetailLoading(false);
    }
  };

  const total = summary?.total ?? alerts.length;
  const unread = summary?.unread ?? alerts.filter((a) => a.status === 'unread').length;
  const critical = summary?.critical ?? alerts.filter((a) => a.severity === 'Critical').length;
  const resolved = summary?.resolved ?? alerts.filter((a) => a.status === 'resolved').length;

  if (!businessId) {
    return (
      <div className="min-h-screen bg-[#F4F7FA]">
        <div className="p-4 md:p-6">
          <h1 className="text-2xl font-semibold text-[#101B2C]">Alerts & Notifications</h1>
          <p className="text-sm text-[#718096] mb-6">No business selected. Please select or create a business to view alerts.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="p-4 md:p-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">Alerts & Notifications</h1>
              <p className="text-sm text-[#718096]">Monitor and manage security alerts across your assets.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <AlertSummaryCard
              label="Total Alerts"
              value={total}
              icon={Bell}
              iconBgColor="bg-[#36D6C4]/10"
              iconColor="text-[#36D6C4]"
            />
            <AlertSummaryCard
              label="Unread Alerts"
              value={unread}
              icon={AlertTriangle}
              iconBgColor="bg-[#F2B84B]/10"
              iconColor="text-[#F2B84B]"
            />
            <AlertSummaryCard
              label="Critical Alerts"
              value={critical}
              icon={XCircle}
              iconBgColor="bg-[#EF4444]/10"
              iconColor="text-[#EF4444]"
            />
            <AlertSummaryCard
              label="Resolved Alerts"
              value={resolved}
              icon={ShieldCheck}
              iconBgColor="bg-[#22C55E]/10"
              iconColor="text-[#22C55E]"
            />
          </div>

          {loading && <p className="text-[#718096] mb-4">Loading alerts...</p>}
          {error && <p className="text-[#EF4444] mb-4">{error}</p>}

          {!loading && (
            <>
              <AlertFilterBar
                search={search}
                setSearch={setSearch}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
              />

              <AlertList
                alerts={alerts}
                search={search}
                setSearch={setSearch}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                onView={handleView}
                onMarkRead={handleMarkRead}
                onMarkUnread={handleMarkUnread}
                onResolve={handleResolve}
              />
            </>
          )}

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">
            Alerts are fetched from the FirmLock API for your selected business.
          </p>
      </div>

      {selectedAlert && (
        <AlertDetails alert={selectedAlert} onClose={() => setSelectedAlert(null)} loading={detailLoading} />
      )}
    </div>
  );
}
