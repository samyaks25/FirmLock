import { X, AlertTriangle, Globe, Info, FileText, ShieldCheck } from 'lucide-react';
import type { AlertResponse } from '../../types/backend';
import type { AlertSeverity } from './AlertSeverityBadge';
import { AlertSeverityBadge } from './AlertSeverityBadge';

interface AlertDetailsProps {
  alert: AlertResponse | null;
  onClose: () => void;
  loading?: boolean;
}

const categoryIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  Critical: AlertTriangle,
  High: AlertTriangle,
  Medium: Info,
  Low: ShieldCheck,
  Info: Info,
};

const getCategoryConfig = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return { color: 'bg-[#EF4444]/10 text-[#EF4444]', label: 'Critical' };
    case 'high':
      return { color: 'bg-[#F2B84B]/10 text-[#F2B84B]', label: 'High' };
    case 'medium':
      return { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', label: 'Medium' };
    case 'low':
      return { color: 'bg-[#718096]/10 text-[#718096]', label: 'Low' };
    default:
      return { color: 'bg-[#718096]/10 text-[#718096]', label: 'Info' };
  }
};

export function AlertDetails({ alert, onClose, loading }: AlertDetailsProps) {
  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
        <div className="bg-white rounded-xl w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
          <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
            <h2 className="text-lg font-semibold text-[#101B2C]">Alert Details</h2>
            <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
              <X className="w-5 h-5 text-[#718096]" />
            </button>
          </div>
          <div className="p-5 text-center text-[#718096]">Loading alert details...</div>
        </div>
      </div>
    );
  }

  if (!alert) return null;

  const created = new Date(alert.created_at);
  const severity = alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1).toLowerCase();
  const categoryConfig = getCategoryConfig(alert.severity);
  const CategoryIcon = (categoryIcons[severity] ?? Globe) as typeof Globe;

  const statusLabel =
    alert.status === 'resolved'
      ? 'Resolved'
      : alert.status === 'read'
        ? 'Read'
        : 'Unread';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
      <div className="bg-white rounded-xl w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Alert Details</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-5">
          <div className="flex items-start gap-4 p-4 bg-[#F4F7FA] rounded-xl">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
                alert.severity.toLowerCase() === 'critical'
                  ? 'bg-[#EF4444]/10'
                  : alert.severity.toLowerCase() === 'high'
                    ? 'bg-[#F2B84B]/10'
                    : alert.severity.toLowerCase() === 'medium'
                      ? 'bg-[#36D6C4]/10'
                      : 'bg-[#718096]/10'
              }`}
            >
              <CategoryIcon
                className={`w-6 h-6 ${
                  alert.severity.toLowerCase() === 'critical'
                    ? 'text-[#EF4444]'
                    : alert.severity.toLowerCase() === 'high'
                      ? 'text-[#F2B84B]'
                      : alert.severity.toLowerCase() === 'medium'
                        ? 'text-[#36D6C4]'
                        : 'text-[#718096]'
                }`}
                aria-hidden="true"
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <AlertSeverityBadge severity={severity as AlertSeverity} />
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${categoryConfig.color}`}>
                  {categoryConfig.label}
                </span>
              </div>
              <h3 className="text-lg font-semibold text-[#101B2C] truncate">{alert.title}</h3>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-sm border border-[#E2E8F0] rounded-xl p-4">
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Status</p>
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                alert.status === 'resolved'
                  ? 'bg-[#22C55E]/10 text-[#22C55E]'
                  : alert.status === 'read'
                    ? 'bg-[#E2E8F0] text-[#718096]'
                    : 'bg-[#36D6C4]/10 text-[#36D6C4]'
              }`}>
                {statusLabel}
              </span>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Severity</p>
              <p className="font-medium text-[#101B2C]">{severity}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Business ID</p>
              <p className="font-medium text-[#101B2C] font-mono">{alert.business_id}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Asset ID</p>
              <p className="font-medium text-[#101B2C] font-mono">{alert.asset_id}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Finding ID</p>
              <p className="font-medium text-[#101B2C] font-mono">{alert.finding_id ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Detected At</p>
              <p className="font-medium text-[#101B2C]">{created.toISOString().slice(0, 10)} {created.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: true })}</p>
            </div>
            {alert.read_at && (
              <div>
                <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Read At</p>
                <p className="font-medium text-[#101B2C]">{new Date(alert.read_at).toISOString().slice(0, 10)}</p>
              </div>
            )}
            {alert.resolved_at && (
              <div>
                <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Resolved At</p>
                <p className="font-medium text-[#101B2C]">{new Date(alert.resolved_at).toISOString().slice(0, 10)}</p>
              </div>
            )}
          </div>

          <div className="space-y-5">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Description</h3>
              </div>
              <p className="text-sm text-[#718096] bg-[#F4F7FA] p-4 rounded-lg">{alert.message}</p>
            </div>
          </div>

          <div className="pt-4 border-t border-[#E2E8F0] flex items-center justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-[#E2E8F0] text-sm font-medium text-[#172536] hover:bg-[#F4F7FA]"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
