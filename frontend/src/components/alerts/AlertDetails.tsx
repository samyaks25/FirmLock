import { X, AlertTriangle, Globe, Shield, Info, FileText } from 'lucide-react';
import { AlertSeverityBadge } from './AlertSeverityBadge';
import type { Alert, AlertCategory } from './AlertList';

interface AlertDetailsProps {
  alert: Alert | null;
  onClose: () => void;
}

const categoryIcons: Record<AlertCategory, typeof Globe> = {
  'SSL Certificate Expiration': Shield,
  'Missing Security Headers': Info,
  'Security Vulnerabilities': AlertTriangle,
  'Domain Expiration': Globe,
  'Website Security Configuration': FileText,
};

const getCategoryConfig = (category: AlertCategory) => {
  switch (category) {
    case 'SSL Certificate Expiration':
      return { color: 'bg-[#F2B84B]/10 text-[#F2B84B]', label: 'SSL Certificate' };
    case 'Missing Security Headers':
      return { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', label: 'Security Headers' };
    case 'Security Vulnerabilities':
      return { color: 'bg-[#EF4444]/10 text-[#EF4444]', label: 'Vulnerabilities' };
    case 'Domain Expiration':
      return { color: 'bg-[#718096]/10 text-[#718096]', label: 'Domain' };
    case 'Website Security Configuration':
      return { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', label: 'Configuration' };
  }
};

export function AlertDetails({ alert, onClose }: AlertDetailsProps) {
  if (!alert) return null;

  const categoryConfig = getCategoryConfig(alert.category);
  const CategoryIcon = categoryIcons[alert.category];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
      <div className="bg-white rounded-xl w-full max-w-2xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Alert Details (demo)</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-5">
          <div className="flex items-start gap-4 p-4 bg-[#F4F7FA] rounded-xl">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
                alert.severity === 'Critical'
                  ? 'bg-[#EF4444]/10'
                  : alert.severity === 'High'
                  ? 'bg-[#F2B84B]/10'
                  : alert.severity === 'Medium'
                  ? 'bg-[#36D6C4]/10'
                  : 'bg-[#718096]/10'
              }`}
            >
              <CategoryIcon
                className={`w-6 h-6 ${
                  alert.severity === 'Critical'
                    ? 'text-[#EF4444]'
                    : alert.severity === 'High'
                    ? 'text-[#F2B84B]'
                    : alert.severity === 'Medium'
                    ? 'text-[#36D6C4]'
                    : 'text-[#718096]'
                }`}
                aria-hidden="true"
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <AlertSeverityBadge severity={alert.severity} />
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${categoryConfig.color}`}>
                  <CategoryIcon className="w-3 h-3" aria-hidden="true" />
                  {categoryConfig.label}
                </span>
              </div>
              <h3 className="text-lg font-semibold text-[#101B2C] truncate">{alert.title}</h3>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-sm border border-[#E2E8F0] rounded-xl p-4">
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Affected Domain</p>
              <p className="font-medium text-[#101B2C]">{alert.domain}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Website</p>
              <p className="font-medium text-[#101B2C]">{alert.website}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Severity</p>
              <AlertSeverityBadge severity={alert.severity} />
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Detection Date</p>
              <p className="font-medium text-[#101B2C]">{alert.date} {alert.time}</p>
            </div>
            <div className="col-span-2">
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Category</p>
              <p className="font-medium text-[#101B2C]">{alert.category}</p>
            </div>
            <div className="col-span-2">
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Status</p>
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                alert.read
                  ? 'bg-[#E2E8F0] text-[#718096]'
                  : 'bg-[#36D6C4]/10 text-[#36D6C4]'
              }`}>
                {alert.read ? 'Read' : 'Unread'}
              </span>
            </div>
          </div>

          <div className="space-y-5">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Description</h3>
              </div>
              <p className="text-sm text-[#718096] bg-[#F4F7FA] p-4 rounded-lg">{alert.description}</p>
            </div>

            <div>
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Potential Impact</h3>
              </div>
              <p className="text-sm text-[#718096] bg-[#FEFDF5] p-4 rounded-lg border border-[#F2B84B]/20">{alert.impact}</p>
            </div>

            <div>
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-[#36D6C4]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Recommended Remediation</h3>
              </div>
              <p className="text-sm text-[#718096] bg-[#F0FDF4] p-4 rounded-lg border border-[#36D6C4]/20">{alert.remediation}</p>
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