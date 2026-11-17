import { Search, Filter, Check, Bell, ShieldCheck } from 'lucide-react';
import { AlertSeverityBadge, type AlertSeverity } from './AlertSeverityBadge';

export type AlertCategory = string;

export interface Alert {
  id: string;
  backendId: number;
  title: string;
  website: string;
  domain: string;
  category: AlertCategory;
  severity: AlertSeverity;
  status: 'unread' | 'read' | 'resolved';
  read: boolean;
  resolved: boolean;
  date: string;
  time: string;
  description: string;
  impact: string;
  remediation: string;
}

export interface AlertListProps {
  alerts: Alert[];
  search: string;
  setSearch: (v: string) => void;
  severityFilter: string;
  setSeverityFilter: (v: string) => void;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  onView: (backendId: number) => void;
  onMarkRead: (backendId: number) => void;
  onMarkUnread: (backendId: number) => void;
  onResolve: (backendId: number) => void;
}

const severityOptions = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'] as const;
const statusOptions = ['All', 'Unread', 'Read', 'Resolved'] as const;

export function AlertFilterBar({
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  statusFilter,
  setStatusFilter,
}: {
  search: string;
  setSearch: (v: string) => void;
  severityFilter: string;
  setSeverityFilter: (v: string) => void;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
}) {
  return (
    <div className="flex flex-col sm:flex-row gap-3 mb-4">
      <div className="relative max-w-md flex-1">
        <Search className="w-4 h-4 text-[#718096] absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search alerts..."
          className="w-full pl-9 pr-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
        />
      </div>
      <div className="flex gap-2">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] min-w-[140px]"
        >
          {severityOptions.map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4] min-w-[120px]"
        >
          {statusOptions.map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
      </div>
    </div>
  );
}

export function AlertList({
  alerts,
  search,
  severityFilter,
  statusFilter,
  onView,
  onMarkRead,
  onMarkUnread,
  onResolve,
}: AlertListProps) {
  const filtered = alerts.filter((a) => {
    const matchesSearch =
      a.title.toLowerCase().includes(search.toLowerCase()) ||
      a.website.toLowerCase().includes(search.toLowerCase()) ||
      a.domain.toLowerCase().includes(search.toLowerCase()) ||
      a.category.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'All' || a.severity === severityFilter;
    const matchesStatus =
      statusFilter === 'All' || a.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const unreadCount = alerts.filter((a) => a.status === 'unread').length;

  if (filtered.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-[#E2E8F0] p-8 text-center text-[#718096]">
        {alerts.length === 0 ? (
          <>
            <Bell className="w-12 h-12 mx-auto text-[#E2E8F0] mb-3" aria-hidden="true" />
            <p className="font-medium text-[#101B2C]">No alerts yet</p>
            <p className="text-sm mt-1">Alerts will appear here when security issues are detected.</p>
          </>
        ) : (
          <>
            <Filter className="w-12 h-12 mx-auto text-[#E2E8F0] mb-3" aria-hidden="true" />
            <p className="font-medium text-[#101B2C]">No alerts match your filters</p>
            <p className="text-sm mt-1">Try adjusting your search or filter criteria.</p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] overflow-hidden">
      {unreadCount > 0 && (
        <div className="px-4 py-3 border-b border-[#E2E8F0] bg-[#F4F7FA] flex items-center justify-between">
          <p className="text-sm text-[#718096]">
            {unreadCount} unread alert{unreadCount !== 1 ? 's' : ''}
          </p>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full" role="table">
          <thead>
            <tr className="bg-[#F4F7FA] border-b border-[#E2E8F0]">
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">
                Alert
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">
                Website
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden lg:table-cell">
                Category
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">
                Severity
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider hidden md:table-cell">
                Date &amp; Time
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-[#718096] uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold text-[#718096] uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E2E8F0]/50">
            {filtered.map((a) => (
              <tr
                key={a.id}
                className={`hover:bg-[#F4F7FA]/50 transition-colors ${a.status === 'unread' ? 'bg-[#FEFDF5]' : ''}`}
              >
                <td className="px-4 py-4">
                  <div className="flex items-start gap-3">
                    <div
                      className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                        a.severity === 'Critical'
                          ? 'bg-[#EF4444]/10'
                          : a.severity === 'High'
                          ? 'bg-[#F2B84B]/10'
                          : a.severity === 'Medium'
                          ? 'bg-[#36D6C4]/10'
                          : 'bg-[#718096]/10'
                      }`}
                    >
                      <Bell className={`w-4 h-4 ${
                        a.severity === 'Critical'
                          ? 'text-[#EF4444]'
                          : a.severity === 'High'
                          ? 'text-[#F2B84B]'
                          : a.severity === 'Medium'
                          ? 'text-[#36D6C4]'
                          : 'text-[#718096]'
                      }`} aria-hidden="true" />
                    </div>
                    <div className="min-w-0">
                      <p className={`font-medium text-[#101B2C] ${a.status !== 'unread' ? 'text-[#718096]' : ''}`}>
                        {a.title}
                      </p>
                      <p className="text-xs text-[#718096] truncate">{a.domain}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-4 hidden md:table-cell">
                  <p className="text-sm text-[#172536]">{a.website}</p>
                </td>
                <td className="px-4 py-4 hidden lg:table-cell text-sm text-[#718096]">{a.category}</td>
                <td className="px-4 py-4">
                  <AlertSeverityBadge severity={a.severity} />
                </td>
                <td className="px-4 py-4 hidden md:table-cell text-sm text-[#718096]">
                  {a.date} {a.time}
                </td>
                <td className="px-4 py-4">
                  <span
                    className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                      a.status === 'resolved'
                        ? 'bg-[#22C55E]/10 text-[#22C55E]'
                        : a.status === 'read'
                          ? 'bg-[#E2E8F0] text-[#718096]'
                          : 'bg-[#36D6C4]/10 text-[#36D6C4]'
                    }`}
                  >
                    {a.status === 'resolved' ? (
                      <>
                        <ShieldCheck className="w-3 h-3" aria-hidden="true" />
                        Resolved
                      </>
                    ) : a.status === 'read' ? (
                      <>
                        <Check className="w-3 h-3" aria-hidden="true" />
                        Read
                      </>
                    ) : (
                      <>
                        <Bell className="w-3 h-3" aria-hidden="true" />
                        Unread
                      </>
                    )}
                  </span>
                </td>
                <td className="px-4 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    {a.status === 'unread' && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onMarkRead(a.backendId);
                        }}
                        className="p-1.5 rounded-lg hover:bg-[#E2E8F0] text-[#718096] transition-colors"
                        aria-label="Mark as read"
                        title="Mark as read"
                      >
                        <Check className="w-4 h-4" />
                      </button>
                    )}
                    {a.status === 'read' && (
                      <>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onMarkUnread(a.backendId);
                          }}
                          className="p-1.5 rounded-lg hover:bg-[#E2E8F0] text-[#718096] transition-colors"
                          aria-label="Mark as unread"
                          title="Mark as unread"
                        >
                          <Bell className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onResolve(a.backendId);
                          }}
                          className="p-1.5 rounded-lg hover:bg-[#F4F7FA] text-[#EF4444] transition-colors"
                          aria-label="Resolve alert"
                          title="Resolve"
                        >
                          <ShieldCheck className="w-4 h-4" />
                        </button>
                      </>
                    )}
                    {a.status === 'resolved' && (
                      <button
                        onClick={() => onView(a.backendId)}
                        className="px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20"
                      >
                        View
                      </button>
                    )}
                    {(a.status === 'unread' || a.status === 'read') && (
                      <button
                        onClick={() => onView(a.backendId)}
                        className="px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20"
                      >
                        View
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}