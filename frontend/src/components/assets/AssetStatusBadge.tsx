import { ShieldCheck, AlertCircle, XCircle, Clock } from 'lucide-react';

export type AssetStatus = 'active' | 'warning' | 'critical' | 'pending';

const config: Record<AssetStatus, { label: string; color: string; icon: typeof ShieldCheck }> = {
  active: { label: 'Active', color: 'bg-[#22C55E]/10 text-[#22C55E]', icon: ShieldCheck },
  warning: { label: 'Warning', color: 'bg-[#F2B84B]/10 text-[#F2B84B]', icon: AlertCircle },
  critical: { label: 'Critical', color: 'bg-[#EF4444]/10 text-[#EF4444]', icon: XCircle },
  pending: { label: 'Pending', color: 'bg-[#718096]/10 text-[#718096]', icon: Clock },
};

export function AssetStatusBadge({ status }: { status: AssetStatus }) {
  const c = config[status];
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${c.color}`}>
      <Icon className="w-3 h-3" aria-hidden="true" />
      {c.label}
    </span>
  );
}
