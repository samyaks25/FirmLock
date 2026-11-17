import { ShieldAlert, AlertTriangle, Info, ShieldCheck } from 'lucide-react';

export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

const config: Record<AlertSeverity, { color: string; icon: typeof ShieldAlert }> = {
  Critical: { color: 'bg-[#EF4444]/10 text-[#EF4444]', icon: ShieldAlert },
  High: { color: 'bg-[#F2B84B]/10 text-[#F2B84B]', icon: AlertTriangle },
  Medium: { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', icon: Info },
  Low: { color: 'bg-[#718096]/10 text-[#718096]', icon: ShieldCheck },
  Info: { color: 'bg-[#718096]/10 text-[#718096]', icon: Info },
};

export function AlertSeverityBadge({ severity }: { severity: AlertSeverity }) {
  const c = config[severity];
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${c.color}`}>
      <Icon className="w-3 h-3" aria-hidden="true" />
      {severity}
    </span>
  );
}