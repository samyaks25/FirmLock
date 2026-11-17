
interface Props {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  iconBgColor: string;
  iconColor: string;
}

export function AssetSummaryCard({ label, value, icon: Icon, iconBgColor, iconColor }: Props) {
  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-[#718096]">{label}</p>
          <p className="text-3xl font-bold text-[#101B2C] mt-1">{value}</p>
        </div>
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${iconBgColor}`} aria-hidden="true">
          <Icon className={`w-6 h-6 ${iconColor}`} aria-hidden="true" />
        </div>
      </div>
    </div>
  );
}

