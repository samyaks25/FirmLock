import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  iconBgColor: string;
  iconColor: string;
  trend?: {
    value: number;
    label: string;
  };
  trendDirection?: 'up' | 'down' | 'neutral';
}

export function StatCard({
  label,
  value,
  icon: Icon,
  iconBgColor,
  iconColor,
  trend,
  trendDirection = 'neutral',
}: StatCardProps) {
  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-[#718096]">{label}</p>
          <p className="text-3xl font-bold text-[#101B2C] mt-1">{value}</p>
          {trend && (
            <div className="flex items-center gap-1 mt-3">
              {trendDirection === 'up' && (
                <TrendingUp className="w-4 h-4 text-[#22C55E]" aria-hidden="true" />
              )}
              {trendDirection === 'down' && (
                <TrendingDown className="w-4 h-4 text-[#EF4444]" aria-hidden="true" />
              )}
              {trendDirection === 'neutral' && (
                <Minus className="w-4 h-4 text-[#718096]" aria-hidden="true" />
              )}
              <span
                className={`text-sm font-medium ${
                  trendDirection === 'up'
                    ? 'text-[#22C55E]'
                    : trendDirection === 'down'
                    ? 'text-[#EF4444]'
                    : 'text-[#718096]'
                }`}
              >
                {trend.value > 0 ? '+' : ''}{trend.value}% {trend.label}
              </span>
            </div>
          )}
        </div>
        <div
          className={`w-12 h-12 rounded-xl flex items-center justify-center ${iconBgColor}`}
          aria-hidden="true"
        >
          <Icon className={`w-6 h-6 ${iconColor}`} aria-hidden="true" />
        </div>
      </div>
    </div>
  );
}