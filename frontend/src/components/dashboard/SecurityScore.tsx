interface SecurityScoreProps {
  score: number;
  maxScore?: number;
  label?: string;
}

export function SecurityScore({ score = 82, maxScore = 100, label = 'Security Score' }: SecurityScoreProps) {
  const percentage = Math.min((score / maxScore) * 100, 100);
  const circumference = 2 * Math.PI * 54;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const getScoreColor = (score: number) => {
    if (score >= 80) return '#22C55E';
    if (score >= 60) return '#F2B84B';
    return '#EF4444';
  };

  const getScoreLabel = (score: number) => {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Good';
    if (score >= 40) return 'Fair';
    return 'Poor';
  };

  const scoreColor = getScoreColor(score);
  const scoreLabel = getScoreLabel(score);

  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] p-6 md:p-8">
      <div className="flex flex-col md:flex-row items-center md:items-start justify-between gap-6 md:gap-8">
        <div className="flex items-center gap-6 md:gap-8 flex-shrink-0">
          <div className="relative w-32 h-32 md:w-36 md:h-36 flex-shrink-0">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 108 108">
              <circle
                cx="54"
                cy="54"
                r="54"
                fill="none"
                stroke="#E2E8F0"
                strokeWidth="8"
                aria-hidden="true"
              />
              <circle
                cx="54"
                cy="54"
                r="54"
                fill="none"
                stroke={scoreColor}
                strokeWidth="8"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                className="transition-all duration-1000 ease-out"
                aria-hidden="true"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-4xl md:text-5xl font-bold text-[#101B2C]">{score}</span>
              <span className="text-sm text-[#718096]">/ {maxScore}</span>
            </div>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-[#101B2C]">{label}</h3>
            <p className="text-sm text-[#718096] mt-1">Last updated 2 hours ago</p>
            <div className="mt-3 flex items-center gap-2">
              <span
                className={`px-3 py-1 rounded-full text-sm font-medium ${
                  score >= 80
                    ? 'bg-[#22C55E]/10 text-[#22C55E]'
                    : score >= 60
                    ? 'bg-[#F2B84B]/10 text-[#F2B84B]'
                    : 'bg-[#EF4444]/10 text-[#EF4444]'
                }`}
              >
                {scoreLabel}
              </span>
            </div>
          </div>
        </div>

        <div className="flex-1 grid grid-cols-2 gap-4 md:gap-6 pt-4 md:pt-0 border-t md:border-t-0 md:border-l border-[#E2E8F0]">
          <div className="text-center p-4 bg-[#F4F7FA] rounded-lg">
            <p className="text-2xl font-bold text-[#101B2C]">12</p>
            <p className="text-sm text-[#718096] mt-1">Passed Checks</p>
          </div>
          <div className="text-center p-4 bg-[#F4F7FA] rounded-lg">
            <p className="text-2xl font-bold text-[#EF4444]">3</p>
            <p className="text-sm text-[#718096] mt-1">Failed Checks</p>
          </div>
          <div className="text-center p-4 bg-[#F4F7FA] rounded-lg">
            <p className="text-2xl font-bold text-[#F2B84B]">5</p>
            <p className="text-sm text-[#718096] mt-1">Warnings</p>
          </div>
          <div className="text-center p-4 bg-[#F4F7FA] rounded-lg">
            <p className="text-2xl font-bold text-[#36D6C4]">2</p>
            <p className="text-sm text-[#718096] mt-1">Info</p>
          </div>
        </div>
      </div>
    </div>
  );
}