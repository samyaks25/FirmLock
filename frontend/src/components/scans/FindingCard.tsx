import { SeverityBadge, type Severity } from './SeverityBadge';

export interface Finding {
  id: number;
  title: string;
  website: string;
  severity: Severity;
  description: string;
  remediation: string;
}

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="bg-white rounded-xl border border-[#E2E8F0] p-4">
      <div className="flex items-start justify-between gap-3 mb-2">
        <h3 className="font-medium text-[#101B2C]">{finding.title}</h3>
        <SeverityBadge severity={finding.severity} />
      </div>
      <p className="text-xs text-[#718096] mb-2">{finding.website}</p>
      <p className="text-sm text-[#172536] mb-2">{finding.description}</p>
      <p className="text-sm text-[#172536]"><span className="font-medium">Remediation: </span>{finding.remediation}</p>
    </div>
  );
}
