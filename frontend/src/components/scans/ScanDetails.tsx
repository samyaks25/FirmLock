import { X } from 'lucide-react';
import type { Scan } from './ScanHistoryTable';
import type { Finding } from './FindingCard';
import { SeverityBadge } from './SeverityBadge';
import type { RiskAssessmentResponse } from '../../types/backend';

interface Props {
  scan: Scan;
  findings: Finding[];
  risk?: RiskAssessmentResponse | null;
  onClose: () => void;
}

export function ScanDetails({ scan, findings, risk, onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-xl w-full max-w-3xl shadow-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Scan Details</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <p><span className="font-medium text-[#101B2C]">Website:</span> {scan.website}</p>
            <p><span className="font-medium text-[#101B2C]">Domain:</span> {scan.domain}</p>
            <p><span className="font-medium text-[#101B2C]">Scan ID:</span> {scan.id}</p>
            <p><span className="font-medium text-[#101B2C]">Date:</span> {scan.date}</p>
            <p><span className="font-medium text-[#101B2C]">Status:</span> {scan.status}</p>
            <p><span className="font-medium text-[#101B2C]">Security Score:</span> {scan.score === null ? 'Not available' : `${scan.score}/100`}</p>
          </div>

          {risk && (
            <div className="bg-[#F4F7FA] rounded-lg p-4 border border-[#E2E8F0]">
              <h3 className="font-medium text-[#101B2C] mb-2">Risk Assessment</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <p><span className="font-medium text-[#101B2C]">Risk level:</span> {risk.risk_level ?? '—'}</p>
                <p><span className="font-medium text-[#101B2C]">Grade:</span> {risk.grade ?? '—'}</p>
                <p><span className="font-medium text-[#101B2C]">Score source:</span> {risk.score_source}</p>
                <p><span className="font-medium text-[#101B2C]">Findings:</span> {risk.findings_total}</p>
              </div>
              {risk.recommended_actions.length > 0 && (
                <div className="mt-3">
                  <h4 className="font-medium text-[#101B2C] text-sm mb-2">Recommended actions</h4>
                  <ul className="text-sm text-[#718096] list-disc pl-5 space-y-1">
                    {risk.recommended_actions.map((action, idx) => (
                      <li key={idx}>{action}</li>
                    ))}
                  </ul>
                </div>
              )}
              {risk.score_available === false && risk.unavailable_reason && (
                <p className="mt-3 text-xs text-[#718096]">{risk.unavailable_reason}</p>
              )}
            </div>
          )}

          <div>
            <h3 className="font-medium text-[#101B2C] mb-1">Findings ({findings.length})</h3>
            {findings.length === 0 ? (
              <p className="text-sm text-[#718096]">No findings recorded for this scan.</p>
            ) : (
              <div className="space-y-2">
                {findings.map((f) => (
                  <div key={f.id} className="border border-[#E2E8F0] rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-sm font-medium text-[#101B2C]">{f.title}</p>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p className="text-xs text-[#718096] mt-1">{f.description}</p>
                    <p className="text-sm text-[#172536] mt-1"><span className="font-medium">Remediation: </span>{f.remediation}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
