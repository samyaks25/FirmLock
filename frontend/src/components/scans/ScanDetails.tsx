import { X } from 'lucide-react';
import type { Scan } from './ScanHistoryTable';
import type { Finding } from './FindingCard';
import { SeverityBadge } from './SeverityBadge';

interface Props {
  scan: Scan;
  findings: Finding[];
  onClose: () => void;
}

export function ScanDetails({ scan, findings, onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-xl w-full max-w-3xl shadow-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Scan Details (demo)</h2>
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
            <p><span className="font-medium text-[#101B2C]">Security Score:</span> {scan.score}/100</p>
          </div>
          <div>
            <h3 className="font-medium text-[#101B2C] mb-1">Overview</h3>
            <p className="text-sm text-[#718096]">Demonstration scan overview. No real assessment performed.</p>
          </div>
          <div>
            <h3 className="font-medium text-[#101B2C] mb-1">Passed checks: {scan.score > 50 ? 42 : 20} (demo)</h3>
            <h3 className="font-medium text-[#101B2C] mb-1">Failed checks: {scan.issues} (demo)</h3>
          </div>
          <div>
            <h3 className="font-medium text-[#101B2C] mb-2">Findings</h3>
            <div className="space-y-2">
              {findings.slice(0, 3).map((f) => (
                <div key={f.id} className="border border-[#E2E8F0] rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium text-[#101B2C]">{f.title}</p>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <p className="text-xs text-[#718096] mt-1">{f.description}</p>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3 className="font-medium text-[#101B2C] mb-1">Recommendations</h3>
            <ul className="text-sm text-[#718096] list-disc pl-5">
              <li>Apply security patches and updates (demo).</li>
              <li>Review and remediate flagged findings (demo).</li>
              <li>Re-scan after remediation (demo).</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
