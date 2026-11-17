import { useState } from 'react';
import { X } from 'lucide-react';

interface Asset {
  id: number;
  name: string;
  url: string;
}

export type ReportType = 'Full Security Assessment' | 'SSL & TLS Analysis' | 'Security Headers Audit' | 'Vulnerability Summary';

interface Props {
  open: boolean;
  onClose: () => void;
  assets: Asset[];
  onGenerate: (data: GenerateReportData) => void;
}

interface GenerateReportData {
  assetId: number;
  reportType: ReportType;
  startDate: string;
  endDate: string;
  includeRecommendations: boolean;
}

const reportTypes: ReportType[] = [
  'Full Security Assessment',
  'SSL & TLS Analysis',
  'Security Headers Audit',
  'Vulnerability Summary',
];

export function GenerateReportModal({ open, onClose, assets, onGenerate }: Props) {
  const [selectedAsset, setSelectedAsset] = useState<number | ''>(assets.length > 0 ? assets[0].id : '');
  const [reportType, setReportType] = useState<ReportType>('Full Security Assessment');
  const [startDate, setStartDate] = useState(() => new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10));
  const [endDate, setEndDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [includeRecommendations, setIncludeRecommendations] = useState(true);
  const [error, setError] = useState('');
  const [generating, setGenerating] = useState(false);

  const validate = () => {
    if (selectedAsset === '') {
      setError('Please select a website.');
      return false;
    }
    if (!startDate || !endDate) {
      setError('Please select a date range.');
      return false;
    }
    if (new Date(startDate) > new Date(endDate)) {
      setError('Start date must be before end date.');
      return false;
    }
    setError('');
    return true;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setGenerating(true);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    onGenerate({ assetId: selectedAsset as number, reportType, startDate, endDate, includeRecommendations });
    setGenerating(false);
    setSelectedAsset('');
    setReportType('Full Security Assessment');
    setIncludeRecommendations(true);
    setError('');
    onClose();
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-xl w-full max-w-md shadow-xl">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Generate Security Report</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]" disabled={generating}>
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-sm font-medium text-[#172536] mb-1">Website</label>
            <select
              value={selectedAsset}
              onChange={(e) => {
                setSelectedAsset(e.target.value === '' ? '' : Number(e.target.value));
                setError('');
              }}
              disabled={generating}
              className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
            >
              <option value="">Select a website...</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>{a.name} ({a.url})</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-[#172536] mb-1">Report Type</label>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value as ReportType)}
              disabled={generating}
              className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
            >
              {reportTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-[#172536] mb-1">Start Date</label>
              <input
                type="date"
                value={startDate}
                onChange={(e) => { setStartDate(e.target.value); setError(''); }}
                disabled={generating}
                className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#172536] mb-1">End Date</label>
              <input
                type="date"
                value={endDate}
                onChange={(e) => { setEndDate(e.target.value); setError(''); }}
                disabled={generating}
                className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
              />
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-[#172536]">
            <input
              type="checkbox"
              checked={includeRecommendations}
              onChange={(e) => setIncludeRecommendations(e.target.checked)}
              disabled={generating}
              className="mt-1"
            />
            <span>Include remediation recommendations</span>
          </label>
          {error && <p className="text-sm text-[#EF4444]">{error}</p>}
          <p className="text-xs text-[#718096]">This is a demo simulation. Report will contain demonstration data only.</p>
        </div>
        <div className="flex items-center justify-end gap-2 p-5 border-t border-[#E2E8F0]">
          <button onClick={onClose} disabled={generating} className="px-4 py-2 text-sm rounded-lg border border-[#E2E8F0] hover:bg-[#F4F7FA]">
            Cancel
          </button>
          <button onClick={handleSubmit} disabled={generating} className="px-4 py-2 text-sm rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90 disabled:opacity-50">
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>
    </div>
  );
}
