import { useState } from 'react';
import { X } from 'lucide-react';

interface Asset { id: number; name: string; url: string; }

interface Props {
  open: boolean;
  onClose: () => void;
  assets: Asset[];
  onStart: (assetId: number) => void;
}

export function StartScanModal({ open, onClose, assets, onStart }: Props) {
  const [selected, setSelected] = useState<number | ''>('');
  const [owns, setOwns] = useState(false);
  const [error, setError] = useState('');

  if (!open) return null;

  const submit = () => {
    if (selected === '') { setError('Please select a website.'); return; }
    if (!owns) { setError('You must confirm ownership or authorisation to assess the selected website.'); return; }
    onStart(selected);
    setSelected('');
    setOwns(false);
    setError('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-xl w-full max-w-md shadow-xl">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Start New Scan</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-sm font-medium text-[#172536] mb-1">Website</label>
            <select
              value={selected}
              onChange={(e) => { setSelected(e.target.value === '' ? '' : Number(e.target.value)); setError(''); }}
              className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
            >
              <option value="">Select a website...</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>{a.name} ({a.url})</option>
              ))}
            </select>
          </div>
          <label className="flex items-start gap-2 text-sm text-[#172536]">
            <input type="checkbox" checked={owns} onChange={(e) => setOwns(e.target.checked)} className="mt-1" />
            <span>I own or am authorised to assess the selected website.</span>
          </label>
          {error && <p className="text-sm text-[#EF4444]">{error}</p>}
          <p className="text-xs text-[#718096]">This is a demo simulation only. No actual security scanning will be performed.</p>
        </div>
        <div className="flex items-center justify-end gap-2 p-5 border-t border-[#E2E8F0]">
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-[#E2E8F0] hover:bg-[#F4F7FA]">Cancel</button>
          <button onClick={submit} className="px-4 py-2 text-sm rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90">Start Scan</button>
        </div>
      </div>
    </div>
  );
}
