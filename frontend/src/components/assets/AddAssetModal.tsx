import { useState } from 'react';
import { X } from 'lucide-react';

interface Props {
  open: boolean;
  onClose: () => void;
  onAdd: (url: string) => void;
}

export function AddAssetModal({ open, onClose, onAdd }: Props) {
  const [url, setUrl] = useState('');
  const [owns, setOwns] = useState(false);
  const [error, setError] = useState('');

  if (!open) return null;

  const validate = (v: string) => {
    try {
      const u = new URL(v.trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'URL must start with http:// or https://';
      if (!u.hostname) return 'Invalid URL';
      return '';
    } catch {
      return 'Please enter a valid URL (e.g. https://example.com)';
    }
  };

  const submit = () => {
    const e = validate(url);
    if (e) { setError(e); return; }
    if (!owns) { setError('You must confirm ownership or authorization to monitor this website.'); return; }
    onAdd(url.trim());
    setUrl('');
    setOwns(false);
    setError('');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-xl w-full max-w-md shadow-xl">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
          <h2 className="text-lg font-semibold text-[#101B2C]">Add Website</h2>
          <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
            <X className="w-5 h-5 text-[#718096]" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-sm font-medium text-[#172536] mb-1">Website URL</label>
            <input
              value={url}
              onChange={(e) => { setUrl(e.target.value); setError(''); }}
              placeholder="https://example.com"
              className="w-full px-3 py-2 border border-[#E2E8F0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#36D6C4]"
            />
          </div>
          <label className="flex items-start gap-2 text-sm text-[#172536]">
            <input type="checkbox" checked={owns} onChange={(e) => setOwns(e.target.checked)} className="mt-1" />
            <span>I own or am authorised to monitor this website.</span>
          </label>
          {error && <p className="text-sm text-[#EF4444]">{error}</p>}
        </div>
        <div className="flex items-center justify-end gap-2 p-5 border-t border-[#E2E8F0]">
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-[#E2E8F0] hover:bg-[#F4F7FA]">Cancel</button>
          <button onClick={submit} className="px-4 py-2 text-sm rounded-lg bg-[#36D6C4] text-[#101B2C] font-medium hover:opacity-90">Add Website</button>
        </div>
      </div>
    </div>
  );
}
