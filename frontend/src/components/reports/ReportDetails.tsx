import { X, FileText, Download, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { jsPDF } from 'jspdf';
import type { ScanReportResponse } from '../../types/backend';
import type { Severity } from '../scans/SeverityBadge';
import { SeverityBadge } from '../scans/SeverityBadge';

interface Props {
  report: ScanReportResponse | null;
  onClose: () => void;
  loading?: boolean;
  error?: string | null;
  onDownloadCsv: (scanId: number) => void;
}

const getScoreColor = (score: number) => {
  if (score >= 80) return { bg: 'bg-[#22C55E]/10', text: 'text-[#22C55E]', border: 'border-[#22C55E]/20' };
  if (score >= 60) return { bg: 'bg-[#F2B84B]/10', text: 'text-[#F2B84B]', border: 'border-[#F2B84B]/20' };
  return { bg: 'bg-[#EF4444]/10', text: 'text-[#EF4444]', border: 'border-[#EF4444]/20' };
};

function toSeverity(severity: string): Severity {
  const cap = (severity || 'Info').charAt(0).toUpperCase() + (severity || 'Info').slice(1).toLowerCase();
  return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(cap) ? (cap as Severity) : 'Info';
}

function fmtDate(value: string | null | undefined) {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not available';
  return date.toLocaleDateString();
}

export function ReportDetails({ report, onClose, loading = false, error = null, onDownloadCsv }: Props) {
  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
        <div className="bg-white rounded-xl w-full max-w-4xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
          <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
            <h2 className="text-lg font-semibold text-[#101B2C]">Report Details</h2>
            <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
              <X className="w-5 h-5 text-[#718096]" />
            </button>
          </div>
          <div className="p-8 flex flex-col items-center justify-center gap-3 text-[#718096]">
            <div className="w-8 h-8 rounded-full border-2 border-[#E2E8F0] border-t-[#36D6C4] animate-spin" aria-hidden="true" />
            <p>Loading report...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
        <div className="bg-white rounded-xl w-full max-w-2xl shadow-xl animate-in zoom-in-95">
          <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0]">
            <h2 className="text-lg font-semibold text-[#101B2C]">Report Details</h2>
            <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
              <X className="w-5 h-5 text-[#718096]" />
            </button>
          </div>
          <div className="p-6">
            <div className="flex items-start gap-3 rounded-lg border border-[#EF4444]/20 bg-[#EF4444]/5 p-4">
              <AlertTriangle className="w-5 h-5 text-[#EF4444] mt-0.5" aria-hidden="true" />
              <div>
                <p className="font-medium text-[#101B2C]">Unable to load report</p>
                <p className="text-sm text-[#718096] mt-1">{error}</p>
              </div>
            </div>
            <div className="mt-5 flex justify-end">
              <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#E2E8F0] text-[#101B2C] hover:bg-[#F4F7FA]">Close</button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const risk = report.risk_assessment ?? null;
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
  const score = typeof risk?.security_score === 'number' ? risk.security_score : (typeof report.security_score === 'number' ? report.security_score : null);
  const scoreAvailable = typeof risk?.score_available === 'boolean' ? risk.score_available : Boolean(report.score_available) && score !== null;
  const scoreConfig = score !== null ? getScoreColor(score) : { bg: 'bg-[#E2E8F0]', text: 'text-[#718096]', border: 'border-[#E2E8F0]' };
  const unavailableReason = report.unavailable_reason || risk?.unavailable_reason || null;

  const downloadPdf = () => {
    try {
      const pdf = new jsPDF();
      const firmNavy = '#101B2C';
      const firmWhite = '#F4F7FA';

      pdf.setFillColor(firmNavy);
      pdf.rect(0, 0, 210, 35, 'F');
      pdf.setTextColor(firmWhite);
      pdf.setFontSize(24);
      pdf.setFont('helvetica', 'bold');
      pdf.text('FirmLock', 20, 22);
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');
      pdf.text('Security Assessment Report', 20, 30);

      let y = 50;
      pdf.setTextColor(firmNavy);
      pdf.setFontSize(18);
      pdf.setFont('helvetica', 'bold');
      pdf.text(`${report.asset_domain || 'Asset'} Security Report`, 20, y);
      y += 12;

      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor('#718096');
      const meta: Array<[string, string]> = [
        ['Asset:', report.asset_domain || 'Not available'],
        ['Business:', report.business_name || 'Not available'],
        ['Report ID:', `Scan #${report.scan_id}`],
        ['Assessment Date:', fmtDate(report.created_at)],
        ['Scan Status:', (report.scan_status || 'unknown').charAt(0).toUpperCase() + (report.scan_status || 'unknown').slice(1)],
        ['Security Score:', scoreAvailable && score !== null ? `${score}/100` : 'Not available'],
      ];
      meta.forEach(([label, value]) => {
        pdf.setFont('helvetica', 'bold');
        pdf.text(label, 20, y);
        pdf.setFont('helvetica', 'normal');
        pdf.text(value, 65, y);
        y += 7;
      });

      y += 8;
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Executive Summary', 20, y);
      y += 10;
      pdf.setFontSize(10);
      pdf.setTextColor('#4A5568');
      const summary =
        `Security assessment for ${report.asset_domain || 'asset'} (${report.business_name || 'business'}). Scan status: ${report.scan_status || 'unknown'}. ` +
        `Total findings: ${report.findings_total ?? findings.length}. ` +
        (scoreAvailable && score !== null ? `Overall security score: ${score}/100${risk?.risk_level ? ` (${risk.risk_level}` : ''}${risk?.grade ? `, grade ${risk.grade}` : ''}${risk?.risk_level ? ')' : ''}.` : (unavailableReason ? `Score not available: ${unavailableReason}` : 'Score not available.'));
      const summaryLines = pdf.splitTextToSize(summary, 170);
      pdf.text(summaryLines, 20, y);
      y += summaryLines.length * 5 + 10;

      if (findings.length > 0) {
        pdf.setFontSize(14);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(firmNavy);
        pdf.text('Detailed Findings', 20, y);
        y += 10;
        findings.forEach((f, idx) => {
          if (y > 250) { pdf.addPage(); y = 20; }
          const desc = f.description || 'No description provided.';
          const descLines = pdf.splitTextToSize(desc, 160);
          const boxHeight = Math.min(70, 18 + descLines.length * 4);
          pdf.setFillColor('#F4F7FA');
          pdf.rect(20, y, 170, boxHeight, 'F');
          pdf.setDrawColor('#E2E8F0');
          pdf.rect(20, y, 170, boxHeight);
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(firmNavy);
          pdf.setFontSize(10);
          pdf.text(`${idx + 1}. ${f.title || 'Finding'}`, 25, y + 7);
          pdf.setFontSize(8);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor('#718096');
          pdf.text(`Severity: ${f.severity || 'unknown'} | Check: ${f.check_code || 'n/a'}`, 25, y + 12);
          pdf.text(descLines, 25, y + 17);
          y += boxHeight + 4;
        });
        y += 4;
      }

      if (recommendations.length > 0) {
        if (y > 240) { pdf.addPage(); y = 20; }
        pdf.setFontSize(14);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(firmNavy);
        pdf.text('Recommendations', 20, y);
        y += 10;
        recommendations.forEach((rec, idx) => {
          if (y > 265) { pdf.addPage(); y = 20; }
          pdf.setFillColor('#F0FDF4');
          const recLines = pdf.splitTextToSize(String(rec), 145);
          const h = 8 + recLines.length * 4;
          pdf.rect(20, y, 170, h, 'F');
          pdf.setFont('helvetica', 'bold');
          pdf.setFontSize(10);
          pdf.setTextColor('#22C55E');
          pdf.text(`${idx + 1}.`, 25, y + 6);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor('#4A5568');
          pdf.text(recLines, 32, y + 6);
          y += h + 4;
        });
      }

      pdf.save(`scan-${report.scan_id}-report.pdf`);
    } catch {
      window.alert('Failed to export PDF for this report.');
    }
  };

  const handleDownloadCsv = () => onDownloadCsv(report.scan_id);
  const statusLabel = (report.scan_status || 'unknown').charAt(0).toUpperCase() + (report.scan_status || 'unknown').slice(1);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
      <div className="bg-white rounded-xl w-full max-w-4xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0] sticky top-0 bg-white z-10">
          <h2 className="text-lg font-semibold text-[#101B2C]">Report Details</h2>
          <div className="flex items-center gap-2">
            <button onClick={downloadPdf} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20">
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              Export PDF
            </button>
            <button onClick={handleDownloadCsv} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20">
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              Download CSV
            </button>
            <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
              <X className="w-5 h-5 text-[#718096]" />
            </button>
          </div>
        </div>
        <div className="p-5 space-y-6">
          <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div>
              <h3 className="text-xl font-semibold text-[#101B2C]">{report.asset_domain || 'Asset'} Security Report</h3>
              <p className="text-sm text-[#718096] mt-1">{report.business_name || 'Business'} · Scan #{report.scan_id}</p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-medium ${
                report.scan_status === 'completed' ? 'bg-[#22C55E]/10 text-[#22C55E]' :
                report.scan_status === 'failed' ? 'bg-[#EF4444]/10 text-[#EF4444]' : 'bg-[#36D6C4]/10 text-[#36D6C4]'
              }`}>
                {statusLabel}
              </span>
              <div className={`w-16 h-16 rounded-xl flex flex-col items-center justify-center ${scoreConfig.bg} border ${scoreConfig.border}`}>
                <span className={`text-2xl font-bold ${scoreConfig.text}`}>{scoreAvailable && score !== null ? score : '—'}</span>
                <span className={`text-xs font-medium ${scoreConfig.text}`}>/100</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm border border-[#E2E8F0] rounded-xl p-4">
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Report ID</p>
              <p className="font-medium text-[#101B2C] font-mono">Scan #{report.scan_id}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Asset</p>
              <p className="font-medium text-[#101B2C]">{report.asset_domain || 'Not available'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Business</p>
              <p className="font-medium text-[#101B2C]">{report.business_name || 'Not available'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Assessment Date</p>
              <p className="font-medium text-[#101B2C]">{fmtDate(report.created_at)}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Started At</p>
              <p className="font-medium text-[#101B2C]">{fmtDate(report.started_at)}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Completed At</p>
              <p className="font-medium text-[#101B2C]">{fmtDate(report.completed_at)}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Total Findings</p>
              <p className="font-medium text-[#101B2C]">{report.findings_total ?? findings.length}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Security Score</p>
              <p className="font-medium text-[#101B2C]">{scoreAvailable && score !== null ? `${score}/100` : 'Not available'}</p>
            </div>
          </div>

          {unavailableReason && !scoreAvailable && (
            <div className="bg-[#FEFDF5] border border-[#F2B84B]/30 rounded-xl p-3">
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
                <span className="text-sm text-[#718096]">{unavailableReason}</span>
              </div>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Executive Security Summary</h3>
            </div>
            <p className="text-sm text-[#718096] bg-[#F4F7FA] p-4 rounded-lg border border-[#E2E8F0]/50">
              Security assessment for <strong>{report.asset_domain || 'this asset'}</strong> under <strong>{report.business_name || 'this business'}</strong>.
              {' '}{report.findings_total ?? findings.length} finding{(report.findings_total ?? findings.length) === 1 ? '' : 's'} recorded.{' '}
              {scoreAvailable && score !== null
                ? `The overall security score is ${score}/100${risk?.risk_level ? ` (${risk.risk_level})` : ''}.`
                : (unavailableReason ? `Security score is not available: ${unavailableReason}` : 'Security score is not available for this scan.')}
            </p>
          </div>

          {risk && (
            <div className="space-y-3 border border-[#E2E8F0] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-[#36D6C4]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Risk Assessment</h3>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                <div className="bg-[#F4F7FA] rounded-xl p-3">
                  <p className="text-xs text-[#718096]">Security Score</p>
                  <p className="font-bold text-[#101B2C]">{risk.security_score ?? '—'}/100</p>
                </div>
                <div className="bg-[#F4F7FA] rounded-xl p-3">
                  <p className="text-xs text-[#718096]">Risk Level</p>
                  <p className="font-bold text-[#101B2C]">{risk.risk_level ?? '—'}</p>
                </div>
                <div className="bg-[#F4F7FA] rounded-xl p-3">
                  <p className="text-xs text-[#718096]">Grade</p>
                  <p className="font-bold text-[#101B2C]">{risk.grade ?? '—'}</p>
                </div>
                <div className="bg-[#F4F7FA] rounded-xl p-3">
                  <p className="text-xs text-[#718096]">Coverage</p>
                  <p className="font-bold text-[#101B2C]">{risk.coverage_percent ?? '—'}%</p>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Findings ({report.findings_total ?? findings.length})</h3>
            </div>
            <div className="space-y-3">
              {findings.length > 0 ? (
                findings.map((f) => (
                  <div key={f.id} className="border border-[#E2E8F0] rounded-xl overflow-hidden">
                    <div className="p-4 bg-[#F4F7FA] border-b border-[#E2E8F0] flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="font-medium text-[#101B2C]">{f.title || 'Untitled finding'}</span>
                          <SeverityBadge severity={toSeverity(f.severity)} />
                        </div>
                        <p className="text-xs text-[#718096]">Check: {f.check_code || 'Not available'}</p>
                      </div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div>
                        <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Description</p>
                        <p className="text-sm text-[#718096]">{f.description || 'No description provided.'}</p>
                      </div>
                      {f.evidence && (
                        <div className="bg-[#FEFDF5] border border-[#F2B84B]/20 rounded-lg p-3">
                          <p className="text-xs font-medium text-[#F2B84B] uppercase tracking-wider mb-1">Evidence</p>
                          <p className="text-sm text-[#718096] whitespace-pre-wrap break-words">{f.evidence}</p>
                        </div>
                      )}
                      <div className="bg-[#F0FDF4] border border-[#22C55E]/20 rounded-lg p-3">
                        <p className="text-xs font-medium text-[#22C55E] uppercase tracking-wider mb-1">Recommended Remediation</p>
                        <p className="text-sm text-[#718096]">{f.recommendation || 'No recommendation provided.'}</p>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-[#718096] text-center py-4">No findings recorded for this scan.</p>
              )}
            </div>
          </div>

          {recommendations.length > 0 && (
            <div className="space-y-3 border-t border-[#E2E8F0] pt-4">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-4 h-4 text-[#22C55E]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Recommendations</h3>
              </div>
              <ul className="space-y-2">
                {recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3 text-sm text-[#718096] bg-[#F0FDF4] border border-[#22C55E]/20 rounded-lg p-3">
                    <span className="text-[#22C55E] font-bold">{idx + 1}.</span>
                    <span>{String(rec)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="pt-4 border-t border-[#E2E8F0] text-center">
            <p className="text-xs text-[#718096] italic">
              Report data retrieved from the FirmLock API for scan #{report.scan_id}. No mock data is used.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
