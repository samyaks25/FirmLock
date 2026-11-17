import { X, FileText, Download, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { jsPDF } from 'jspdf';
import type { ScanReportResponse } from '../../types/backend';
import type { Severity } from '../scans/SeverityBadge';
import { SeverityBadge } from '../scans/SeverityBadge';

interface Props {
  report: ScanReportResponse | null;
  onClose: () => void;
  loading?: boolean;
  onDownloadCsv: (scanId: number) => void;
}

const getScoreColor = (score: number) => {
  if (score >= 80) return { bg: 'bg-[#22C55E]/10', text: 'text-[#22C55E]', border: 'border-[#22C55E]/20' };
  if (score >= 60) return { bg: 'bg-[#F2B84B]/10', text: 'text-[#F2B84B]', border: 'border-[#F2B84B]/20' };
  return { bg: 'bg-[#EF4444]/10', text: 'text-[#EF4444]', border: 'border-[#EF4444]/20' };
};

function toSeverity(severity: string): Severity {
  const cap = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
  return ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(cap) ? (cap as Severity) : 'Info';
}

function fmtDate(value: string | null) {
  if (!value) return '—';
  return new Date(value).toISOString().slice(0, 10);
}

export function ReportDetails({ report, onClose, loading = false, onDownloadCsv }: Props) {
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
          <div className="p-5 text-center text-[#718096]">Loading report...</div>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const risk = report.risk_assessment;
  const score = risk?.security_score ?? report.security_score;
  const scoreAvailable = risk?.score_available ?? report.score_available;
  const scoreConfig = score !== null ? getScoreColor(score) : { bg: 'bg-[#E2E8F0]', text: 'text-[#718096]', border: 'border-[#E2E8F0]' };

  const downloadPdf = () => {
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
    pdf.text(`${report.asset_domain} Security Report`, 20, y);
    y += 12;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor('#718096');
    const meta = [
      ['Asset:', report.asset_domain],
      ['Business:', report.business_name],
      ['Report ID:', String(report.scan_id)],
      ['Assessment Date:', fmtDate(report.created_at)],
      ['Scan Status:', report.scan_status.charAt(0).toUpperCase() + report.scan_status.slice(1)],
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
      `Security assessment for ${report.asset_domain} (${report.business_name}). Scan status: ${report.scan_status}. ` +
      `Total findings: ${report.findings_total}. ` +
      (scoreAvailable && score !== null ? `Overall security score: ${score}/100 (${risk?.risk_level ?? 'N/A'}, grade ${risk?.grade ?? 'N/A'}).` : 'Score not available: ' + (report.unavailable_reason ?? ''));
    pdf.text(pdf.splitTextToSize(summary, 170), 20, y);
    y += pdf.splitTextToSize(summary, 170).length * 5 + 10;

    if (report.findings.length > 0) {
      y += 2;
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Detailed Findings', 20, y);
      y += 10;
      report.findings.forEach((f, idx) => {
        if (y > 260) { pdf.addPage(); y = 20; }
        pdf.setFillColor('#F4F7FA');
        pdf.rect(20, y, 170, 30, 'F');
        pdf.setDrawColor('#E2E8F0');
        pdf.rect(20, y, 170, 30);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(firmNavy);
        pdf.text(`${idx + 1}. ${f.title}`, 25, y + 7);
        pdf.setFontSize(8);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor('#718096');
        pdf.text(`Severity: ${f.severity}`, 25, y + 12);
        const descLines = pdf.splitTextToSize(f.description, 160);
        pdf.text(descLines, 25, y + 17);
        y += 10 + descLines.length * 4;
      });
      y += 8;
    }

    if (report.recommendations.length > 0) {
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Recommendations', 20, y);
      y += 10;
      report.recommendations.forEach((rec, idx) => {
        if (y > 265) { pdf.addPage(); y = 20; }
        pdf.setFillColor('#F0FDF4');
        pdf.rect(20, y, 170, 12, 'F');
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor('#22C55E');
        pdf.text(`${idx + 1}.`, 25, y + 8);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor('#4A5568');
        pdf.text(pdf.splitTextToSize(rec, 145), 30, y + 8);
        y += 14;
      });
    }

    pdf.save(`scan-${report.scan_id}-report.pdf`);
  };

  const handleDownloadCsv = () => onDownloadCsv(report.scan_id);

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
              <h3 className="text-xl font-semibold text-[#101B2C]">{report.asset_domain} Security Report</h3>
              <p className="text-sm text-[#718096] mt-1">{report.business_name} · Scan #{report.scan_id}</p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-medium ${
                report.scan_status === 'completed' ? 'bg-[#22C55E]/10 text-[#22C55E]' :
                report.scan_status === 'failed' ? 'bg-[#EF4444]/10 text-[#EF4444]' : 'bg-[#36D6C4]/10 text-[#36D6C4]'
              }`}>
                {report.scan_status.charAt(0).toUpperCase() + report.scan_status.slice(1)}
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
              <p className="font-medium text-[#101B2C]">{report.asset_domain}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Business</p>
              <p className="font-medium text-[#101B2C]">{report.business_name}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Assessment Date</p>
              <p className="font-medium text-[#101B2C]">{fmtDate(report.created_at)}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Completed At</p>
              <p className="font-medium text-[#101B2C]">{fmtDate(report.completed_at)}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Total Findings</p>
              <p className="font-medium text-[#101B2C]">{report.findings_total}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Score</p>
              <p className="font-medium text-[#101B2C]">{scoreAvailable && score !== null ? `${score}/100` : 'Not available'}</p>
            </div>
          </div>

          {report.unavailable_reason && !scoreAvailable && (
            <div className="bg-[#FEFDF5] border border-[#F2B84B]/30 rounded-xl p-3">
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
                <span className="text-sm text-[#718096]">{report.unavailable_reason}</span>
              </div>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Executive Security Summary</h3>
            </div>
            <p className="text-sm text-[#718096] bg-[#F4F7FA] p-4 rounded-lg border border-[#E2E8F0]/50">
              Security assessment for <strong>{report.asset_domain}</strong> under <strong>{report.business_name}</strong>.
              {report.findings_total} finding{report.findings_total !== 1 ? 's' : ''} were identified.{' '}
              {scoreAvailable && score !== null
                ? `The overall security score is ${score}/100, indicating a ${score >= 80 ? 'good' : score >= 60 ? 'fair' : 'poor'} security posture.`
                : `A security score is ${report.unavailable_reason ? 'not available (' + report.unavailable_reason + ')' : 'not available'}.`}
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
              <h3 className="font-medium text-[#101B2C]">Findings ({report.findings_total})</h3>
            </div>
            <div className="space-y-3">
              {report.findings.length > 0 ? (
                report.findings.map((f) => (
                  <div key={f.id} className="border border-[#E2E8F0] rounded-xl overflow-hidden">
                    <div className="p-4 bg-[#F4F7FA] border-b border-[#E2E8F0] flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="font-medium text-[#101B2C]">{f.title}</span>
                          <SeverityBadge severity={toSeverity(f.severity)} />
                        </div>
                        <p className="text-xs text-[#718096]">Check: {f.check_code}</p>
                      </div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div>
                        <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Description</p>
                        <p className="text-sm text-[#718096]">{f.description}</p>
                      </div>
                      {f.evidence && (
                        <div className="bg-[#FEFDF5] border border-[#F2B84B]/20 rounded-lg p-3">
                          <p className="text-xs font-medium text-[#F2B84B] uppercase tracking-wider mb-1">Evidence</p>
                          <p className="text-sm text-[#718096]">{f.evidence}</p>
                        </div>
                      )}
                      <div className="bg-[#F0FDF4] border border-[#22C55E]/20 rounded-lg p-3">
                        <p className="text-xs font-medium text-[#22C55E] uppercase tracking-wider mb-1">Recommended Remediation</p>
                        <p className="text-sm text-[#718096]">{f.recommendation}</p>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-[#718096] text-center py-4">No findings recorded for this scan.</p>
              )}
            </div>
          </div>

          {report.recommendations.length > 0 && (
            <div className="space-y-3 border-t border-[#E2E8F0] pt-4">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-4 h-4 text-[#22C55E]" aria-hidden="true" />
                <h3 className="font-medium text-[#101B2C]">Recommendations</h3>
              </div>
              <ul className="space-y-2">
                {report.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3 text-sm text-[#718096] bg-[#F0FDF4] border border-[#22C55E]/20 rounded-lg p-3">
                    <span className="text-[#22C55E] font-bold">{idx + 1}.</span>
                    <span>{rec}</span>
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
