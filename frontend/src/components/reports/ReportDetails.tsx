import { useState } from 'react';
import { X, FileText, Download, Shield, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import { jsPDF } from 'jspdf';
import type { Report } from './ReportTable';
import { SeverityBadge, type Severity } from '../scans/SeverityBadge';

interface Finding {
  id: number;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  remediation: string;
}

interface Props {
  report: Report | null;
  onClose: () => void;
}

const getScoreColor = (score: number) => {
  if (score >= 80) return { bg: 'bg-[#22C55E]/10', text: 'text-[#22C55E]', border: 'border-[#22C55E]/20' };
  if (score >= 60) return { bg: 'bg-[#F2B84B]/10', text: 'text-[#F2B84B]', border: 'border-[#F2B84B]/20' };
  return { bg: 'bg-[#EF4444]/10', text: 'text-[#EF4444]', border: 'border-[#EF4444]/20' };
};

const getStatusConfig = (status: Report['status']) => {
  switch (status) {
    case 'Completed':
      return { color: 'bg-[#22C55E]/10 text-[#22C55E]', label: 'Completed' };
    case 'Generating':
      return { color: 'bg-[#36D6C4]/10 text-[#36D6C4]', label: 'Generating' };
    case 'Failed':
      return { color: 'bg-[#EF4444]/10 text-[#EF4444]', label: 'Failed' };
  }
};

const mockFindings: Finding[] = [
  {
    id: 1,
    title: 'Outdated TLS Version Supported',
    category: 'SSL/TLS Configuration',
    severity: 'Critical',
    description: 'The server supports TLS 1.0 and TLS 1.1, which are deprecated and have known vulnerabilities. Modern clients should use TLS 1.2 or 1.3.',
    remediation: 'Disable TLS 1.0 and TLS 1.1 on the server. Configure the server to only support TLS 1.2 and TLS 1.3. Test compatibility with all client applications.',
  },
  {
    id: 2,
    title: 'Missing Content-Security-Policy Header',
    category: 'Security Headers',
    severity: 'High',
    description: 'The website is missing the Content-Security-Policy (CSP) header, which helps prevent XSS attacks and data injection by controlling resource loading.',
    remediation: 'Implement a Content-Security-Policy header with appropriate directives for your application. Start with report-only mode to test, then enforce.',
  },
  {
    id: 3,
    title: 'Cookie Without Secure Flag',
    category: 'Session Management',
    severity: 'Medium',
    description: 'Session cookies are missing the Secure flag, making them transmittable over non-HTTPS connections.',
    remediation: 'Set the Secure flag on all session cookies to ensure they are only sent over HTTPS connections.',
  },
  {
    id: 4,
    title: 'Verbose Error Messages Exposed',
    category: 'Information Disclosure',
    severity: 'Low',
    description: 'Detailed error messages with stack traces are exposed to users, potentially revealing sensitive system information.',
    remediation: 'Configure the application to show generic error messages in production. Log detailed errors server-side only.',
  },
  {
    id: 5,
    title: 'Missing HSTS Header',
    category: 'Security Headers',
    severity: 'Low',
    description: 'The HTTP Strict Transport Security (HSTS) header is not present, which means browsers may allow HTTP connections to the site.',
    remediation: 'Add the Strict-Transport-Security header with an appropriate max-age. Consider including subdomains and preloading.',
  },
  {
    id: 6,
    title: 'Weak Cipher Suite Enabled',
    category: 'SSL/TLS Configuration',
    severity: 'Medium',
    description: 'The server supports weak cipher suites including RC4 and 3DES, which have known cryptographic vulnerabilities.',
    remediation: 'Update the server SSL/TLS configuration to disable weak cipher suites. Enable only strong ciphers (AES-GCM, ChaCha20-Poly1305).',
  },
];

const mockSslFindings = [
  { check: 'SSL Certificate Valid', status: 'Pass', details: 'Certificate is valid and trusted (demo)' },
  { check: 'Certificate Expiry', status: 'Pass', details: 'Expires in 89 days (demo)' },
  { check: 'TLS 1.2 Supported', status: 'Pass', details: 'Modern TLS version enabled (demo)' },
  { check: 'TLS 1.3 Supported', status: 'Pass', details: 'Latest TLS version enabled (demo)' },
  { check: 'TLS 1.0/1.1 Disabled', status: 'Fail', details: 'Deprecated TLS versions still enabled (demo)' },
  { check: 'Strong Cipher Suites', status: 'Warning', details: 'Some weak ciphers still supported (demo)' },
];

const mockHeaderFindings = [
  { check: 'Content-Security-Policy', status: 'Fail', details: 'CSP header not present (demo)' },
  { check: 'X-Frame-Options', status: 'Pass', details: 'DENY (demo)' },
  { check: 'X-Content-Type-Options', status: 'Pass', details: 'nosniff (demo)' },
  { check: 'Strict-Transport-Security', status: 'Fail', details: 'HSTS header not present (demo)' },
  { check: 'Referrer-Policy', status: 'Pass', details: 'strict-origin-when-cross-origin (demo)' },
  { check: 'Permissions-Policy', status: 'Warning', details: 'Partial configuration (demo)' },
];

export function ReportDetails({ report, onClose }: Props) {
  const [exporting, setExporting] = useState(false);

  if (!report) return null;

  const scoreConfig = getScoreColor(report.score);
  const statusConfig = getStatusConfig(report.status);

  const downloadPdf = async () => {
    setExporting(true);
    const pdf = new jsPDF();

    const firmNavy = '#101B2C';
    const firmAmber = '#F2B84B';
    const firmWhite = '#F4F7FA';

    let y = 20;

    // Header with FirmLock branding
    pdf.setFillColor(firmNavy);
    pdf.rect(0, 0, 210, 35, 'F');
    pdf.setTextColor(firmWhite);
    pdf.setFontSize(24);
    pdf.setFont('helvetica', 'bold');
    pdf.text('FirmLock', 20, 22);

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.text('Security Assessment Report', 20, 30);

    // Demo disclaimer banner
    y = 45;
    pdf.setFillColor(firmAmber);
    pdf.rect(15, y, 180, 10, 'F');
    pdf.setTextColor(firmNavy);
    pdf.setFontSize(9);
    pdf.setFont('helvetica', 'bold');
    pdf.text('DEMONSTRATION DATA - No actual security assessment was performed', 20, y + 6.5);

    y = 65;

    // Report Title
    pdf.setTextColor(firmNavy);
    pdf.setFontSize(18);
    pdf.setFont('helvetica', 'bold');
    pdf.text(report.name, 20, y);
    y += 12;

    // Report metadata
    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor('#718096');

    const meta = [
      ['Website:', report.website],
      ['Domain:', report.domain],
      ['Report ID:', report.id],
      ['Assessment Date:', report.date],
      ['Generated:', new Date().toLocaleDateString()],
      ['Report Type:', 'Full Security Assessment (demo)'],
    ];

    meta.forEach(([label, value]) => {
      pdf.setFont('helvetica', 'bold');
      pdf.text(label, 20, y);
      pdf.setFont('helvetica', 'normal');
      pdf.text(value, 65, y);
      y += 7;
    });

    y += 5;

    // Security Score
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Overall Security Score', 20, y);
    y += 10;

    // Score circle representation
    const scoreColor = report.score >= 80 ? '#22C55E' : report.score >= 60 ? '#F2B84B' : '#EF4444';
    pdf.setDrawColor(scoreColor);
    pdf.setLineWidth(2);
    pdf.circle(35, y + 10, 12);
    pdf.setFontSize(20);
    pdf.setTextColor(scoreColor);
    pdf.text(`${report.score}/100`, 28, y + 14);

    pdf.setFontSize(10);
    pdf.setTextColor('#718096');
    pdf.text(report.score >= 80 ? 'Good' : report.score >= 60 ? 'Fair' : 'Poor', 55, y + 10);
    pdf.text(report.score >= 80 ? 'Good' : report.score >= 60 ? 'Fair' : 'Poor', 55, y + 16);
    y += 30;

    // Executive Summary
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Executive Summary', 20, y);
    y += 10;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.setTextColor('#4A5568');
    const summaryLines = pdf.splitTextToSize(
      `This security assessment report provides an overview of the security posture for ${report.website} (${report.domain}). The assessment evaluated SSL/TLS configuration, security headers, and common vulnerability patterns. A total of ${report.findings} findings were identified across multiple severity levels. This report contains demonstration data only.`,
      170
    );
    pdf.text(summaryLines, 20, y);
    y += summaryLines.length * 5 + 10;

    // SSL/TLS Findings
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('SSL & TLS Configuration', 20, y);
    y += 10;

    mockSslFindings.forEach((f) => {
      const statusColor = f.status === 'Pass' ? '#22C55E' : f.status === 'Fail' ? '#EF4444' : '#F2B84B';
      pdf.setFillColor(statusColor);
      pdf.circle(23, y + 2, 1.5, 'F');
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor('#4A5568');
      pdf.text(f.check, 28, y + 4);
      pdf.setTextColor('#718096');
      pdf.text(f.details, 28, y + 9);
      y += 14;
    });

    y += 5;

    // Security Headers
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Security Headers Assessment', 20, y);
    y += 10;

    mockHeaderFindings.forEach((f) => {
      const statusColor = f.status === 'Pass' ? '#22C55E' : f.status === 'Fail' ? '#EF4444' : '#F2B84B';
      pdf.setFillColor(statusColor);
      pdf.circle(23, y + 2, 1.5, 'F');
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor('#4A5568');
      pdf.text(f.check, 28, y + 4);
      pdf.setTextColor('#718096');
      pdf.text(f.details, 28, y + 9);
      y += 14;
    });

    y += 5;

    // Vulnerability Breakdown
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Vulnerability Breakdown by Severity', 20, y);
    y += 10;

    const severityCounts = {
      Critical: mockFindings.filter((f) => f.severity === 'Critical').length,
      High: mockFindings.filter((f) => f.severity === 'High').length,
      Medium: mockFindings.filter((f) => f.severity === 'Medium').length,
      Low: mockFindings.filter((f) => f.severity === 'Low').length,
    };

    const severities = [
      { label: 'Critical', count: severityCounts.Critical, color: '#EF4444' },
      { label: 'High', count: severityCounts.High, color: '#F2B84B' },
      { label: 'Medium', count: severityCounts.Medium, color: '#36D6C4' },
      { label: 'Low', count: severityCounts.Low, color: '#718096' },
    ];

    severities.forEach((s) => {
      pdf.setFillColor(s.color);
      pdf.rect(20, y, 8, 8, 'F');
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(s.color);
      pdf.text(s.label, 32, y + 5.5);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor('#4A5568');
      pdf.text(`${s.count} finding${s.count !== 1 ? 's' : ''}`, 70, y + 5.5);
      y += 12;
    });

    y += 5;

    // Findings Detail
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Detailed Findings', 20, y);
    y += 10;

    mockFindings.forEach((f, idx) => {
      if (y > 260) {
        pdf.addPage();
        y = 20;
      }

      const severityColor = f.severity === 'Critical' ? '#EF4444' : f.severity === 'High' ? '#F2B84B' : f.severity === 'Medium' ? '#36D6C4' : '#718096';

      pdf.setFillColor('#F4F7FA');
      pdf.rect(20, y, 170, 30, 'F');
      pdf.setDrawColor('#E2E8F0');
      pdf.rect(20, y, 170, 30);

      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(firmNavy);
      pdf.text(`${idx + 1}. ${f.title}`, 25, y + 7);

      pdf.setFontSize(8);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(severityColor);
      pdf.text(f.severity, 160, y + 7);

      pdf.setFontSize(8);
      pdf.setTextColor('#718096');
      pdf.text(f.category, 25, y + 12);

      const descLines = pdf.splitTextToSize(f.description, 160);
      pdf.text(descLines, 25, y + 17);
      y += 10 + descLines.length * 4;

      if (y > 255) {
        pdf.addPage();
        y = 20;
      }
    });

    y += 10;

    // Recommendations
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.setTextColor(firmNavy);
    pdf.text('Recommendations', 20, y);
    y += 10;

    const recommendations = [
      'Apply security patches and updates for all identified vulnerabilities (demo).',
      'Disable deprecated TLS versions (1.0, 1.1) and weak cipher suites (demo).',
      'Implement missing security headers: Content-Security-Policy, Strict-Transport-Security (demo).',
      'Set Secure and HttpOnly flags on all session cookies (demo).',
      'Configure custom error pages to prevent information disclosure (demo).',
      'Schedule regular security assessments to maintain security posture (demo).',
    ];

    recommendations.forEach((rec, idx) => {
      if (y > 265) {
        pdf.addPage();
        y = 20;
      }
      pdf.setFillColor('#F0FDF4');
      pdf.rect(20, y, 170, 12, 'F');
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor('#22C55E');
      pdf.text(`${idx + 1}.`, 25, y + 8);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor('#4A5568');
      const recLines = pdf.splitTextToSize(rec, 145);
      pdf.text(recLines, 30, y + 8);
      y += 14;
    });

    y += 15;

    // Footer disclaimer
    pdf.setFillColor('#F4F7FA');
    pdf.rect(15, y, 180, 15, 'F');
    pdf.setFontSize(8);
    pdf.setTextColor('#718096');
    pdf.setFont('helvetica', 'italic');
    const disclaimerLines = pdf.splitTextToSize(
      'This report contains demonstration/mock data for preview purposes only. No actual security assessment was conducted. FirmLock is not liable for any decisions made based on this demonstration data.',
      170
    );
    pdf.text(disclaimerLines, 20, y + 6);

    // Save
    pdf.save(`${report.id}_Security_Report.pdf`);
    setExporting(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-in fade-in-0">
      <div className="bg-white rounded-xl w-full max-w-4xl shadow-xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
        <div className="flex items-center justify-between p-5 border-b border-[#E2E8F0] sticky top-0 bg-white z-10">
          <h2 className="text-lg font-semibold text-[#101B2C]">Report Details (demo)</h2>
          <div className="flex items-center gap-2">
            <button onClick={downloadPdf} disabled={exporting} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-[#36D6C4]/10 text-[#36D6C4] hover:bg-[#36D6C4]/20 disabled:opacity-50">
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              {exporting ? 'Exporting...' : 'Export PDF'}
            </button>
            <button onClick={onClose} aria-label="Close" className="p-2 rounded-lg hover:bg-[#F4F7FA]">
              <X className="w-5 h-5 text-[#718096]" />
            </button>
          </div>
        </div>
        <div className="p-5 space-y-6">
          {/* Demo Banner */}
          <div className="bg-[#FEFDF5] border border-[#F2B84B]/30 rounded-xl p-3">
            <div className="flex items-center gap-2 text-sm">
              <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
              <span className="font-medium text-[#F2B84B]">Demonstration Data</span>
              <span className="text-[#718096]">This report contains mock data for preview purposes. No actual security assessment was performed.</span>
            </div>
          </div>

          {/* Header Info */}
          <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div>
              <h3 className="text-xl font-semibold text-[#101B2C]">{report.name}</h3>
              <p className="text-sm text-[#718096] mt-1">{report.website} — {report.domain}</p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-medium ${statusConfig.color}`}>
                {statusConfig.label}
              </span>
              <div className={`w-16 h-16 rounded-xl flex flex-col items-center justify-center ${scoreConfig.bg} border ${scoreConfig.border}`}>
                <span className={`text-2xl font-bold ${scoreConfig.text}`}>{report.score}</span>
                <span className={`text-xs font-medium ${scoreConfig.text}`}>/100</span>
              </div>
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm border border-[#E2E8F0] rounded-xl p-4">
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Report ID</p>
              <p className="font-medium text-[#101B2C] font-mono">{report.id}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Assessment Date</p>
              <p className="font-medium text-[#101B2C]">{report.date}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Total Findings</p>
              <p className="font-medium text-[#101B2C]">{report.findings}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Status</p>
              <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusConfig.color}`}>
                {statusConfig.label}
              </span>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Executive Security Summary</h3>
            </div>
            <p className="text-sm text-[#718096] bg-[#F4F7FA] p-4 rounded-lg border border-[#E2E8F0]/50">
              This security assessment report provides an overview of the security posture for <strong>{report.website}</strong> ({report.domain}).
              The assessment evaluated SSL/TLS configuration, security headers, and common vulnerability patterns.
              A total of <strong>{report.findings} findings</strong> were identified across multiple severity levels.
              The overall security score is <strong>{report.score}/100</strong>, indicating a{" "}
              {report.score >= 80 ? 'good' : report.score >= 60 ? 'fair' : 'poor'} security posture.
              <br /><br />
              <em className="text-[#F2B84B]">Note: This report contains demonstration data only. No actual security assessment was conducted.</em>
            </p>
          </div>

          {/* SSL/TLS Findings */}
          <div className="space-y-3 border border-[#E2E8F0] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-4 h-4 text-[#36D6C4]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">SSL & HTTPS Configuration</h3>
            </div>
            <div className="space-y-2">
              {mockSslFindings.map((f) => (
                <div key={f.check} className="flex items-center justify-between py-2 border-b border-[#E2E8F0]/50 last:border-0">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${
                      f.status === 'Pass' ? 'bg-[#22C55E]' :
                      f.status === 'Fail' ? 'bg-[#EF4444]' : 'bg-[#F2B84B]'
                    }`} />
                    <span className="text-sm font-medium text-[#172536]">{f.check}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    f.status === 'Pass' ? 'bg-[#22C55E]/10 text-[#22C55E]' :
                    f.status === 'Fail' ? 'bg-[#EF4444]/10 text-[#EF4444]' : 'bg-[#F2B84B]/10 text-[#F2B84B]'
                  }`}>
                    {f.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Security Headers */}
          <div className="space-y-3 border border-[#E2E8F0] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Info className="w-4 h-4 text-[#36D6C4]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Security Headers Assessment</h3>
            </div>
            <div className="space-y-2">
              {mockHeaderFindings.map((f) => (
                <div key={f.check} className="flex items-center justify-between py-2 border-b border-[#E2E8F0]/50 last:border-0">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${
                      f.status === 'Pass' ? 'bg-[#22C55E]' :
                      f.status === 'Fail' ? 'bg-[#EF4444]' : 'bg-[#F2B84B]'
                    }`} />
                    <span className="text-sm font-medium text-[#172536] font-mono">{f.check}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    f.status === 'Pass' ? 'bg-[#22C55E]/10 text-[#22C55E]' :
                    f.status === 'Fail' ? 'bg-[#EF4444]/10 text-[#EF4444]' : 'bg-[#F2B84B]/10 text-[#F2B84B]'
                  }`}>
                    {f.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerability Breakdown */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-[#F2B84B]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Vulnerability Breakdown by Severity</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Critical', severity: 'Critical' as Severity, count: mockFindings.filter((f) => f.severity === 'Critical').length },
                { label: 'High', severity: 'High' as Severity, count: mockFindings.filter((f) => f.severity === 'High').length },
                { label: 'Medium', severity: 'Medium' as Severity, count: mockFindings.filter((f) => f.severity === 'Medium').length },
                { label: 'Low', severity: 'Low' as Severity, count: mockFindings.filter((f) => f.severity === 'Low').length },
              ].map((s) => (
                <div key={s.label} className="bg-white border border-[#E2E8F0] rounded-xl p-4 text-center">
                  <SeverityBadge severity={s.severity} />
                  <p className="text-2xl font-bold text-[#101B2C] mt-2">{s.count}</p>
                  <p className="text-xs text-[#718096] mt-1">{s.label} Findings</p>
                </div>
              ))}
            </div>
          </div>

          {/* Detailed Findings */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-[#718096]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Detailed Findings</h3>
            </div>
            <div className="space-y-3">
              {mockFindings.map((f) => (
                <div key={f.id} className="border border-[#E2E8F0] rounded-xl overflow-hidden">
                  <div className="p-4 bg-[#F4F7FA] border-b border-[#E2E8F0] flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="font-medium text-[#101B2C]">{f.title}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      <p className="text-xs text-[#718096]">{f.category}</p>
                    </div>
                  </div>
                  <div className="p-4 space-y-3">
                    <div>
                      <p className="text-xs font-medium text-[#718096] uppercase tracking-wider mb-1">Description</p>
                      <p className="text-sm text-[#718096]">{f.description}</p>
                    </div>
                    <div className="bg-[#FEFDF5] border border-[#F2B84B]/20 rounded-lg p-3">
                      <p className="text-xs font-medium text-[#F2B84B] uppercase tracking-wider mb-1">Recommended Remediation</p>
                      <p className="text-sm text-[#718096]">{f.remediation}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className="space-y-3 border-t border-[#E2E8F0] pt-4">
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle className="w-4 h-4 text-[#22C55E]" aria-hidden="true" />
              <h3 className="font-medium text-[#101B2C]">Recommendations</h3>
            </div>
            <ul className="space-y-2">
              {[
                'Apply security patches and updates for all identified vulnerabilities (demo).',
                'Disable deprecated TLS versions (1.0, 1.1) and weak cipher suites (demo).',
                'Implement missing security headers: Content-Security-Policy, Strict-Transport-Security (demo).',
                'Set Secure and HttpOnly flags on all session cookies (demo).',
                'Configure custom error pages to prevent information disclosure (demo).',
                'Schedule regular security assessments to maintain security posture (demo).',
              ].map((rec, idx) => (
                <li key={idx} className="flex items-start gap-3 text-sm text-[#718096] bg-[#F0FDF4] border border-[#22C55E]/20 rounded-lg p-3">
                  <span className="text-[#22C55E] font-bold">{idx + 1}.</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Footer disclaimer */}
          <div className="pt-4 border-t border-[#E2E8F0] text-center">
            <p className="text-xs text-[#718096] italic">
              All data shown is demonstration/mock data for preview purposes. No actual security assessments were conducted.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}