import { useCallback, useEffect, useState } from 'react';
import { FileText, Globe, CheckCircle2, Award } from 'lucide-react';
import { api, reportsApi } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { ReportSummaryCard } from '../components/reports/ReportSummaryCard';
import { ReportTable, ReportFilterBar, type Report } from '../components/reports/ReportTable';
import { ReportDetails } from '../components/reports/ReportDetails';
import type { AssetResponse, ScanReportResponse } from '../types/backend';

function normalizeStatus(status: string): Report['status'] {
  if (status === 'completed') return 'Completed';
  if (status === 'failed') return 'Failed';
  return 'Generating';
}

export function Reports() {
  const { businessId } = useAuth();
  const [assets, setAssets] = useState<AssetResponse[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [search, setSearch] = useState('');
  const [websiteFilter, setWebsiteFilter] = useState('All');
  const [dateFilter, setDateFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedReport, setSelectedReport] = useState<ScanReportResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!businessId) return;
    setLoading(true);
    setError(null);
    try {
      const assetList = await api.get<AssetResponse[]>(`/api/businesses/${businessId}/assets`);
      setAssets(assetList);
      const assetReports = await Promise.all(assetList.map((a) => reportsApi.assetReports(a.id)));
      const merged: Report[] = [];
      assetReports.forEach((data) => {
        data.scans.forEach((entry) => {
          merged.push({
            id: String(entry.scan_id),
            scanId: entry.scan_id,
            assetId: data.asset_id,
            name: `Security Report — ${data.asset_domain}`,
            website: data.asset_domain,
            domain: data.asset_domain,
            date: entry.created_at.slice(0, 10),
            status: normalizeStatus(entry.scan_status),
            score: entry.security_score ?? null,
            findings: entry.findings_total,
          });
        });
      });
      merged.sort((a, b) => b.date.localeCompare(a.date));
      setReports(merged);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports.');
    } finally {
      setLoading(false);
    }
  }, [businessId]);

  useEffect(() => {
    if (!businessId) return;
    (async () => {
      await loadData();
    })();
  }, [businessId, loadData]);

  const handleView = async (scanId: number) => {
    setReportLoading(true);
    setReportError(null);
    setSelectedReport(null);
    try {
      const report = await reportsApi.scanReport(scanId);
      setSelectedReport(report);
    } catch (err) {
      setReportError(err instanceof Error ? err.message : 'Failed to load report.');
    } finally {
      setReportLoading(false);
    }
  };

  const handleCloseReport = () => {
    setSelectedReport(null);
    setReportError(null);
    setReportLoading(false);
  };

  const handleDownloadCsv = async (scanId: number) => {
    setError(null);
    try {
      const csv = await reportsApi.scanReportCsv(scanId);
      const blob = new Blob([csv], { type: 'text/csv; charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${scanId}-report.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download CSV report.');
    }
  };

  const total = reports.length;
  const generated = reports.filter((r) => r.status === 'Completed').length;
  const covered = new Set(reports.map((r) => r.website)).size;
  const scored = reports.filter((r) => r.score !== null);
  const avgScore = scored.length > 0 ? Math.round(scored.reduce((acc, r) => acc + (r.score ?? 0), 0) / scored.length) : 0;

  const websites = assets.map((a) => a.domain);

  if (!businessId) {
    return (
      <div className="min-h-screen bg-[#F4F7FA]">
        <div className="p-4 md:p-6">
          <h1 className="text-2xl font-semibold text-[#101B2C]">Security Reports</h1>
          <p className="text-sm text-[#718096] mb-6">No business selected. Please select or create a business to view reports.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="p-4 md:p-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">Security Reports</h1>
              <p className="text-sm text-[#718096]">Review and manage your website security assessment reports.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <ReportSummaryCard label="Total Reports" value={total} icon={FileText} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ReportSummaryCard label="Reports Generated" value={generated} icon={CheckCircle2} iconBgColor="bg-[#22C55E]/10" iconColor="text-[#22C55E]" />
            <ReportSummaryCard label="Websites Covered" value={covered} icon={Globe} iconBgColor="bg-[#36D6C4]/10" iconColor="text-[#36D6C4]" />
            <ReportSummaryCard label="Average Security Score" value={scored.length > 0 ? `${avgScore}/100` : '—'} icon={Award} iconBgColor="bg-[#F2B84B]/10" iconColor="text-[#F2B84B]" />
          </div>

          {loading && <p className="text-[#718096] mb-4">Loading reports...</p>}
          {error && <p className="text-[#EF4444] mb-4">{error}</p>}

          {!loading && (
            <>
              <ReportFilterBar
                search={search}
                setSearch={setSearch}
                websiteFilter={websiteFilter}
                setWebsiteFilter={setWebsiteFilter}
                dateFilter={dateFilter}
                setDateFilter={setDateFilter}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                websites={websites}
              />

              <ReportTable
                reports={reports}
                search={search}
                websiteFilter={websiteFilter}
                dateFilter={dateFilter}
                statusFilter={statusFilter}
                onView={(r) => handleView(r.scanId)}
                onDownloadCsv={handleDownloadCsv}
              />
            </>
          )}

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">
            Reports are generated from completed security scans via the FirmLock API.
          </p>
      </div>

      {(selectedReport || reportLoading || reportError) && (
        <ReportDetails
          report={selectedReport}
          onClose={handleCloseReport}
          loading={reportLoading}
          error={reportError}
          onDownloadCsv={handleDownloadCsv}
        />
      )}
    </div>
  );
}
