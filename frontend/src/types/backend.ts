export interface UserResponse {
  id: number;
  email: string;
  full_name: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Token {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserCreate {
  email: string;
  password: string;
  full_name?: string | null;
}

export interface UserLogin {
  email: string;
  password: string;
}

export interface BusinessResponse {
  id: number;
  name: string;
  industry: string | null;
  created_at: string;
  updated_at: string;
}

export interface BusinessCreate {
  name: string;
  industry?: string | null;
}

export interface AssetResponse {
  id: number;
  business_id: number;
  domain: string;
  authorization_confirmed: boolean;
  authorization_confirmed_at: string;
  monitoring_enabled: boolean;
  status: string;
  last_scanned_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetCreate {
  domain: string;
  authorization_confirmed: boolean;
}

export interface AssetUpdate {
  monitoring_enabled?: boolean;
  status?: 'active' | 'paused';
}

export interface FindingResponse {
  id: number;
  scan_id: number;
  check_code: string;
  title: string;
  description: string;
  severity: string;
  evidence: string | null;
  recommendation: string;
  created_at: string;
}

export interface ScanResponse {
  id: number;
  asset_id: number;
  status: string;
  security_score: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  celery_task_id: string | null;
  queue_timestamp: string | null;
  attempt_count: number;
  worker_metadata: Record<string, unknown> | null;
  findings: FindingResponse[];
}

export interface ScanAcceptedResponse {
  scan_id: number;
  asset_id: number;
  status: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface CoverageInfo {
  percentage: number;
  evaluated: number;
  total: number;
  unknown: number;
  not_applicable: number;
  threshold_percent: number;
  sufficient: boolean;
  unknown_checks: string[];
}

export interface ScoreDeduction {
  check_code: string;
  title: string;
  severity: string;
  penalty: number;
  applied_penalty: number;
  score_before: number;
  score_after: number;
  reason: string;
  recommendation: string;
}

export interface PriorityIssue {
  rank: number;
  check_code: string;
  title: string;
  severity: string;
  penalty: number;
  recommendation: string;
}

export interface ScoreWeights {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  minimum_score: number;
  maximum_score: number;
}

export interface RiskAssessmentResponse {
  scan_id: number;
  asset_id: number;
  scan_status: string;
  scan_started_at: string | null;
  scan_completed_at: string | null;
  security_score: number | null;
  score_available: boolean;
  unavailable_reason: string | null;
  base_score: number;
  total_penalty: number;
  risk_level: string | null;
  grade: string | null;
  coverage: CoverageInfo;
  findings_by_severity: SeverityCounts;
  findings_total: number;
  deductions: ScoreDeduction[];
  highest_priority_issues: PriorityIssue[];
  recommended_actions: string[];
  score_weights: ScoreWeights;
  score_source: string;
  generated_at: string;
}

export interface RiskHistoryEntry {
  scan_id: number;
  completed_at: string | null;
  security_score: number | null;
  score_available: boolean;
  risk_level: string | null;
  grade: string | null;
  coverage_percent: number;
  findings_total: number;
  severity_counts: SeverityCounts;
  unavailable_reason: string | null;
  score_source: string;
}

export interface AssetRiskResponse extends RiskAssessmentResponse {
  asset_domain: string;
  previous_assessment: RiskHistoryEntry | null;
  score_change: number | null;
}

export interface DashboardResponse {
  business_id: number;
  business_name: string;
  total_monitored_websites: number;
  active_websites: number;
  paused_websites: number;
  latest_scan: DashboardScanSummary | null;
  latest_security_scores: Record<string, unknown>;
  critical_security_findings: CriticalFindingSummary[];
  alert_counts: DashboardAlertCounts;
  recent_security_activity: RecentActivityItem[];
  security_overview: DashboardSecurityOverview;
}

export interface DashboardScanSummary {
  scan_id: number;
  asset_id: number;
  asset_domain: string;
  status: string;
  security_score: number | null;
  score_available: boolean;
  unavailable_reason: string | null;
  risk_level: string | null;
  grade: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface DashboardAlertCounts {
  total_unread: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved: number;
}

export interface CriticalFindingSummary {
  scan_id: number;
  asset_id: number;
  asset_domain: string;
  finding_id: number;
  check_code: string;
  title: string;
  severity: string;
  recommendation: string;
  detected_at: string | null;
}

export interface RecentActivityItem {
  type: string;
  occurred_at: string | null;
  title: string;
  severity: string | null;
  asset_id: number | null;
  asset_domain: string | null;
  scan_id: number | null;
  alert_id: number | null;
  status: string | null;
}

export interface DashboardSecurityOverview {
  average_security_score: number | null;
  scored_assets: number;
  overall_risk_level: string;
  latest_completed_scans: number;
}

export interface AlertResponse {
  id: number;
  business_id: number;
  asset_id: number;
  finding_id: number | null;
  title: string;
  message: string;
  severity: string;
  status: string;
  created_at: string;
  read_at: string | null;
  resolved_at: string | null;
}

export interface AlertUpdate {
  read?: boolean;
  resolved?: boolean;
}

export interface AlertSummary {
  total: number;
  unread: number;
  read: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AlertListResponse {
  items: AlertResponse[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ReportFinding {
  id: number;
  scan_id: number;
  check_code: string;
  title: string;
  description: string;
  severity: string;
  evidence: string | null;
  recommendation: string;
  created_at: string;
}

export interface ReportRiskAssessment {
  security_score: number | null;
  score_available: boolean;
  unavailable_reason: string | null;
  risk_level: string | null;
  grade: string | null;
  coverage_percent: number | null;
  checks_total: number | null;
  checks_evaluated: number | null;
  checks_unknown: number | null;
  checks_not_applicable: number | null;
  coverage_sufficient: boolean | null;
  coverage_unknown_checks: string[];
  findings_by_severity: Record<string, unknown>;
  findings_total: number;
  highest_priority_issues: Record<string, unknown>[];
  recommended_actions: string[];
  score_source: string | null;
}

export interface ScanReportResponse {
  scan_id: number;
  scan_status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  business_id: number;
  business_name: string;
  asset_id: number;
  asset_domain: string;
  security_score: number | null;
  score_available: boolean;
  unavailable_reason: string | null;
  risk_assessment: ReportRiskAssessment | null;
  scan_coverage: Record<string, unknown> | null;
  findings_total: number;
  findings_by_severity: Record<string, number>;
  findings: ReportFinding[];
  recommendations: string[];
}

export interface AssetReportHistoryEntry {
  scan_id: number;
  scan_status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  security_score: number | null;
  score_available: boolean;
  unavailable_reason: string | null;
  risk_level: string | null;
  grade: string | null;
  coverage_percent: number | null;
  findings_total: number;
  findings_by_severity: Record<string, number>;
}

export interface AssetReportsResponse {
  asset_id: number;
  asset_domain: string;
  business_id: number;
  business_name: string;
  scans: AssetReportHistoryEntry[];
}
