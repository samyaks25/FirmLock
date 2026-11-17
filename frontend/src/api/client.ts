import type {
  AlertListResponse,
  AlertResponse,
  AlertSummary,
  AlertUpdate,
  AssetReportsResponse,
  ScanReportResponse,
  UserResponse,
  ScanResponse,
} from '../types/backend';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/$/, '');
const TOKEN_KEY = 'firmlock_auth_token';
const USER_KEY = 'firmlock_auth_user';
const BUSINESS_KEY = 'firmlock_auth_business_id';

export interface TokenPayload {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function headersWithAuth(extra: Record<string, string> = {}): Record<string, string> {
  const token = getToken();
  const headers: Record<string, string> = { ...extra };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export function getToken(): string | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(BUSINESS_KEY);
}

export function getStoredUser(): UserResponse | null {
  if (typeof localStorage === 'undefined') return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserResponse;
  } catch {
    return null;
  }
}

export function setStoredUser(user: UserResponse): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getStoredBusinessId(): number | null {
  if (typeof localStorage === 'undefined') return null;
  const raw = localStorage.getItem(BUSINESS_KEY);
  if (!raw) return null;
  const id = Number(raw);
  return Number.isFinite(id) ? id : null;
}

export function setStoredBusinessId(id: number): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(BUSINESS_KEY, String(id));
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const isJsonBody = init.body && !(init.body instanceof FormData);
  const headers: Record<string, string> = {
    ...headersWithAuth(),
    ...(isJsonBody ? { 'Content-Type': 'application/json' } : {}),
    ...((init.headers as Record<string, string>) ?? {}),
  };

  const res = await fetch(url, { ...init, headers });

  if (!res.ok) {
    const body = await parseBody(res);
    const detail = body && typeof body === 'object' && 'detail' in body ? (body as { detail?: unknown }).detail : body;
    const message = typeof detail === 'string' ? detail : `Request failed with status ${res.status}`;
    throw new ApiError(res.status, message, detail);
  }

  if (res.status === 204) return undefined as T;
  const body = await parseBody(res);
  return body as T;
}

export const api = {
  get: <T>(path: string, init?: RequestInit) => request<T>(path, { ...init, method: 'GET' }),
  post: <T>(path: string, body?: unknown, init?: RequestInit) =>
    request<T>(path, { ...init, method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown, init?: RequestInit) =>
    request<T>(path, { ...init, method: 'PATCH', body: body ? JSON.stringify(body) : undefined }),
  pollScan: (
    scanId: number,
    onStatus: (status: string) => void,
    interval = 3000,
  ): Promise<ScanResponse> =>
    new Promise((resolve, reject) => {
      const loop = async () => {
        try {
          const scan = await api.get<ScanResponse>(`/api/scans/${scanId}`);
          onStatus(scan.status);
          if (scan.status === 'completed' || scan.status === 'failed') {
            resolve(scan);
            return;
          }
          setTimeout(loop, interval);
        } catch (err) {
          reject(err);
        }
      };
      loop();
    }),
};

export interface AlertListParams {
  severity?: string;
  status?: string;
  page?: number;
  page_size?: number;
}

export const alertsApi = {
  list: (businessId: number, params: AlertListParams = {}) => {
    const searchParams = new URLSearchParams();
    if (params.severity) searchParams.set('severity', params.severity);
    if (params.status) searchParams.set('status', params.status);
    if (params.page) searchParams.set('page', String(params.page));
    if (params.page_size) searchParams.set('page_size', String(params.page_size));
    const qs = searchParams.toString();
    return api.get<AlertListResponse>(`/api/businesses/${businessId}/alerts${qs ? `?${qs}` : ''}`);
  },
  summary: (businessId: number) =>
    api.get<AlertSummary>(`/api/businesses/${businessId}/alerts/summary`),
  get: (alertId: number) => api.get<AlertResponse>(`/api/alerts/${alertId}`),
  update: (alertId: number, body: AlertUpdate) =>
    api.patch<AlertResponse>(`/api/alerts/${alertId}`, body),
};

export const reportsApi = {
  assetReports: (assetId: number) =>
    api.get<AssetReportsResponse>(`/api/assets/${assetId}/reports`),
  scanReport: (scanId: number) => api.get<ScanReportResponse>(`/api/scans/${scanId}`),
  scanReportCsv: (scanId: number) => api.get<string>(`/api/scans/${scanId}/report.csv`),
};
