/**
 * Centralized typed API client for RepoLens backend communication.
 * Includes credentials by default and automatically attaches X-CSRF-Token on state-modifying requests.
 */

import {
  ChangeAnalysisPRRequest,
  ChangeAnalysisReportResponse,
  ChangeAnalysisRequest,
  ChangeAnalysisResponse,
  ChangeAnalysisSummary,
  ChangeAnalysisTelemetry,
  ChangeImpact,
  ChangeReviewReport,
  DeliveryPreviewResponse,
  DeliveryRequest,
  DeliveryResponse,
  FixPlan,
  Finding,
  HealthResponse,
  JobResource,
  PatchProposal,
  PatchRejectRequest,
  PatchResponse,
  PatchReviewRequest,
  PatchReviseRequest,
  PatchWorkflowResult,
  ResearchResult,
  RemediationAccepted,
  ReviewPublicationApproveRequest,
  ReviewPublicationPreviewResponse,
  ReviewPublicationPublishResponse,
  Scan,
  ScanCreate,
  ScanReportResource,
  ScanTelemetry,
  StructuralDiffResult,
  UserLoginRequest,
  UserRegisterRequest,
  UserResponse,
} from '@/types/domain';

export function getApiBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, '');
  if (process.env.NODE_ENV === 'production') {
    if (!configured) {
      throw new Error('RepoLens production requires NEXT_PUBLIC_API_BASE_URL.');
    }
    let apiOrigin: URL;
    try {
      apiOrigin = new URL(configured);
    } catch {
      throw new Error('RepoLens production requires an absolute NEXT_PUBLIC_API_BASE_URL origin.');
    }
    const apiHost = apiOrigin.hostname.toLowerCase();
    const isIpLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(apiHost) || apiHost.startsWith('[');
    const isDevelopmentHost =
      apiHost === 'localhost' || apiHost.endsWith('.localhost') || apiHost === 'testserver';
    if (
      apiOrigin.protocol !== 'https:' ||
      apiOrigin.username ||
      apiOrigin.password ||
      apiOrigin.search ||
      apiOrigin.hash ||
      (apiOrigin.pathname !== '/' && apiOrigin.pathname !== '') ||
      isIpLiteral ||
      isDevelopmentHost
    ) {
      throw new Error('RepoLens production API base must be a credential-free HTTPS origin.');
    }
    return apiOrigin.origin;
  }
  if (configured) return configured;
  if (typeof window !== 'undefined') {
    // Keep localhost/127.0.0.1 consistent with the page host. Cookies are
    // host-scoped, so mixing the two names creates a false logged-in state.
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return 'http://localhost:8000';
}

type ApiErrorDetail = {
  message?: unknown;
  error_code?: unknown;
  detail?: unknown;
  msg?: unknown;
};

export class ApiError extends Error {
  readonly status: number;
  readonly errorCode?: string;

  constructor(message: string, status: number, errorCode?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errorCode = errorCode;
  }
}

function cleanMessage(value: string): string {
  return value.trim().replace(/^Value error,\s*/i, '');
}

function humanizeErrorCode(value: string): string {
  const text = value.toLowerCase().replace(/_/g, ' ');
  return text ? text[0].toUpperCase() + text.slice(1) : '';
}

function extractApiMessage(value: unknown): string | null {
  if (typeof value === 'string') return cleanMessage(value) || null;
  if (Array.isArray(value)) {
    const messages = value.map(extractApiMessage).filter((item): item is string => Boolean(item));
    return messages.length ? [...new Set(messages)].join('. ') : null;
  }
  if (!value || typeof value !== 'object') return null;
  const detail = value as ApiErrorDetail;
  return (
    extractApiMessage(detail.message) ||
    extractApiMessage(detail.msg) ||
    extractApiMessage(detail.detail) ||
    (typeof detail.error_code === 'string' ? humanizeErrorCode(detail.error_code) : null)
  );
}

function extractErrorCode(value: unknown): string | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const body = value as ApiErrorDetail;
  if (typeof body.error_code === 'string') return body.error_code;
  if (body.detail && typeof body.detail === 'object' && !Array.isArray(body.detail)) {
    const nested = body.detail as ApiErrorDetail;
    return typeof nested.error_code === 'string' ? nested.error_code : undefined;
  }
  return undefined;
}

export async function apiErrorFromResponse(response: Response, fallback: string): Promise<ApiError> {
  let payload: unknown = null;
  try {
    const body = await response.text();
    if (body) {
      try {
        payload = JSON.parse(body);
      } catch {
        if (response.headers.get('content-type')?.toLowerCase().startsWith('text/plain')) {
          payload = body.slice(0, 240);
        }
      }
    }
  } catch {
    // The fallback remains authoritative when an error body cannot be read.
  }
  const message = extractApiMessage(payload) || `${fallback} (${response.status})`;
  return new ApiError(message, response.status, extractErrorCode(payload));
}

export function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === 'string' && error.trim()) return error;
  return fallback;
}

/**
 * Extract CSRF token from client cookie.
 */
export function getCsrfToken(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)repolens_csrf=([^;]*)/);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

/**
 * Standard fetch wrapper attaching credentials and CSRF tokens.
 */
export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const url = input.startsWith('http') ? input : `${getApiBaseUrl()}${input}`;
  const method = (init?.method || 'GET').toUpperCase();
  const headers = new Headers(init?.headers || {});

  if (!headers.has('Content-Type') && method !== 'GET' && method !== 'HEAD') {
    headers.set('Content-Type', 'application/json');
  }

  // Attach CSRF token on state-modifying requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = getCsrfToken();
    if (csrfToken && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  try {
    return await fetch(url, {
      ...init,
      headers,
      credentials: 'include',
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError('Unable to reach the RepoLens server. Check that the backend is running.', 0, 'NETWORK_ERROR');
  }
}

/* ========================================================================= */
/* Authentication API                                                        */
/* ========================================================================= */

export async function registerUser(payload: UserRegisterRequest): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Registration failed');
  }

  return response.json();
}

export async function loginUser(payload: UserLoginRequest): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Login failed');
  }

  return response.json();
}

export async function logoutUser(): Promise<{ message: string }> {
  const response = await apiFetch('/api/v1/auth/logout', {
    method: 'POST',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Logout failed');
  }

  return response.json();
}

export async function fetchCurrentUser(): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/me', {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Authentication required');
  }

  return response.json();
}

/* ========================================================================= */
/* System & Health API                                                       */
/* ========================================================================= */

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await apiFetch('/health', {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Health check failed');
  }

  return response.json();
}

/* ========================================================================= */
/* Scan API                                                                  */
/* ========================================================================= */

export async function startScan(payload: ScanCreate): Promise<Scan> {
  const response = await apiFetch('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Scan initiation failed');
  }

  return response.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const response = await apiFetch(`/api/v1/scans/${scanId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch scan status');
  }

  return response.json();
}

export async function requestScanReport(scanId: string): Promise<ScanReportResource> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/reports`, { method: 'POST' });
  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Report generation request failed');
  }
  return response.json();
}

export async function fetchLatestScanReport(
  scanId: string,
  signal?: AbortSignal
): Promise<ScanReportResource | null> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/reports/latest`, {
    cache: 'no-store',
    signal,
  });
  if (response.status === 404) return null;
  if (!response.ok) throw await apiErrorFromResponse(response, 'Failed to restore report status');
  return response.json();
}

export async function fetchReport(reportId: string, signal?: AbortSignal): Promise<ScanReportResource> {
  const response = await apiFetch(`/api/v1/reports/${reportId}`, { cache: 'no-store', signal });
  if (!response.ok) throw await apiErrorFromResponse(response, 'Failed to fetch report status');
  return response.json();
}

export async function downloadReportPdf(reportId: string): Promise<Blob> {
  const response = await apiFetch(`/api/v1/reports/${reportId}/download`, { cache: 'no-store' });
  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Report download failed');
  }
  const contentType = response.headers.get('content-type')?.toLowerCase() || '';
  if (!contentType.startsWith('application/pdf')) {
    throw new Error('The report server returned an unexpected file type.');
  }
  return response.blob();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/findings`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch scan findings');
  }

  return response.json();
}

export async function listScans(limit = 20, offset = 0): Promise<Scan[]> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const response = await apiFetch(`/api/v1/scans?${params.toString()}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch repository scans');
  }

  return response.json();
}

export async function fetchScanTelemetry(scanId: string): Promise<ScanTelemetry> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/telemetry`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch scan telemetry');
  }

  return response.json();
}

/* ========================================================================= */
/* Findings & Remediation API                                                */
/* ========================================================================= */

export async function fetchFinding(findingId: string): Promise<Finding> {
  const response = await apiFetch(`/api/v1/findings/${findingId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch finding');
  }

  return response.json();
}

const REMEDIATION_POLL_INTERVAL_MS = 1000;
const REMEDIATION_POLL_ATTEMPTS = 300;
const TERMINAL_JOB_STATES = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT']);

function isRemediationAccepted(value: unknown): value is RemediationAccepted {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'job_id' in value &&
      typeof (value as RemediationAccepted).job_id === 'string'
  );
}

export async function fetchJob(jobId: string): Promise<JobResource> {
  const response = await apiFetch(`/api/v1/jobs/${jobId}`, { cache: 'no-store' });
  if (!response.ok) throw await apiErrorFromResponse(response, 'Failed to fetch job status');
  return response.json();
}

export async function fetchJobResult<T>(jobId: string): Promise<T> {
  const response = await apiFetch(`/api/v1/jobs/${jobId}/result`, { cache: 'no-store' });
  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch job result');
  }
  return response.json();
}

async function resolveRemediationResponse<T>(response: Response, failureLabel: string): Promise<T> {
  if (!response.ok) {
    throw await apiErrorFromResponse(response, failureLabel);
  }
  const value: unknown = await response.json();
  if (!isRemediationAccepted(value)) return value as T;

  for (let attempt = 0; attempt < REMEDIATION_POLL_ATTEMPTS; attempt += 1) {
    const job = await fetchJob(value.job_id);
    if (job.state === 'SUCCEEDED') return fetchJobResult<T>(job.id);
    if (TERMINAL_JOB_STATES.has(job.state)) {
      const failure = job.failures.at(-1)?.message;
      throw new Error(failure || `${failureLabel}: job ended in ${job.state.toLowerCase()}`);
    }
    await new Promise((resolve) => setTimeout(resolve, REMEDIATION_POLL_INTERVAL_MS));
  }
  throw new Error(`${failureLabel}: job is still running; retry to restore its durable result`);
}

export async function requestFindingResearch(findingId: string): Promise<ResearchResult> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/research`, {
    method: 'POST',
    headers: { Prefer: 'respond-async' },
  });
  return resolveRemediationResponse<ResearchResult>(response, 'Failed to research finding');
}

export async function requestFixPlan(findingId: string): Promise<FixPlan> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/plan`, {
    method: 'POST',
    headers: { Prefer: 'respond-async' },
  });
  return resolveRemediationResponse<FixPlan>(response, 'Failed to generate fix plan');
}

export async function requestPatchGeneration(findingId: string): Promise<PatchWorkflowResult> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/patch`, {
    method: 'POST',
    headers: { Prefer: 'respond-async' },
  });
  return resolveRemediationResponse<PatchWorkflowResult>(response, 'Failed to generate patch');
}

/* ========================================================================= */
/* Patches & Human-in-the-Loop Review API                                    */
/* ========================================================================= */

export async function fetchPatch(patchId: string): Promise<PatchResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch patch');
  }

  return response.json();
}

export async function fetchScanPatches(scanId: string): Promise<PatchResponse[]> {
  const response = await apiFetch(`/api/v1/patches/scan/${scanId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch scan patches');
  }

  return response.json();
}

export async function approvePatch(
  patchId: string,
  payload: PatchReviewRequest = { approved_by: 'user' }
): Promise<PatchResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}/approve`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to approve patch');
  }

  return response.json();
}

export async function rejectPatch(
  patchId: string,
  payload: PatchRejectRequest
): Promise<PatchResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}/reject`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to reject patch');
  }

  return response.json();
}

export async function revisePatch(
  patchId: string,
  payload: PatchReviseRequest
): Promise<PatchResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}/revise`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to request patch revision');
  }

  return response.json();
}

/* ========================================================================= */
/* Safe GitHub Delivery API (Phase 5)                                         */
/* ========================================================================= */

export async function fetchDeliveryPreview(patchId: string): Promise<DeliveryPreviewResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}/delivery-preview`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch delivery preview');
  }

  return response.json();
}

export async function requestDelivery(
  patchId: string,
  payload: DeliveryRequest = { requested_by: 'user' }
): Promise<DeliveryResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}/deliver`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Delivery failed');
  }

  return response.json();
}

export async function fetchDelivery(deliveryId: string): Promise<DeliveryResponse> {
  const response = await apiFetch(`/api/v1/deliveries/${deliveryId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch delivery status');
  }

  return response.json();
}

export async function fetchDeliveryByPatch(patchId: string): Promise<DeliveryResponse | null> {
  const response = await apiFetch(`/api/v1/deliveries/patch/${patchId}`, {
    cache: 'no-store',
  });

  if (response.status === 404 || response.status === 204) {
    return null;
  }
  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch delivery status');
  }

  return response.json();
}

/* ========================================================================= */
/* Change Intelligence & PR Impact Analysis API (Phase 6)                    */
/* ========================================================================= */

export async function startChangeAnalysis(
  payload: ChangeAnalysisRequest
): Promise<ChangeAnalysisResponse> {
  const response = await apiFetch('/api/v1/change-analyses', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to start change analysis');
  }

  return response.json();
}

export async function startChangeAnalysisFromPR(
  payload: ChangeAnalysisPRRequest
): Promise<ChangeAnalysisResponse> {
  const response = await apiFetch('/api/v1/change-analyses/from-pr', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to resolve PR and start analysis');
  }

  return response.json();
}

export async function listChangeAnalyses(
  repositoryUrl?: string,
  limit = 20,
  offset = 0
): Promise<ChangeAnalysisSummary[]> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (repositoryUrl) params.set('repository_url', repositoryUrl);

  const response = await apiFetch(`/api/v1/change-analyses?${params.toString()}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to list change analyses');
  }

  return response.json();
}

export async function fetchChangeAnalysis(
  analysisId: string
): Promise<ChangeAnalysisResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch change analysis');
  }

  return response.json();
}

export async function fetchChangeAnalysisDiff(
  analysisId: string
): Promise<StructuralDiffResult> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/diff`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch diff results');
  }

  return response.json();
}

export async function fetchChangeAnalysisImpacts(
  analysisId: string
): Promise<ChangeImpact[]> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/impacts`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch impacts');
  }

  return response.json();
}

export async function fetchChangeAnalysisReview(
  analysisId: string
): Promise<ChangeReviewReport> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/review`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch review findings');
  }

  return response.json();
}

export async function fetchChangeAnalysisReport(
  analysisId: string
): Promise<ChangeAnalysisReportResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/report`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch change analysis report');
  }

  return response.json();
}

export async function fetchChangeAnalysisTelemetry(
  analysisId: string
): Promise<ChangeAnalysisTelemetry> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/telemetry`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch change analysis telemetry');
  }

  return response.json();
}

export async function downloadChangeAnalysisMarkdown(analysisId: string): Promise<string> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/markdown`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to download report markdown');
  }

  return response.text();
}

/* ========================================================================= */
/* Safe Pull Request Review Publication API (Phase 7)                         */
/* ========================================================================= */

export async function fetchReviewPublication(
  analysisId: string
): Promise<ReviewPublicationPreviewResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/review-publication`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to fetch review publication');
  }

  return response.json();
}

export async function generateReviewPublicationPreview(
  analysisId: string
): Promise<ReviewPublicationPreviewResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/review-publication/preview`, {
    method: 'POST',
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to generate review preview');
  }

  return response.json();
}

export async function approveReviewPublication(
  analysisId: string,
  expectedPreviewDigest: string
): Promise<ReviewPublicationPreviewResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/review-publication/approve`, {
    method: 'POST',
    body: JSON.stringify({ expected_preview_digest: expectedPreviewDigest }),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to approve review publication');
  }

  return response.json();
}

export async function publishReviewPublication(
  analysisId: string,
  expectedPreviewDigest: string
): Promise<ReviewPublicationPublishResponse> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/review-publication/publish`, {
    method: 'POST',
    body: JSON.stringify({ expected_preview_digest: expectedPreviewDigest }),
  });

  if (!response.ok) {
    throw await apiErrorFromResponse(response, 'Failed to publish review');
  }

  return response.json();
}
