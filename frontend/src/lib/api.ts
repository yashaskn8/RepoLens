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
  PatchProposal,
  PatchRejectRequest,
  PatchResponse,
  PatchReviewRequest,
  PatchReviseRequest,
  PatchWorkflowResult,
  ResearchResult,
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

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

/**
 * Extract CSRF token from client cookie.
 */
export function getCsrfToken(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)repolens_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Standard fetch wrapper attaching credentials and CSRF tokens.
 */
export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const url = input.startsWith('http') ? input : `${API_BASE_URL}${input}`;
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

  return fetch(url, {
    ...init,
    headers,
    credentials: 'include',
  });
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Registration failed (${response.status})`);
  }

  return response.json();
}

export async function loginUser(payload: UserLoginRequest): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Login failed (${response.status})`);
  }

  return response.json();
}

export async function logoutUser(): Promise<{ message: string }> {
  const response = await apiFetch('/api/v1/auth/logout', {
    method: 'POST',
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Logout failed (${response.status})`);
  }

  return response.json();
}

export async function fetchCurrentUser(): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/me', {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Unauthenticated (${response.status})`);
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
    throw new Error(`Health check failed with status: ${response.status}`);
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
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail?.message || errData.detail || `Scan initiation failed (${response.status})`);
  }

  return response.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const response = await apiFetch(`/api/v1/scans/${scanId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan status (${response.status})`);
  }

  return response.json();
}

export async function requestScanReport(scanId: string): Promise<ScanReportResource> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/reports`, { method: 'POST' });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.message || error.detail || `Report generation request failed (${response.status})`);
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
  if (!response.ok) throw new Error(`Failed to restore report status (${response.status})`);
  return response.json();
}

export async function fetchReport(reportId: string, signal?: AbortSignal): Promise<ScanReportResource> {
  const response = await apiFetch(`/api/v1/reports/${reportId}`, { cache: 'no-store', signal });
  if (!response.ok) throw new Error(`Failed to fetch report status (${response.status})`);
  return response.json();
}

export async function downloadReportPdf(reportId: string): Promise<Blob> {
  const response = await apiFetch(`/api/v1/reports/${reportId}/download`, { cache: 'no-store' });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail?.message || error.detail || `Report download failed (${response.status})`);
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
    throw new Error(`Failed to fetch scan findings (${response.status})`);
  }

  return response.json();
}

export async function fetchScanTelemetry(scanId: string): Promise<ScanTelemetry> {
  const response = await apiFetch(`/api/v1/scans/${scanId}/telemetry`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan telemetry (${response.status})`);
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
    throw new Error(`Failed to fetch finding (${response.status})`);
  }

  return response.json();
}

export async function requestFindingResearch(findingId: string): Promise<ResearchResult> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/research`, {
    method: 'POST',
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to research finding (${response.status})`);
  }

  return response.json();
}

export async function requestFixPlan(findingId: string): Promise<FixPlan> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/plan`, {
    method: 'POST',
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to generate fix plan (${response.status})`);
  }

  return response.json();
}

export async function requestPatchGeneration(findingId: string): Promise<PatchWorkflowResult> {
  const response = await apiFetch(`/api/v1/findings/${findingId}/patch`, {
    method: 'POST',
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to generate patch (${response.status})`);
  }

  return response.json();
}

/* ========================================================================= */
/* Patches & Human-in-the-Loop Review API                                    */
/* ========================================================================= */

export async function fetchPatch(patchId: string): Promise<PatchResponse> {
  const response = await apiFetch(`/api/v1/patches/${patchId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch patch (${response.status})`);
  }

  return response.json();
}

export async function fetchScanPatches(scanId: string): Promise<PatchResponse[]> {
  const response = await apiFetch(`/api/v1/patches/scan/${scanId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan patches (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to approve patch (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to reject patch (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to request patch revision (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to fetch delivery preview (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Delivery failed (${response.status})`);
  }

  return response.json();
}

export async function fetchDelivery(deliveryId: string): Promise<DeliveryResponse> {
  const response = await apiFetch(`/api/v1/deliveries/${deliveryId}`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch delivery status (${response.status})`);
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
    return null;
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to start change analysis (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to resolve PR and start analysis (${response.status})`);
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
    throw new Error(`Failed to list change analyses (${response.status})`);
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
    throw new Error(`Failed to fetch change analysis (${response.status})`);
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
    throw new Error(`Failed to fetch diff results (${response.status})`);
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
    throw new Error(`Failed to fetch impacts (${response.status})`);
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
    throw new Error(`Failed to fetch review findings (${response.status})`);
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
    throw new Error(`Failed to fetch change analysis report (${response.status})`);
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
    throw new Error(`Failed to fetch change analysis telemetry (${response.status})`);
  }

  return response.json();
}

export async function downloadChangeAnalysisMarkdown(analysisId: string): Promise<string> {
  const response = await apiFetch(`/api/v1/change-analyses/${analysisId}/markdown`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to download report markdown (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to fetch review publication (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to generate review preview (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to approve review publication (${response.status})`);
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
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to publish review (${response.status})`);
  }

  return response.json();
}
