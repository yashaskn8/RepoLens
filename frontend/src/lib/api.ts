/**
 * Centralized typed API client for RepoLens backend communication.
 */

import { Finding, HealthResponse, Scan, ScanCreate } from '@/types/domain';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Health check failed with status: ${response.status}`);
  }

  return response.json();
}

export async function startScan(payload: ScanCreate): Promise<Scan> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `Scan initiation failed (${response.status})`);
  }

  return response.json();
}

export async function fetchScan(scanId: string): Promise<Scan> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}`, {
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan status (${response.status})`);
  }

  return response.json();
}

export async function fetchScanFindings(scanId: string): Promise<Finding[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}/findings`, {
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan findings (${response.status})`);
  }

  return response.json();
}

export async function fetchPatch(patchId: string): Promise<import('@/types/domain').PatchResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch patch (${response.status})`);
  }

  return response.json();
}

export async function fetchScanPatches(scanId: string): Promise<import('@/types/domain').PatchResponse[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/scan/${scanId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan patches (${response.status})`);
  }

  return response.json();
}

export async function approvePatch(
  patchId: string,
  payload: import('@/types/domain').PatchReviewRequest = { approved_by: 'user' }
): Promise<import('@/types/domain').PatchResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to approve patch (${response.status})`);
  }

  return response.json();
}

export async function rejectPatch(
  patchId: string,
  payload: import('@/types/domain').PatchRejectRequest
): Promise<import('@/types/domain').PatchResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to reject patch (${response.status})`);
  }

  return response.json();
}

export async function revisePatch(
  patchId: string,
  payload: import('@/types/domain').PatchReviseRequest
): Promise<import('@/types/domain').PatchResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}/revise`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to request patch revision (${response.status})`);
  }

  return response.json();
}

export async function fetchFinding(findingId: string): Promise<Finding> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${findingId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch finding (${response.status})`);
  }

  return response.json();
}

export async function requestFindingResearch(findingId: string): Promise<import('@/types/domain').ResearchResult> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${findingId}/research`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to research finding (${response.status})`);
  }

  return response.json();
}

export async function requestFixPlan(findingId: string): Promise<import('@/types/domain').FixPlan> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${findingId}/plan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to generate fix plan (${response.status})`);
  }

  return response.json();
}

export async function requestPatchGeneration(findingId: string): Promise<import('@/types/domain').PatchWorkflowResult> {
  const response = await fetch(`${API_BASE_URL}/api/v1/findings/${findingId}/patch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to generate patch (${response.status})`);
  }

  return response.json();
}

export async function fetchScanTelemetry(scanId: string): Promise<import('@/types/domain').ScanTelemetry> {
  const response = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}/telemetry`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan telemetry (${response.status})`);
  }

  return response.json();
}

export async function fetchDeliveryPreview(patchId: string): Promise<import('@/types/domain').DeliveryPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}/delivery-preview`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch delivery preview (${response.status})`);
  }

  return response.json();
}

export async function requestDelivery(
  patchId: string,
  payload: import('@/types/domain').DeliveryRequest = { requested_by: 'user' }
): Promise<import('@/types/domain').DeliveryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/patches/${patchId}/deliver`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Delivery failed (${response.status})`);
  }

  return response.json();
}

export async function fetchDelivery(deliveryId: string): Promise<import('@/types/domain').DeliveryResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/deliveries/${deliveryId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch delivery status (${response.status})`);
  }

  return response.json();
}

export async function fetchDeliveryByPatch(patchId: string): Promise<import('@/types/domain').DeliveryResponse | null> {
  const response = await fetch(`${API_BASE_URL}/api/v1/deliveries/patch/${patchId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (response.status === 404 || response.status === 204) {
    return null;
  }
  if (!response.ok) {
    return null;
  }

  return response.json();
}

export async function startChangeAnalysis(
  payload: import('@/types/domain').ChangeAnalysisRequest
): Promise<import('@/types/domain').ChangeAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to start change analysis (${response.status})`);
  }

  return response.json();
}

export async function startChangeAnalysisFromPR(
  payload: import('@/types/domain').ChangeAnalysisPRRequest
): Promise<import('@/types/domain').ChangeAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/from-pr`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to resolve PR and start analysis (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysis(
  analysisId: string
): Promise<import('@/types/domain').ChangeAnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch change analysis (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysisDiff(
  analysisId: string
): Promise<import('@/types/domain').StructuralDiffResult> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/diff`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch diff results (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysisImpacts(
  analysisId: string
): Promise<import('@/types/domain').ChangeImpact[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/impacts`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch impacts (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysisReview(
  analysisId: string
): Promise<import('@/types/domain').ChangeReviewReport> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/review`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch review findings (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysisReport(
  analysisId: string
): Promise<import('@/types/domain').ChangeAnalysisReportResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/report`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch change analysis report (${response.status})`);
  }

  return response.json();
}

export async function fetchChangeAnalysisTelemetry(
  analysisId: string
): Promise<import('@/types/domain').ChangeAnalysisTelemetry> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/telemetry`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch change analysis telemetry (${response.status})`);
  }

  return response.json();
}

export async function downloadChangeAnalysisMarkdown(analysisId: string): Promise<string> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/markdown`, {
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Failed to download report markdown (${response.status})`);
  }

  return response.text();
}

export async function fetchReviewPublication(
  analysisId: string
): Promise<import('@/types/domain').ReviewPublicationPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/review-publication`, {
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to fetch review publication (${response.status})`);
  }

  return response.json();
}

export async function generateReviewPublicationPreview(
  analysisId: string
): Promise<import('@/types/domain').ReviewPublicationPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/review-publication/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
): Promise<import('@/types/domain').ReviewPublicationPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/review-publication/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
): Promise<import('@/types/domain').ReviewPublicationPublishResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/change-analyses/${analysisId}/review-publication/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ expected_preview_digest: expectedPreviewDigest }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail?.message || err.detail || `Failed to publish review (${response.status})`);
  }

  return response.json();
}
