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

