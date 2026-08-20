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
