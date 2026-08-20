/**
 * Canonical domain types for RepoLens, mirroring the FastAPI backend schemas.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface ModelExecutionMetadata {
  model_name: string;
  provider?: string | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
  execution_time_ms?: number | null;
  temperature?: number | null;
  extra_metadata?: Record<string, unknown>;
}

export interface Evidence {
  id: string;
  file_path: string;
  start_line?: number | null;
  end_line?: number | null;
  code_snippet?: string | null;
  context_notes?: string | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: FindingStatus;
  rule_id?: string | null;
  category?: string | null;
  evidences: Evidence[];
  mitigation_guidance?: string | null;
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  repository_url: string;
  branch?: string | null;
  commit_hash?: string | null;
  status: ScanStatus;
  findings_count: number;
  findings: Finding[];
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
  completed_at?: string | null;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded';
  service: string;
  version: string;
  environment: string;
  database: string;
}
