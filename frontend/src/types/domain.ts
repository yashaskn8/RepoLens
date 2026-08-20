/**
 * Canonical domain types for RepoLens, mirroring the FastAPI backend schemas.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type VerificationVerdict = 'CONFIRMED' | 'POSSIBLE' | 'REJECTED';

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
  mitigation_guidance?: string | null;
  verification_verdict?: VerificationVerdict | null;
  verification_reason?: string | null;
  evidences: Evidence[];
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
  updated_at: string;
}

export interface ScanCreate {
  repository_url: string;
  branch?: string | null;
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

export type SymbolKind =
  | 'FUNCTION'
  | 'CLASS'
  | 'METHOD'
  | 'IMPORT'
  | 'FASTAPI_ROUTE'
  | 'EXPRESS_ROUTE'
  | 'FETCH_CALL'
  | 'AXIOS_CALL';

export interface ParsedSymbol {
  name: string;
  kind: SymbolKind;
  start_line: number;
  end_line: number;
  start_column?: number | null;
  end_column?: number | null;
  details?: Record<string, unknown>;
}

export interface FileEntry {
  path: string;
  language?: string | null;
  size_bytes: number;
  lines_count: number;
  symbols: ParsedSymbol[];
  is_binary: boolean;
  skipped_reason?: string | null;
}

export interface FrameworkDetected {
  name: string;
  version?: string | null;
  evidence: string;
}

export interface RepositoryManifest {
  repository_url: string;
  commit_hash: string;
  branch?: string | null;
  total_files: number;
  total_size_bytes: number;
  languages: Record<string, number>;
  frameworks: FrameworkDetected[];
  files: FileEntry[];
  cloned_at: string;
  scan_duration_ms?: number | null;
}

export type ToolStatus =
  | 'AVAILABLE'
  | 'UNAVAILABLE'
  | 'DISABLED'
  | 'TIMEOUT'
  | 'FAILED'
  | 'COMPLETED';

export interface StaticFinding {
  id: string;
  tool: string;
  rule_id?: string | null;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  evidence: Evidence;
  mitigation?: string | null;
  confidence?: string | null;
  raw_details?: Record<string, unknown>;
}

export interface ScannerResult {
  tool: string;
  status: ToolStatus;
  findings: StaticFinding[];
  error_message?: string | null;
  execution_time_ms: number;
}
