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
  source_tool?: string | null;
  detector_id?: string | null;
  detector_kind?: string | null;
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
  requested_branch?: string | null;
  resolved_branch_or_ref?: string | null;
  commit_hash?: string | null;
  commit_sha?: string | null;
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

export interface ScanTelemetry {
  scan_id: string;
  commit_sha?: string | null;
  status: string;
  total_duration_ms?: number | null;
  event_count: number;
  stage_count: number;
  tools_completed: number;
  tools_failed: number;
  tools_unavailable: number;
  llm_calls?: number | null;
  llm_retries?: number | null;
  provider_fallbacks?: number | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
  confirmed_findings: number;
  possible_findings: number;
  rejected_findings: number;
  patches_generated: number;
  patches_verified: number;
  patches_needing_review: number;
  patches_approved: number;
  patches_rejected: number;
  deliveries_requested?: number;
  deliveries_blocked?: number;
  pull_requests_created?: number;
  delivery_failures?: number;
  analysis_truncated: boolean;
  analysis_truncation_reason?: string | null;
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

export interface AnalysisScope {
  truncated: boolean;
  reason?: string | null;
  files_processed: number;
  source_bytes_processed: number;
  total_observed_files: number;
  total_observed_bytes: number;
}

export interface RepositoryManifest {
  repository_url: string;
  commit_hash: string;
  commit_sha?: string | null;
  branch?: string | null;
  requested_branch?: string | null;
  resolved_branch_or_ref?: string | null;
  total_files: number;
  total_size_bytes: number;
  languages: Record<string, number>;
  frameworks: FrameworkDetected[];
  files: FileEntry[];
  cloned_at: string;
  scan_duration_ms?: number | null;
  analysis_scope?: AnalysisScope | null;
}

export type ToolStatus =
  | 'AVAILABLE'
  | 'UNAVAILABLE'
  | 'DISABLED'
  | 'TIMEOUT'
  | 'FAILED'
  | 'COMPLETED'
  | 'INVALID_OUTPUT';

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
  diagnostic_stderr?: string | null;
}

export type NodeKind = 'FILE' | 'SYMBOL' | 'ROUTE' | 'FRONTEND_REQUEST' | 'DEPENDENCY' | 'TEST';

export type EdgeKind =
  | 'CONTAINS'
  | 'IMPORTS'
  | 'CALLS'
  | 'EXPOSES_ROUTE'
  | 'REQUESTS_ROUTE'
  | 'MATCHES_ROUTE'
  | 'DEPENDS_ON'
  | 'TESTS';

export type ContractMatchStatus =
  | 'MATCHED'
  | 'UNMATCHED_FRONTEND_REQUEST'
  | 'METHOD_MISMATCH'
  | 'PATH_MISMATCH'
  | 'AMBIGUOUS_MATCH';

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  file_path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: EdgeKind;
  metadata: Record<string, unknown>;
}

export interface RouteContractMatch {
  frontend_request_id: string;
  frontend_method: string;
  frontend_url: string;
  frontend_file: string;
  frontend_line?: number | null;
  status: ContractMatchStatus;
  matched_route_ids: string[];
  matched_backend_paths: string[];
  matched_backend_methods: string[];
  details: string;
}

export interface ContractMatchReport {
  total_frontend_requests: number;
  total_backend_routes: number;
  matched_count: number;
  unmatched_count: number;
  method_mismatch_count: number;
  ambiguous_count: number;
  matches: RouteContractMatch[];
}

export interface RepositoryGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
  node_counts_by_kind: Record<string, number>;
  edge_counts_by_kind: Record<string, number>;
  contract_report?: ContractMatchReport | null;
}

export type ChunkSymbolKind = 'FUNCTION' | 'CLASS' | 'METHOD' | 'ROUTE' | 'FILE';

export interface CodeChunk {
  chunk_id: string;
  commit_sha: string;
  file_path: string;
  language?: string | null;
  symbol: string;
  symbol_kind: ChunkSymbolKind;
  start_line: number;
  end_line: number;
  content: string;
  content_hash: string;
  index_version: number;
}

export type RetrievalChannel = 'exact' | 'lexical' | 'dense' | 'graph';

export interface RetrievalResult {
  chunk_id: string;
  score: number;
  source_channels: RetrievalChannel[];
  chunk: CodeChunk;
  reranked_score?: number | null;
  provenance: Record<string, unknown>;
}

export interface RetrievalQuery {
  query: string;
  top_k?: number;
  use_reranker?: boolean;
  file_path_filter?: string | null;
  symbol_kind_filter?: string | null;
}

export type PatchStatus = 'DRAFT' | 'VERIFIED' | 'NEEDS_REVIEW' | 'REJECTED' | 'APPROVED';

export type CheckStatus = 'PASSED' | 'FAILED' | 'NEEDS_REVIEW' | 'UNAVAILABLE' | 'TIMEOUT' | 'NOT_EVALUATED';

export interface VerificationCheckItem {
  check_name: string;
  passed: boolean;
  status?: CheckStatus;
  details?: string | null;
}

export interface PatchVerificationResult {
  id: string;
  patch_id: string;
  finding_id: string;
  status: 'PASSED' | 'NEEDS_REVIEW' | 'FAILED';
  syntax_valid: boolean;
  security_clean: boolean;
  contract_aligned: boolean;
  target_finding_resolved: boolean;
  checks: VerificationCheckItem[];
  checks_passed: string[];
  checks_failed: string[];
  explanation: string;
  verified_at: string;
}

export type CriticVerdict = 'APPROVE' | 'REVISE' | 'REJECT';

export interface PatchCriticReport {
  id: string;
  patch_id: string;
  finding_id: string;
  verdict: CriticVerdict;
  critic_score: number;
  concerns: string[];
  required_revisions?: string | null;
  evidence_notes: string;
  escalation_reasons: string[];
  created_at: string;
}

export interface PatchResponse {
  id: string;
  finding_id: string;
  plan_id?: string | null;
  scan_id: string;
  parent_patch_id?: string | null;
  revision_number?: number;
  thread_id?: string | null;
  status: PatchStatus;
  machine_verdict?: MachineVerdict | null;
  unified_diff: string;
  files_modified: string[];
  explanation: string;
  expected_behavior_change: string;
  generated_tests_or_test_plan?: string[] | null;
  verification_report?: PatchVerificationResult | null;
  critic_report?: PatchCriticReport | null;
  user_feedback?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  rejected_reason?: string | null;
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
  updated_at: string;
}

export interface ResearchEvidence {
  source_url: string;
  source_title: string;
  source_tier: string;
  supported_claim: string;
  confidence: number;
}

export interface ResearchResult {
  id: string;
  finding_id?: string | null;
  target_framework: string;
  detected_version?: string | null;
  recommended_version?: string | null;
  migration_summary: string;
  repository_impact: string;
  evidences: ResearchEvidence[];
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
}

export interface OrderedChangeStep {
  step_number: number;
  target_file: string;
  description: string;
  rationale: string;
}

export interface FixPlan {
  id: string;
  finding_id: string;
  root_cause: string;
  objective: string;
  files_expected_to_change: string[];
  ordered_changes: OrderedChangeStep[];
  validation_plan: string[];
  estimated_scope?: string | null;
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
}

export interface PatchProposal {
  id: string;
  finding_id: string;
  plan_id?: string | null;
  unified_diff: string;
  files_modified: string[];
  explanation: string;
  expected_behavior_change: string;
  generated_tests_or_test_plan?: string[] | null;
  model_metadata?: ModelExecutionMetadata | null;
  created_at: string;
}

export type MachineVerdict = 'PASSED' | 'NEEDS_REVIEW' | 'REJECTED';

export interface PatchWorkflowResult {
  finding_id: string;
  proposal: PatchProposal;
  verification_result: PatchVerificationResult;
  critic_escalated: boolean;
  critic_report?: PatchCriticReport | null;
  revision_count: number;
  machine_verdict: MachineVerdict;
  final_verdict: MachineVerdict;
}

export interface PatchReviewRequest {
  approved_by?: string;
  notes?: string;
}

export interface PatchRejectRequest {
  reason: string;
}

export interface PatchReviseRequest {
  user_feedback: string;
}

export type DeliveryStatus =
  | 'PENDING'
  | 'VALIDATING'
  | 'BLOCKED'
  | 'READY'
  | 'CREATING_COMMIT'
  | 'CREATING_BRANCH'
  | 'CREATING_PR'
  | 'PR_CREATED'
  | 'FAILED';

export interface DeliveryPreviewResponse {
  eligible: boolean;
  blocking_reason?: string | null;
  failure_code?: string | null;
  repository_url: string;
  repository_owner: string;
  repository_name: string;
  base_branch: string;
  scanned_base_sha: string;
  observed_base_sha?: string | null;
  files_modified: string[];
  patch_status: PatchStatus;
  machine_verdict?: string | null;
  human_approved: boolean;
  proposed_branch_name: string;
  proposed_pr_title: string;
  github_delivery_configured: boolean;
}

export interface DeliveryRequest {
  requested_by?: string;
  notes?: string | null;
}

export interface DeliveryResponse {
  id: string;
  scan_id: string;
  finding_id: string;
  patch_id: string;
  provider: string;
  repository_url: string;
  repository_owner: string;
  repository_name: string;
  base_branch: string;
  scanned_base_sha: string;
  observed_base_sha?: string | null;
  head_branch?: string | null;
  head_sha?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  status: DeliveryStatus;
  failure_code?: string | null;
  failure_message?: string | null;
  idempotency_key: string;
  requested_by: string;
  attempt_count: number;
  last_attempt_at?: string | null;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
}

export interface ReportDelivery {
  delivery_id: string;
  status: string;
  provider: string;
  repository: string;
  base_branch: string;
  scanned_base_sha: string;
  observed_base_sha?: string | null;
  head_branch?: string | null;
  head_sha?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  failure_code?: string | null;
  completed_at?: string | null;
}

export type WorkflowEventType =
  | 'SCAN_CREATED'
  | 'SCAN_STARTED'
  | 'SCAN_COMPLETED'
  | 'SCAN_FAILED'
  | 'STAGE_STARTED'
  | 'STAGE_COMPLETED'
  | 'STAGE_FAILED'
  | 'TOOL_STARTED'
  | 'TOOL_COMPLETED'
  | 'TOOL_FAILED'
  | 'TOOL_UNAVAILABLE'
  | 'FINDING_CONFIRMED'
  | 'PATCH_GENERATED'
  | 'PATCH_VERIFIED'
  | 'PATCH_NEEDS_REVIEW'
  | 'PATCH_REJECTED'
  | 'PATCH_APPROVED'
  | 'PATCH_REVISION_CREATED'
  | 'HUMAN_APPROVED'
  | 'HUMAN_REJECTED'
  | 'HUMAN_REVISION_REQUESTED'
  | 'DELIVERY_REQUESTED'
  | 'DELIVERY_VALIDATED'
  | 'DELIVERY_BLOCKED'
  | 'DELIVERY_COMMIT_CREATED'
  | 'DELIVERY_BRANCH_CREATED'
  | 'DELIVERY_PR_CREATED'
  | 'DELIVERY_FAILED'
  | 'CHANGE_ANALYSIS_REQUESTED'
  | 'CHANGE_REVISIONS_ACQUIRED'
  | 'CHANGE_DIFF_COMPLETED'
  | 'CHANGE_IMPACT_ANALYZED'
  | 'CHANGE_ANALYSIS_COMPLETED'
  | 'CHANGE_ANALYSIS_FAILED'
  | 'WORKFLOW_ERROR';

export const WORKFLOW_EVENT_TYPES: readonly WorkflowEventType[] = [
  'SCAN_CREATED',
  'SCAN_STARTED',
  'SCAN_COMPLETED',
  'SCAN_FAILED',
  'STAGE_STARTED',
  'STAGE_COMPLETED',
  'STAGE_FAILED',
  'TOOL_STARTED',
  'TOOL_COMPLETED',
  'TOOL_FAILED',
  'TOOL_UNAVAILABLE',
  'FINDING_CONFIRMED',
  'PATCH_GENERATED',
  'PATCH_VERIFIED',
  'PATCH_NEEDS_REVIEW',
  'PATCH_REJECTED',
  'PATCH_APPROVED',
  'PATCH_REVISION_CREATED',
  'HUMAN_APPROVED',
  'HUMAN_REJECTED',
  'HUMAN_REVISION_REQUESTED',
  'DELIVERY_REQUESTED',
  'DELIVERY_VALIDATED',
  'DELIVERY_BLOCKED',
  'DELIVERY_COMMIT_CREATED',
  'DELIVERY_BRANCH_CREATED',
  'DELIVERY_PR_CREATED',
  'DELIVERY_FAILED',
  'CHANGE_ANALYSIS_REQUESTED',
  'CHANGE_REVISIONS_ACQUIRED',
  'CHANGE_DIFF_COMPLETED',
  'CHANGE_IMPACT_ANALYZED',
  'CHANGE_ANALYSIS_COMPLETED',
  'CHANGE_ANALYSIS_FAILED',
  'WORKFLOW_ERROR',
] as const;

export interface WorkflowEvent {
  id: number;
  event_type: WorkflowEventType;
  scan_id?: string | null;
  change_analysis_id?: string | null;
  finding_id?: string | null;
  patch_id?: string | null;
  delivery_id?: string | null;
  thread_id?: string | null;
  commit_sha?: string | null;
  stage?: string | null;
  tool_name?: string | null;
  provider?: string | null;
  model_name?: string | null;
  message?: string | null;
  metadata_payload?: Record<string, unknown>;
  created_at: string;
}

export type ChangeAnalysisStatus =
  | 'PENDING'
  | 'ACQUIRING'
  | 'DIFFING'
  | 'ANALYZING'
  | 'VERIFYING'
  | 'COMPLETED'
  | 'FAILED';

export type ChangeImpactType =
  | 'SYMBOL_CHANGE'
  | 'CALLER_IMPACT'
  | 'API_CONTRACT_CHANGE'
  | 'SCHEMA_CHANGE'
  | 'DEPENDENCY_CHANGE'
  | 'CONFIG_CHANGE'
  | 'SECURITY_SENSITIVE_CHANGE';

export type ImpactVerificationStatus = 'FACT' | 'INFERENCE' | 'ASSUMPTION';

export type ChangeRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

export interface ChangeAnalysisRequest {
  repository_url: string;
  base_commit_sha: string;
  head_commit_sha: string;
  base_ref?: string | null;
  head_ref?: string | null;
}

export interface ChangeImpactEvidence {
  file_path: string;
  symbol_name?: string | null;
  base_line_range?: [number, number] | null;
  head_line_range?: [number, number] | null;
  edge_type?: string | null;
  caller_file?: string | null;
  caller_symbol?: string | null;
  callee_file?: string | null;
  callee_symbol?: string | null;
  contract_name?: string | null;
  code_snippet?: string | null;
  context_notes?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ChangeImpact {
  id: string;
  analysis_id: string;
  impact_type: ChangeImpactType;
  severity: Severity;
  title: string;
  description: string;
  source_file?: string | null;
  source_symbol?: string | null;
  affected_file?: string | null;
  affected_symbol?: string | null;
  evidence_payload: Record<string, unknown>;
  confidence: number;
  verification_status: ImpactVerificationStatus;
  created_at: string;
}

export interface ChangeAnalysisSummary {
  id: string;
  repository_url: string;
  repository_owner: string;
  repository_name: string;
  base_ref?: string | null;
  base_commit_sha: string;
  head_ref?: string | null;
  head_commit_sha: string;
  status: ChangeAnalysisStatus;
  changed_files_count: number;
  changed_symbols_count: number;
  impacted_symbols_count: number;
  risk_level?: ChangeRiskLevel | null;
  failure_code?: string | null;
  failure_message?: string | null;
  created_at: string;
  updated_at: string;
  completed_at?: string | null;
}

export interface ChangeAnalysisResponse extends ChangeAnalysisSummary {
  impacts: ChangeImpact[];
  model_metadata?: ModelExecutionMetadata | null;
}

export type FileChangeType = 'ADDED' | 'DELETED' | 'MODIFIED' | 'RENAMED' | 'UNMODIFIED';

export type SymbolChangeType = 'ADDED' | 'DELETED' | 'MODIFIED' | 'SIGNATURE_CHANGED' | 'RENAMED';

export interface FileDiffFact {
  file_path: string;
  old_path?: string | null;
  change_type: FileChangeType;
  is_binary: boolean;
  is_parsed: boolean;
  skipped_reason?: string | null;
  language?: string | null;
  changed_line_ranges: [number, number][];
  base_line_ranges: [number, number][];
}

export interface SymbolDiffFact {
  file_path: string;
  symbol_name: string;
  symbol_kind: string;
  change_type: SymbolChangeType;
  base_location?: Record<string, unknown> | null;
  head_location?: Record<string, unknown> | null;
  evidence: Record<string, unknown>;
}

export interface DependencyDelta {
  manifest_file: string;
  package_name: string;
  base_version?: string | null;
  head_version?: string | null;
  change_type: string;
}

export interface ConfigDelta {
  file_path: string;
  key: string;
  base_value?: string | null;
  head_value?: string | null;
  change_type: string;
}

export interface RouteContractDelta {
  file_path: string;
  route_type: string;
  route_name: string;
  base_http_method?: string | null;
  head_http_method?: string | null;
  base_path?: string | null;
  head_path?: string | null;
  change_type: string;
  details: string;
}

export interface SchemaModelDelta {
  file_path: string;
  model_name: string;
  model_kind: string;
  field_name: string;
  base_type?: string | null;
  head_type?: string | null;
  change_type: string;
  details: string;
}

export interface StructuralDiffResult {
  base_commit_sha: string;
  head_commit_sha: string;
  repository_url: string;
  changed_files: FileDiffFact[];
  added_files: string[];
  deleted_files: string[];
  renamed_files: [string, string][];
  modified_files: string[];
  changed_symbols: SymbolDiffFact[];
  added_symbols: SymbolDiffFact[];
  deleted_symbols: SymbolDiffFact[];
  modified_symbols: SymbolDiffFact[];
  dependency_deltas: DependencyDelta[];
  config_deltas: ConfigDelta[];
  route_deltas: RouteContractDelta[];
  schema_deltas: SchemaModelDelta[];
  summary: Record<string, number>;
}



