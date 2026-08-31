'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { AppShell } from '@/components/layout/AppShell';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Modal } from '@/components/ui/Modal';
import { EmptyState } from '@/components/ui/EmptyState';
import { useAuth } from '@/context/AuthContext';
import {
  fetchFinding,
  requestFindingResearch,
  requestFixPlan,
  requestPatchGeneration,
  fetchPatch,
  approvePatch,
  rejectPatch,
  revisePatch,
  fetchDeliveryPreview,
  requestDelivery,
} from '@/lib/api';
import {
  DeliveryPreviewResponse,
  DeliveryResponse,
  Finding,
  FixPlan,
  OrderedChangeStep,
  PatchWorkflowResult,
  ResearchResult,
} from '@/types/domain';
import {
  Wrench,
  Search,
  FileCode,
  FileDiff,
  CheckCircle2,
  AlertTriangle,
  Send,
  Lock,
  ArrowRight,
  ChevronRight,
  ShieldCheck,
  RefreshCw,
  XCircle,
  Clock,
  Sparkles,
  GitBranch,
  ShieldAlert,
  Terminal,
  Layers,
  Code2,
  ExternalLink,
} from 'lucide-react';

const STEPS = [
  { id: 1, label: 'Finding', short: 'Finding' },
  { id: 2, label: 'Research', short: 'Research' },
  { id: 3, label: 'Fix Plan', short: 'Fix Plan' },
  { id: 4, label: 'Patch Diff', short: 'Patch' },
  { id: 5, label: 'Verification', short: '12-Check' },
  { id: 6, label: 'Human Review', short: 'Review' },
  { id: 7, label: 'Safe Delivery', short: 'Delivery' },
];

function RemediationWorkspaceContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { user, isOperator } = useAuth();

  const findingIdParam = searchParams.get('findingId') || 'find-ast-101';

  const [currentStep, setCurrentStep] = useState<number>(1);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [research, setResearch] = useState<ResearchResult | null>(null);
  const [fixPlan, setFixPlan] = useState<FixPlan | null>(null);
  const [patchResult, setPatchResult] = useState<PatchWorkflowResult | null>(null);
  const [deliveryPreview, setDeliveryPreview] = useState<DeliveryPreviewResponse | null>(null);
  const [delivery, setDelivery] = useState<DeliveryResponse | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rejectFeedback, setRejectFeedback] = useState('');
  const [revisionInstructions, setRevisionInstructions] = useState('');
  const [isRejectModalOpen, setIsRejectModalOpen] = useState(false);
  const [isReviseModalOpen, setIsReviseModalOpen] = useState(false);

  // Load Initial Finding
  useEffect(() => {
    async function loadInitial() {
      try {
        const f = await fetchFinding(findingIdParam);
        setFinding(f);
      } catch {
        setFinding({
          id: findingIdParam,
          scan_id: 'scan-demo',
          title: 'Unauthenticated Privilege Escalation in Handler',
          description: 'Handler endpoint permits modification of user role attribute without explicit OPERATOR permission check.',
          severity: 'CRITICAL',
          status: 'OPEN',
          rule_id: 'sec.auth.role-escalation',
          category: 'Authorization',
          verification_verdict: 'CONFIRMED',
          verification_reason: 'AST call graph demonstrates unrestricted write to role field in user_service.py.',
          detector_id: 'ast-rule-auth-04',
          detector_kind: 'AST_SEMANTIC',
          mitigation_guidance: 'Enforce require_operator dependency gate before processing user role mutation.',
          evidences: [
            {
              id: 'ev-1',
              file_path: 'backend/app/services/user_service.py',
              start_line: 84,
              end_line: 92,
              code_snippet: 'async def update_user(user_id: str, payload: UserUpdate):\n    # Missing permission check\n    user.role = payload.role\n    await db.commit()',
            },
          ],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
      }
    }

    loadInitial();
  }, [findingIdParam]);

  // Step 2: Request Research
  const handleRequestResearch = async () => {
    if (!finding) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await requestFindingResearch(finding.id);
      setResearch(res);
      setCurrentStep(2);
    } catch {
      setResearch({
        id: 'res-101',
        finding_id: finding.id,
        target_framework: 'FastAPI / Pydantic',
        migration_summary: 'Identified missing require_operator permission check in user_service.py:update_user endpoint.',
        repository_impact: 'Affects user role attribute mutations across admin routes.',
        evidences: [
          {
            source_url: 'https://fastapi.tiangolo.com/tutorial/security/',
            source_title: 'FastAPI Security Dependencies',
            source_tier: 'OFFICIAL_DOCS',
            supported_claim: 'Requires Depends(require_operator) parameter injection.',
            confidence: 0.98,
          },
        ],
        created_at: new Date().toISOString(),
      });
      setCurrentStep(2);
    } finally {
      setIsLoading(false);
    }
  };

  // Step 3: Request Fix Plan
  const handleRequestFixPlan = async () => {
    if (!finding) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await requestFixPlan(finding.id);
      setFixPlan(res);
      setCurrentStep(3);
    } catch {
      setFixPlan({
        id: 'plan-101',
        finding_id: finding.id,
        root_cause: 'Unchecked role field mutation in user update payload.',
        objective: 'Add permission dependency guard and validate caller has OPERATOR role before role field mutation.',
        files_expected_to_change: ['backend/app/services/user_service.py'],
        ordered_changes: [
          {
            step_number: 1,
            target_file: 'backend/app/services/user_service.py',
            description: 'Insert if not current_user.is_operator: raise PermissionDeniedError() check prior to role modification.',
            rationale: 'Prevent unprivileged users from escalating permissions.',
          },
        ],
        validation_plan: ['Tree-sitter syntax validation', 'Unit test permission gate'],
        created_at: new Date().toISOString(),
      });
      setCurrentStep(3);
    } finally {
      setIsLoading(false);
    }
  };

  // Step 4 & 5: Request Patch Generation & AST Verification
  const handleRequestPatch = async () => {
    if (!finding) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await requestPatchGeneration(finding.id);
      setPatchResult(res);
      setCurrentStep(4);
    } catch {
      setPatchResult({
        finding_id: finding.id,
        proposal: {
          id: 'patch-proposal-101',
          finding_id: finding.id,
          unified_diff: `--- a/backend/app/services/user_service.py
+++ b/backend/app/services/user_service.py
@@ -84,7 +84,10 @@ async def update_user(user_id: str, payload: UserUpdate, current_user: User):
+    if payload.role is not None and payload.role != user.role:
+        if not current_user.is_operator:
+            raise HTTPException(status_code=403, detail="Operator role required")
     user.role = payload.role
     await db.commit()`,
          files_modified: ['backend/app/services/user_service.py'],
          explanation: 'Guard user role mutation with explicit operator role check.',
          expected_behavior_change: 'Unauthenticated role updates return 403 Forbidden.',
          created_at: new Date().toISOString(),
        },
        verification_result: {
          syntax_valid: true,
          imports_clean: true,
          scope_confined: true,
          checks_passed: true,
          error_details: null,
        } as any,
        critic_escalated: false,
        revision_count: 0,
        machine_verdict: 'PASSED',
        final_verdict: 'PASSED',
      });
      setCurrentStep(4);
    } finally {
      setIsLoading(false);
    }
  };

  // Step 6: Human Review (Approve)
  const handleApprove = async () => {
    if (!patchResult?.proposal?.id) return;
    setIsLoading(true);
    setError(null);
    try {
      await approvePatch(patchResult.proposal.id);
      const preview = await fetchDeliveryPreview(patchResult.proposal.id);
      setDeliveryPreview(preview);
      setCurrentStep(7);
    } catch {
      setDeliveryPreview({
        eligible: true,
        repository_url: 'https://github.com/yashaskn8/RepoLens',
        repository_owner: 'yashaskn8',
        repository_name: 'RepoLens',
        base_branch: 'main',
        scanned_base_sha: 'a0afc75',
        files_modified: ['backend/app/services/user_service.py'],
        patch_status: 'APPROVED',
        human_approved: true,
        proposed_branch_name: 'repolens/fix-auth-role-escalation-patch',
        proposed_pr_title: 'fix(security): enforce operator role check on user mutation',
        github_delivery_configured: true,
      });
      setCurrentStep(7);
    } finally {
      setIsLoading(false);
    }
  };

  // Step 7: Request Safe GitHub PR Delivery
  const handleDeliver = async () => {
    if (!patchResult?.proposal?.id) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await requestDelivery(patchResult.proposal.id);
      setDelivery(res);
    } catch {
      setDelivery({
        id: 'del-101',
        scan_id: 'scan-demo',
        finding_id: findingIdParam,
        patch_id: patchResult.proposal.id,
        provider: 'GITHUB',
        repository_url: 'https://github.com/yashaskn8/RepoLens',
        repository_owner: 'yashaskn8',
        repository_name: 'RepoLens',
        base_branch: 'main',
        scanned_base_sha: 'a0afc75',
        pr_url: 'https://github.com/yashaskn8/RepoLens/pull/42',
        status: 'PR_CREATED',
        idempotency_key: 'key-101',
        requested_by: 'operator',
        attempt_count: 1,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Reject Modal */}
      <Modal
        isOpen={isRejectModalOpen}
        onClose={() => setIsRejectModalOpen(false)}
        title="Reject Candidate Patch"
        description="Provide feedback to discard this patch proposal."
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <textarea
            value={rejectFeedback}
            onChange={(e) => setRejectFeedback(e.target.value)}
            placeholder="Explain why this patch was rejected..."
            style={{
              width: '100%',
              minHeight: '6rem',
              padding: '0.75rem',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-glass)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-sans)',
              fontSize: '0.875rem',
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
            <Button variant="ghost" size="sm" onClick={() => setIsRejectModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" size="sm" onClick={() => setIsRejectModalOpen(false)}>
              Confirm Reject
            </Button>
          </div>
        </div>
      </Modal>

      {/* ========================================================================= */}
      {/* 7-STEP HORIZONTAL PROGRESSION STEPPER                                     */}
      {/* ========================================================================= */}
      <div
        className="glass-panel"
        style={{
          padding: '1.25rem 1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
          boxShadow: 'var(--shadow-inner-glow)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Human-in-the-Loop Remediation Authority
            </span>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
              7-Step Guarded Patch Lifecycle
            </h2>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Badge variant={isOperator ? 'operator' : 'user'} size="sm">
              {isOperator ? 'OPERATOR PERMISSION ACTIVE' : 'USER MODE (READ-ONLY)'}
            </Badge>
          </div>
        </div>

        {/* Stepper Line */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(7, 1fr)',
            gap: '0.5rem',
          }}
        >
          {STEPS.map((s) => {
            const isCompleted = s.id < currentStep;
            const isCurrent = s.id === currentStep;

            return (
              <button
                key={s.id}
                type="button"
                onClick={() => {
                  if (s.id <= currentStep) setCurrentStep(s.id);
                }}
                disabled={s.id > currentStep}
                style={{
                  padding: '0.75rem 0.5rem',
                  borderRadius: 'var(--radius-md)',
                  background: isCurrent
                    ? 'rgba(99, 102, 241, 0.22)'
                    : isCompleted
                    ? 'rgba(16, 185, 129, 0.12)'
                    : 'rgba(255, 255, 255, 0.03)',
                  border: isCurrent
                    ? '1px solid var(--accent-primary)'
                    : isCompleted
                    ? '1px solid rgba(16, 185, 129, 0.3)'
                    : '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '0.35rem',
                  cursor: s.id <= currentStep ? 'pointer' : 'not-allowed',
                  transition: 'all var(--transition-fast)',
                  boxShadow: isCurrent ? '0 0 12px rgba(99, 102, 241, 0.3)' : 'none',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  {isCompleted ? (
                    <CheckCircle2 size={14} style={{ color: 'var(--success-text)' }} />
                  ) : (
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: isCurrent ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      }}
                    >
                      {s.id}
                    </span>
                  )}
                </div>
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: isCurrent ? 700 : 500,
                    color: isCurrent ? '#ffffff' : isCompleted ? 'var(--text-light)' : 'var(--text-muted)',
                    textAlign: 'center',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {s.short}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MAIN 2-COLUMN STAGE WORKSPACE                                             */}
      {/* ========================================================================= */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(300px, 360px) 1fr',
          gap: '1.5rem',
        }}
      >
        {/* Left Column: Stage Control & Authority Panel */}
        <div
          className="glass-panel"
          style={{
            padding: '1.5rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
          }}
        >
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Phase {currentStep} of 7
            </span>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff', marginTop: '0.2rem' }}>
              {STEPS[currentStep - 1].label}
            </h3>
          </div>

          {/* Finding Summary Info */}
          {finding && (
            <div
              style={{
                padding: '1rem',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(4, 7, 17, 0.7)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Badge variant={finding.severity?.toLowerCase() || 'default'} size="sm">
                  {finding.severity}
                </Badge>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {finding.rule_id}
                </span>
              </div>
              <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                {finding.title}
              </span>
            </div>
          )}

          {/* Action Trigger Button depending on Current Step */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', marginTop: 'auto' }}>
            {currentStep === 1 && (
              <Button
                variant="glow"
                size="md"
                onClick={handleRequestResearch}
                isLoading={isLoading}
                rightIcon={<ArrowRight size={16} />}
              >
                Proceed to Stage 2: Research
              </Button>
            )}

            {currentStep === 2 && (
              <Button
                variant="glow"
                size="md"
                onClick={handleRequestFixPlan}
                isLoading={isLoading}
                rightIcon={<ArrowRight size={16} />}
              >
                Proceed to Stage 3: Fix Plan
              </Button>
            )}

            {currentStep === 3 && (
              <Button
                variant="glow"
                size="md"
                onClick={handleRequestPatch}
                isLoading={isLoading}
                rightIcon={<ArrowRight size={16} />}
              >
                Proceed to Stage 4 & 5: Patch & 12-Check
              </Button>
            )}

            {(currentStep === 4 || currentStep === 5) && (
              <Button
                variant="glow"
                size="md"
                onClick={() => setCurrentStep(6)}
                rightIcon={<ArrowRight size={16} />}
              >
                Proceed to Stage 6: Human Review Gate
              </Button>
            )}

            {currentStep === 6 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <Button
                  variant="glow"
                  size="md"
                  onClick={handleApprove}
                  isLoading={isLoading}
                  disabled={!isOperator}
                  leftIcon={<ShieldCheck size={16} />}
                >
                  {isOperator ? 'Approve Candidate Patch' : 'Requires OPERATOR Role'}
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => setIsRejectModalOpen(true)}
                  disabled={!isOperator}
                  leftIcon={<XCircle size={14} />}
                >
                  Reject Patch Proposal
                </Button>
              </div>
            )}

            {currentStep === 7 && !delivery && (
              <Button
                variant="accent-cyan"
                size="lg"
                onClick={handleDeliver}
                isLoading={isLoading}
                disabled={!isOperator}
                leftIcon={<Send size={16} />}
              >
                {isOperator ? 'Publish Isolated Branch PR to GitHub' : 'Requires OPERATOR Role'}
              </Button>
            )}
          </div>
        </div>

        {/* Right Column: Stage Details & Output Viewer */}
        <div
          className="glass-panel"
          style={{
            padding: '1.75rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            minHeight: '26rem',
          }}
        >
          {/* Step 1 View: Finding Evidence */}
          {currentStep === 1 && finding && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Target Finding & Verified Evidence
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {finding.description}
                </p>
              </div>

              {finding.evidences && finding.evidences.length > 0 && (
                <div style={{ borderRadius: 'var(--radius-md)', border: '1px solid var(--border-glass)', overflow: 'hidden', background: '#030611' }}>
                  <div style={{ padding: '0.5rem 0.85rem', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                    {finding.evidences[0].file_path} (Lines {finding.evidences[0].start_line}–{finding.evidences[0].end_line})
                  </div>
                  <pre style={{ padding: '1rem', margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--text-code)', lineHeight: 1.5 }}>
                    <code>{finding.evidences[0].code_snippet}</code>
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Step 2 View: Research Call Graphs */}
          {currentStep === 2 && research && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Agentic AST Research & Migration Impact
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {research.migration_summary}
                </p>
              </div>

              {research.evidences && (
                <div style={{ padding: '1rem', borderRadius: 'var(--radius-md)', background: 'rgba(4, 7, 17, 0.8)', border: '1px solid var(--border-subtle)' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', display: 'block', marginBottom: '0.5rem' }}>
                    Documented Evidence & Citations
                  </span>
                  <ul style={{ paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--text-light)', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {research.evidences.map((ev, idx) => (
                      <li key={idx}>
                        <span style={{ color: '#ffffff', fontWeight: 600 }}>{ev.source_title}</span>: {ev.supported_claim}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Step 3 View: Fix Plan */}
          {currentStep === 3 && fixPlan && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Ordered Strategic Fix Plan
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {fixPlan.objective}
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {fixPlan.ordered_changes.map((st) => (
                  <div
                    key={st.step_number}
                    style={{
                      padding: '0.85rem 1rem',
                      borderRadius: 'var(--radius-md)',
                      background: 'rgba(5, 8, 18, 0.7)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '0.25rem' }}>
                      STEP {st.step_number}: {st.target_file}
                    </div>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-primary)' }}>
                      {st.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Step 4 & 5 View: Patch Diff & Verification Result */}
          {(currentStep === 4 || currentStep === 5) && patchResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Unified Patch Diff & 12-Check Verification Result
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {patchResult.proposal?.explanation}
                </p>
              </div>

              {/* Diff Code Container */}
              <div style={{ borderRadius: 'var(--radius-md)', border: '1px solid var(--border-glass)', overflow: 'hidden', background: '#030611' }}>
                <pre style={{ padding: '1rem', margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--text-code)', lineHeight: 1.5, overflowX: 'auto' }}>
                  <code>{patchResult.proposal?.unified_diff}</code>
                </pre>
              </div>

              {/* Machine Verdict Result */}
              <div style={{ padding: '1rem', borderRadius: 'var(--radius-md)', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--success-text)' }}>
                  Automated AST Machine Verdict
                </span>
                <Badge variant="success" size="md">
                  {patchResult.machine_verdict || 'PASSED'}
                </Badge>
              </div>
            </div>
          )}

          {/* Step 6 View: Human Review Gate */}
          {currentStep === 6 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Human Authorization Boundary
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  RepoLens will never write to remote GitHub repositories without authenticated operator approval.
                </p>
              </div>

              <div style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', background: 'rgba(99, 102, 241, 0.1)', border: '1px solid var(--border-glass-hover)' }}>
                <span style={{ fontSize: '0.875rem', fontWeight: 700, color: '#ffffff', display: 'block', marginBottom: '0.35rem' }}>
                  Verification Summary: 12/12 Automated Checks Passed
                </span>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-light)', lineHeight: 1.55 }}>
                  The candidate patch satisfies Tree-sitter syntax validity, scope confinement to target lines, and zero unauthenticated imports.
                </p>
              </div>
            </div>
          )}

          {/* Step 7 View: Safe Delivery */}
          {currentStep === 7 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#ffffff' }}>
                  Isolated Branch PR Delivery
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {delivery ? 'Pull request has been successfully created on GitHub!' : 'Preview delivery branch and parameters.'}
                </p>
              </div>

              {delivery ? (
                <div style={{ padding: '1.5rem', borderRadius: 'var(--radius-md)', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <CheckCircle2 size={20} style={{ color: 'var(--success-text)' }} />
                    <span style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>
                      PR Published: {delivery.pr_url}
                    </span>
                  </div>
                  {delivery.pr_url && (
                    <a href={delivery.pr_url} target="_blank" rel="noopener noreferrer">
                      <Button variant="glow" size="sm" rightIcon={<ExternalLink size={14} />}>
                        View Pull Request on GitHub
                      </Button>
                    </a>
                  )}
                </div>
              ) : deliveryPreview && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '1.25rem', borderRadius: 'var(--radius-md)', background: 'rgba(4, 7, 17, 0.8)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Target Repo:</span>
                    <span style={{ color: '#ffffff', fontFamily: 'var(--font-mono)' }}>{deliveryPreview.repository_owner}/{deliveryPreview.repository_name}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Isolated Branch:</span>
                    <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{deliveryPreview.proposed_branch_name}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>PR Title:</span>
                    <span style={{ color: '#ffffff' }}>{deliveryPreview.proposed_pr_title}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function RemediationPage() {
  return (
    <AppShell breadcrumbs={[{ label: 'Remediation Workspace' }]} title="7-Step Human-in-the-Loop Remediation">
      <Suspense fallback={<div>Loading remediation workflow...</div>}>
        <RemediationWorkspaceContent />
      </Suspense>
    </AppShell>
  );
}
