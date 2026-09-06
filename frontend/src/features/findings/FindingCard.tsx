import React from 'react';
import { Finding } from '@/types/domain';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { FindingEvidence } from './FindingEvidence';
import { RemediationLifecycle } from '@/components/RemediationLifecycle';
import { AlertCircle, AlertTriangle, FileCode, HelpCircle, ShieldAlert, Sparkles, Wrench } from 'lucide-react';

export interface FindingCardProps {
  finding: Finding;
  isExpanded: boolean;
  onToggleExpand: () => void;
}

/**
 * Returns a human-friendly explanation of why a finding matters based on category/severity.
 */
function getImpactExplanation(finding: Finding): string {
  if (finding.description && finding.description.length > 20) {
    return finding.description;
  }
  switch (finding.severity) {
    case 'CRITICAL':
      return 'Critical security risk: Can lead to unauthorized access, privilege escalation, or arbitrary code execution.';
    case 'HIGH':
      return 'High risk: Exposes sensitive data, circumvents access controls, or creates severe architectural fragility.';
    case 'MEDIUM':
      return 'Medium risk: Insecure configuration, missing input sanitization, or breaking contract inconsistency.';
    case 'LOW':
    default:
      return 'Code quality or maintenance debt: Could degrade maintainability or introduce subtle defects over time.';
  }
}

/**
 * Returns a clear recommended action for the finding.
 */
function getRecommendation(finding: Finding): string {
  if (finding.mitigation_guidance) {
    return finding.mitigation_guidance;
  }
  if (finding.category?.toLowerCase().includes('auth') || finding.title.toLowerCase().includes('token')) {
    return 'Ensure credentials and tokens are loaded securely from environment secrets and never committed to source.';
  }
  if (finding.category?.toLowerCase().includes('injection') || finding.title.toLowerCase().includes('sql')) {
    return 'Use parameterized queries or an ORM to prevent unsanitized user inputs from being executed directly.';
  }
  return 'Apply input validation, confine permissions, and verify that test coverage guards against regressions.';
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  isExpanded,
  onToggleExpand,
}) => {
  const primaryEvidence = finding.evidences && finding.evidences.length > 0 ? finding.evidences[0] : null;

  return (
    <article
      className="finding-card"
      style={{
        borderRadius: 'var(--radius-lg)',
        backgroundColor: 'rgba(9, 13, 26, 0.85)',
        border: '1px solid var(--border-glass)',
        padding: '1.25rem 1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      {/* Header Badges & Severity */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Badge
            variant={
              finding.severity === 'CRITICAL'
                ? 'critical'
                : finding.severity === 'HIGH'
                ? 'high'
                : finding.severity === 'MEDIUM'
                ? 'medium'
                : 'low'
            }
            size="sm"
          >
            {finding.severity}
          </Badge>

          {finding.verification_verdict && (
            <Badge
              variant={finding.verification_verdict === 'CONFIRMED' ? 'success' : 'medium'}
              size="sm"
            >
              {finding.verification_verdict === 'CONFIRMED' ? 'Verified' : finding.verification_verdict}
            </Badge>
          )}

          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
            {finding.category || 'Security Finding'}
          </span>
        </div>

        {finding.rule_id && (
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Rule: {finding.rule_id}
          </span>
        )}
      </div>

      {/* 4-Question Structured Format */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {/* 1. What happened? */}
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'baseline' }}>
          <div style={{ width: '130px', flexShrink: 0, fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
            What happened?
          </div>
          <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#ffffff', lineHeight: 1.4 }}>
            {finding.title}
          </div>
        </div>

        {/* 2. Why does it matter? */}
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'baseline' }}>
          <div style={{ width: '130px', flexShrink: 0, fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
            Why it matters
          </div>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-light)', lineHeight: 1.5 }}>
            {getImpactExplanation(finding)}
          </div>
        </div>

        {/* 3. Where is it? */}
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'baseline' }}>
          <div style={{ width: '130px', flexShrink: 0, fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
            Where is it?
          </div>
          <div style={{ flex: 1 }}>
            {primaryEvidence ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8125rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                  <FileCode size={14} />
                  <span>{primaryEvidence.file_path}</span>
                  {primaryEvidence.start_line && (
                    <span style={{ color: 'var(--text-muted)' }}>
                      :L{primaryEvidence.start_line}
                      {primaryEvidence.end_line && primaryEvidence.end_line !== primaryEvidence.start_line ? `-L${primaryEvidence.end_line}` : ''}
                    </span>
                  )}
                </div>

                {primaryEvidence.code_snippet && (
                  <pre
                    style={{
                      margin: '0.35rem 0 0 0',
                      padding: '0.65rem 0.85rem',
                      background: '#030611',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-code)',
                      overflowX: 'auto',
                    }}
                  >
                    <code>{primaryEvidence.code_snippet}</code>
                  </pre>
                )}
              </div>
            ) : (
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                Identified in repository configuration or manifest
              </span>
            )}
          </div>
        </div>

        {/* 4. What should I do? */}
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'baseline' }}>
          <div style={{ width: '130px', flexShrink: 0, fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
            What to do
          </div>
          <div style={{ fontSize: '0.8125rem', color: '#6ee7b7', lineHeight: 1.5, background: 'rgba(16, 185, 129, 0.08)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(16, 185, 129, 0.2)', width: '100%' }}>
            {getRecommendation(finding)}
          </div>
        </div>
      </div>

      {/* Remediation Lifecycle Action Button */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
        <Button
          variant={isExpanded ? 'secondary' : 'glow'}
          size="sm"
          onClick={onToggleExpand}
          aria-expanded={isExpanded}
          leftIcon={<Wrench size={14} />}
        >
          {isExpanded ? 'Hide Suggested Fix' : 'View Suggested Fix'}
        </Button>
      </div>

      {/* Embedded Remediation Lifecycle */}
      {isExpanded && (
        <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
          <RemediationLifecycle finding={finding} />
        </div>
      )}
    </article>
  );
};
