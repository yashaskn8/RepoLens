import React from 'react';
import { ReviewPublicationPreviewResponse } from '@/types/domain';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';

export interface ReviewPublicationPanelProps {
  publication: ReviewPublicationPreviewResponse | null;
  isGeneratingPreview: boolean;
  isApprovingPub: boolean;
  isPublishingPub: boolean;
  pubError: string | null;
  showPublishConfirm: boolean;
  copiedDigest: boolean;
  isAnalysisCompleted: boolean;
  onGeneratePreview: () => void;
  onApprovePublication: () => void;
  onPublishReview: () => void;
  onCopyDigest: () => void;
  onSetShowPublishConfirm: (show: boolean) => void;
}

export const ReviewPublicationPanel: React.FC<ReviewPublicationPanelProps> = ({
  publication,
  isGeneratingPreview,
  isApprovingPub,
  isPublishingPub,
  pubError,
  showPublishConfirm,
  copiedDigest,
  isAnalysisCompleted,
  onGeneratePreview,
  onApprovePublication,
  onPublishReview,
  onCopyDigest,
  onSetShowPublishConfirm,
}) => {
  const getStatusBadgeStyle = (status: string) => {
    switch (status) {
      case 'PUBLISHED':
        return { bg: 'rgba(34, 197, 94, 0.2)', color: '#4ade80', border: 'rgba(34, 197, 94, 0.4)' };
      case 'APPROVED':
        return { bg: 'rgba(234, 179, 8, 0.2)', color: '#facc15', border: 'rgba(234, 179, 8, 0.4)' };
      case 'PREVIEW_READY':
        return { bg: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', border: 'rgba(56, 189, 248, 0.4)' };
      default:
        return { bg: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: 'rgba(239, 68, 68, 0.4)' };
    }
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header & Invariants Banner */}
      <div className="p-5 bg-slate-900/75 border border-white/10 rounded-xl">
        <div className="flex justify-between items-center flex-wrap gap-4">
          <div>
            <div className="text-lg font-bold text-slate-100">
              Safe GitHub Pull Request Review Publication
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Publish verified change review directly back to the pull request with strict human authorization.
            </div>
          </div>

          {publication && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Status:</span>
              <span
                className="badge"
                style={{
                  background: getStatusBadgeStyle(publication.status).bg,
                  color: getStatusBadgeStyle(publication.status).color,
                  borderColor: getStatusBadgeStyle(publication.status).border,
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  fontWeight: 700,
                }}
              >
                {publication.status}
              </span>
            </div>
          )}
        </div>

        {/* Safety Invariants Checklist */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 pt-4 border-t border-white/10 text-xs text-slate-300">
          <div className="flex items-center gap-1.5">
            <span className="text-emerald-400 font-bold">✓</span> Review Event: <code className="font-mono text-slate-200">COMMENT</code> only
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-emerald-400 font-bold">✓</span> Auto PR Merge: <code className="font-mono text-slate-200">Disabled</code>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-emerald-400 font-bold">✓</span> SHA-256 Parity: <code className="font-mono text-slate-200">Enforced</code>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-emerald-400 font-bold">✓</span> Secret Redaction: <code className="font-mono text-slate-200">Active</code>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {pubError && (
        <Alert variant="error" title="Action Failed">
          {pubError}
        </Alert>
      )}

      {/* State 1: No preview generated yet */}
      {!publication && (
        <Card className="!p-10 text-center flex flex-col items-center gap-4">
          <div className="text-4xl" aria-hidden="true">📋</div>
          <div className="text-lg font-bold text-slate-100">
            Generate Review Publication Preview
          </div>
          <div className="max-w-lg text-slate-400 text-xs leading-relaxed">
            Compute the exact deterministic review markdown, verify live pull request drift against immutable commit SHAs, and calculate the cryptographic SHA-256 preview digest. <strong>Makes ZERO writes to GitHub.</strong>
          </div>
          <Button
            variant="primary"
            disabled={isGeneratingPreview || !isAnalysisCompleted}
            onClick={onGeneratePreview}
            isLoading={isGeneratingPreview}
          >
            {isGeneratingPreview ? 'Computing Preview...' : '✨ Generate Review Preview'}
          </Button>
        </Card>
      )}

      {/* State 2+: Publication object exists */}
      {publication && (
        <>
          {/* Published Banner */}
          {publication.status === 'PUBLISHED' && (
            <div className="p-4 bg-emerald-950/30 border border-emerald-700/50 rounded-xl flex justify-between items-center flex-wrap gap-4">
              <div>
                <div className="text-sm font-bold text-emerald-400">
                  ✓ Review Successfully Published to GitHub Pull Request #{publication.pr_number}
                </div>
                <div className="text-xs text-slate-300 mt-1">
                  Review ID: <code className="font-mono">{publication.github_review_id}</code> • Published at:{' '}
                  {publication.published_at ? new Date(publication.published_at).toLocaleString() : 'Just now'}
                  {publication.reconciliation_occurred && (
                    <span className="ml-2 text-sky-400">
                      (Reconciled via hidden audit marker)
                    </span>
                  )}
                </div>
              </div>
              {publication.github_review_url && (
                <a
                  href={publication.github_review_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-primary !text-xs !py-1.5 !px-3.5"
                >
                  🔗 View on GitHub ↗
                </a>
              )}
            </div>
          )}

          {/* Blocked or Failed Banner */}
          {(publication.status === 'BLOCKED' || publication.status === 'FAILED') && (
            <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-xl">
              <div className="text-sm font-bold text-rose-400">
                🚫 Publication {publication.status}: {publication.failure_code || 'ERROR'}
              </div>
              <div className="text-xs text-rose-300 mt-1">
                {publication.failure_message || 'Pull request drift or policy constraint blocked publication.'}
              </div>
              <div className="mt-3">
                <Button
                  variant="filter"
                  size="sm"
                  onClick={onGeneratePreview}
                  disabled={isGeneratingPreview}
                >
                  {isGeneratingPreview ? 'Refreshing...' : '🔄 Re-evaluate PR & Generate Fresh Preview'}
                </Button>
              </div>
            </div>
          )}

          {/* Canonical Digest & Action Controls */}
          <Card className="!p-5 flex flex-col gap-4">
            <div className="flex justify-between items-center flex-wrap gap-3">
              <div className="text-xs text-slate-400 font-semibold">
                CANONICAL PREVIEW DIGEST (SHA-256)
              </div>
              <div className="text-xs text-slate-500 font-mono">
                Base: {publication.base_commit_sha.slice(0, 8)} → Head: {publication.head_commit_sha.slice(0, 8)}
              </div>
            </div>

            <div className="flex items-center gap-3 bg-slate-950 p-3 rounded-lg border border-white/10 font-mono text-xs text-sky-400 overflow-x-auto">
              <span className="flex-1 break-all">{publication.preview_digest}</span>
              <Button
                variant="filter"
                size="sm"
                onClick={onCopyDigest}
                className="whitespace-nowrap"
              >
                {copiedDigest ? '✓ Copied' : '📋 Copy'}
              </Button>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3 flex-wrap items-center mt-2">
              {publication.status === 'PREVIEW_READY' && (
                <>
                  <Button
                    variant="primary"
                    disabled={isApprovingPub || isGeneratingPreview}
                    onClick={onApprovePublication}
                    isLoading={isApprovingPub}
                    className="bg-blue-600 hover:bg-blue-500"
                  >
                    {isApprovingPub ? 'Authorizing...' : '✍️ Approve Review Publication'}
                  </Button>
                  <Button
                    variant="filter"
                    size="sm"
                    disabled={isGeneratingPreview}
                    onClick={onGeneratePreview}
                  >
                    {isGeneratingPreview ? 'Refreshing...' : '🔄 Refresh Preview'}
                  </Button>
                </>
              )}

              {publication.status === 'APPROVED' && (
                <>
                  <Button
                    variant="primary"
                    disabled={isPublishingPub}
                    onClick={() => onSetShowPublishConfirm(true)}
                    className="bg-emerald-600 hover:bg-emerald-500"
                  >
                    🚀 Publish Review to GitHub PR #{publication.pr_number}
                  </Button>
                  <Button
                    variant="filter"
                    size="sm"
                    disabled={isGeneratingPreview}
                    onClick={onGeneratePreview}
                  >
                    🔄 Regenerate Preview (Resets Approval)
                  </Button>
                </>
              )}

              {publication.status === 'PUBLISHED' && (
                <Button
                  variant="filter"
                  size="sm"
                  disabled={isGeneratingPreview}
                  onClick={onGeneratePreview}
                >
                  🔄 Re-verify & Check Publication Status
                </Button>
              )}
            </div>
          </Card>

          {/* Safety Confirmation Modal */}
          {showPublishConfirm && (
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="publish-modal-title"
              className="fixed inset-0 bg-black/75 backdrop-blur-xs flex items-center justify-center z-50 p-4 animate-in fade-in duration-200"
              onClick={() => onSetShowPublishConfirm(false)}
            >
              <div
                className="max-w-lg w-full p-6 bg-slate-900 border border-white/15 rounded-2xl shadow-2xl space-y-4 animate-in zoom-in-95 duration-200"
                onClick={(e) => e.stopPropagation()}
              >
                <div id="publish-modal-title" className="text-lg font-bold text-slate-100">
                  Authorize Pull Request Review Publication
                </div>
                <div className="text-xs text-slate-300 leading-relaxed">
                  You are about to publish a <strong>COMMENT</strong> review to GitHub. Please verify the publication targets:
                </div>

                <div className="bg-slate-950 rounded-lg p-4 text-xs font-mono text-slate-200 flex flex-col gap-2 border border-slate-800">
                  <div><strong>Repository:</strong> {publication.repository_owner}/{publication.repository_name}</div>
                  <div><strong>Pull Request:</strong> #{publication.pr_number}</div>
                  <div><strong>Head Commit:</strong> {publication.head_commit_sha}</div>
                  <div><strong>Inline Comments:</strong> {publication.inline_comments?.length || 0} verified comment(s)</div>
                  <div><strong>Review Event:</strong> <code>COMMENT</code> (strictly non-mutating)</div>
                  <div className="break-all"><strong>Digest:</strong> {publication.preview_digest}</div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onSetShowPublishConfirm(false)}
                    disabled={isPublishingPub}
                  >
                    Cancel
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={isPublishingPub}
                    isLoading={isPublishingPub}
                    onClick={onPublishReview}
                    className="bg-emerald-600 hover:bg-emerald-500"
                  >
                    {isPublishingPub ? 'Publishing to GitHub...' : '✓ Confirm & Publish Review'}
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Inline Comments Preview */}
          {publication.inline_comments && publication.inline_comments.length > 0 && (
            <div>
              <div className="text-base font-semibold text-slate-100 mb-3 flex items-center gap-2">
                <span>💬</span> Mapped Inline Comments ({publication.inline_comments.length})
              </div>
              <div className="flex flex-col gap-3">
                {publication.inline_comments.map((ic, idx) => (
                  <div key={idx} className="finding-card">
                    <div className="flex justify-between items-center flex-wrap gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge severity={(ic.severity as any) || 'HIGH'}>{ic.severity || 'HIGH'}</Badge>
                        <span className="font-mono font-semibold text-sky-400 text-xs">
                          {ic.path}:{ic.line}
                        </span>
                        <Badge variant="tag">Side: {ic.side}</Badge>
                      </div>
                      {ic.finding_title && (
                        <span className="text-xs text-slate-400">{ic.finding_title}</span>
                      )}
                    </div>
                    <div className="mt-2.5 text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                      {ic.body}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Rendered Review Markdown Preview */}
          <div>
            <div className="text-base font-semibold text-slate-100 mb-3 flex items-center gap-2">
              <span>📄</span> Top-Level Review Body Preview
            </div>
            <pre className="bg-slate-950 border border-white/10 rounded-lg p-5 text-xs font-mono text-slate-200 max-h-[400px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
              {publication.body_markdown}
            </pre>
          </div>
        </>
      )}
    </div>
  );
};
