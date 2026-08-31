import React from 'react';
import { DeliveryPreviewResponse } from '@/types/domain';
import { Button } from '@/components/ui/Button';

export interface DeliveryPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  deliveryPreview: DeliveryPreviewResponse | null;
  deliveryRequestedBy: string;
  onDeliveryRequestedByChange: (val: string) => void;
  deliveryNotes: string;
  onDeliveryNotesChange: (val: string) => void;
  onConfirmDelivery: () => void;
  isDelivering: boolean;
}

export const DeliveryPreviewModal: React.FC<DeliveryPreviewModalProps> = ({
  isOpen,
  onClose,
  deliveryPreview,
  deliveryRequestedBy,
  onDeliveryRequestedByChange,
  deliveryNotes,
  onDeliveryNotesChange,
  onConfirmDelivery,
  isDelivering,
}) => {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="delivery-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs animate-in fade-in duration-200"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-xl border border-neutral-800 bg-neutral-950 p-6 shadow-2xl space-y-5 text-neutral-200 animate-in zoom-in-95 duration-200">
        <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
          <h3 id="delivery-modal-title" className="text-base font-semibold text-neutral-100 flex items-center gap-2">
            <span aria-hidden="true">🛡️</span> Confirm GitHub Pull Request Delivery
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close delivery modal"
            className="text-neutral-400 hover:text-neutral-200 transition"
          >
            ✕
          </button>
        </div>

        <div className="text-xs space-y-3 text-neutral-300">
          <div className="rounded-lg bg-neutral-900 p-3 space-y-1.5 border border-neutral-800">
            <div className="flex justify-between">
              <span className="text-neutral-400">Target Repository:</span>
              <span className="font-semibold text-neutral-100">
                {deliveryPreview?.repository_owner}/{deliveryPreview?.repository_name}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-400">Target Base Branch:</span>
              <span className="font-mono text-sky-400">{deliveryPreview?.base_branch || 'main'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-400">New Dedicated Branch:</span>
              <span className="font-mono text-emerald-400">{deliveryPreview?.proposed_branch_name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-400">Files to Patch:</span>
              <span>{deliveryPreview?.files_modified.length || 0} file(s)</span>
            </div>
          </div>

          {/* Safety Guarantees Callout */}
          <div className="rounded-lg bg-sky-950/30 border border-sky-900/60 p-3 space-y-1 text-[11px] text-sky-300">
            <div className="font-semibold">Safety Boundary & Execution Rules:</div>
            <ul className="list-disc list-inside space-y-0.5 text-neutral-300">
              <li>RepoLens will <strong>never write directly</strong> to the default/base branch.</li>
              <li>RepoLens will <strong>never automatically merge</strong> or close pull requests.</li>
              <li>
                The pull request contains human-approved code verified against commit{' '}
                <code className="font-mono">{deliveryPreview?.scanned_base_sha?.slice(0, 8)}</code>.
              </li>
            </ul>
          </div>

          {/* Sign-off Inputs */}
          <div className="space-y-2 pt-1">
            <div>
              <label className="block text-[11px] font-medium text-neutral-300 mb-1">
                Requested By (User Identifier):
              </label>
              <input
                type="text"
                value={deliveryRequestedBy}
                onChange={(e) => onDeliveryRequestedByChange(e.target.value)}
                placeholder="e.g. lead-engineer"
                className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-neutral-300 mb-1">
                Optional Delivery Notes / Sign-off:
              </label>
              <textarea
                rows={2}
                value={deliveryNotes}
                onChange={(e) => onDeliveryNotesChange(e.target.value)}
                placeholder="e.g. Reviewed and authorized for production remediation"
                className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-1.5 text-xs text-neutral-200 focus:outline-none focus:border-sky-500 resize-none"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end space-x-3 pt-2 border-t border-neutral-800">
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            disabled={isDelivering}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={onConfirmDelivery}
            disabled={isDelivering}
            isLoading={isDelivering}
            className="bg-emerald-700 hover:bg-emerald-600 border-emerald-600"
          >
            {isDelivering ? 'Delivering...' : 'Confirm & Create Pull Request'}
          </Button>
        </div>
      </div>
    </div>
  );
};
