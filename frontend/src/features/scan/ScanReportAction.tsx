'use client';

import { useCallback, useEffect, useState } from 'react';
import { Download, FileDown, RefreshCw } from 'lucide-react';

import { Button } from '@/components/ui/Button';
import { downloadReportPdf, fetchLatestScanReport, fetchReport, requestScanReport } from '@/lib/api';
import type { ScanReportResource, ScanStatus } from '@/types/domain';


const ACTIVE_STATUSES = new Set(['REQUESTED', 'ASSEMBLING', 'RENDERING']);

interface ScanReportActionProps {
  scanId: string;
  scanStatus: ScanStatus;
}

export function ScanReportAction({ scanId, scanStatus }: ScanReportActionProps) {
  const [report, setReport] = useState<ScanReportResource | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(scanStatus === 'COMPLETED');
  const [isRequesting, setIsRequesting] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [transportError, setTransportError] = useState<string | null>(null);

  useEffect(() => {
    if (scanStatus !== 'COMPLETED') {
      setIsDiscovering(false);
      return;
    }
    const controller = new AbortController();
    setIsDiscovering(true);
    fetchLatestScanReport(scanId, controller.signal)
      .then((latest) => {
        setReport(latest);
        setTransportError(null);
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setTransportError(error instanceof Error ? error.message : 'Could not restore report status.');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setIsDiscovering(false);
      });
    return () => controller.abort();
  }, [scanId, scanStatus]);

  useEffect(() => {
    if (!report || !ACTIVE_STATUSES.has(report.status)) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const poll = async () => {
      try {
        const next = await fetchReport(report.id, controller.signal);
        if (controller.signal.aborted) return;
        setReport(next);
        setTransportError(null);
        if (ACTIVE_STATUSES.has(next.status)) timer = setTimeout(poll, 1500);
      } catch (error: unknown) {
        if (controller.signal.aborted) return;
        setTransportError(error instanceof Error ? error.message : 'Report status is temporarily unavailable.');
        timer = setTimeout(poll, 3000);
      }
    };

    timer = setTimeout(poll, 1000);
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [report?.id, report?.status]);

  const generate = useCallback(async () => {
    setIsRequesting(true);
    setTransportError(null);
    try {
      setReport(await requestScanReport(scanId));
    } catch (error: unknown) {
      setTransportError(error instanceof Error ? error.message : 'Could not request the PDF report.');
    } finally {
      setIsRequesting(false);
    }
  }, [scanId]);

  const download = useCallback(async () => {
    if (!report || report.status !== 'READY') return;
    setIsDownloading(true);
    setTransportError(null);
    try {
      const blob = await downloadReportPdf(report.id);
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = `repolens-report-${scanId.slice(0, 8)}.pdf`;
      anchor.style.display = 'none';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
    } catch (error: unknown) {
      setTransportError(error instanceof Error ? error.message : 'Could not download the PDF report.');
    } finally {
      setIsDownloading(false);
    }
  }, [report, scanId]);

  const isGenerating = Boolean(report && ACTIVE_STATUSES.has(report.status));
  const ready = report?.status === 'READY';
  const failed = report?.status === 'FAILED';
  const unavailable = scanStatus !== 'COMPLETED';
  const statusText = isGenerating
    ? `Report ${report?.status.toLowerCase()}.`
    : ready
      ? `PDF ready${report.page_count ? `, ${report.page_count} pages` : ''}.`
      : failed
        ? 'PDF generation failed.'
        : transportError || '';

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
      {ready ? (
        <Button
          variant="accent-cyan"
          size="sm"
          onClick={download}
          isLoading={isDownloading}
          disabled={isDownloading}
          leftIcon={<Download size={14} aria-hidden="true" />}
        >
          {isDownloading ? 'Downloading…' : 'Download PDF'}
        </Button>
      ) : failed ? (
        <Button
          variant="danger"
          size="sm"
          onClick={generate}
          isLoading={isRequesting}
          disabled={!report.retryable || isRequesting}
          leftIcon={<RefreshCw size={14} aria-hidden="true" />}
        >
          {report.retryable ? 'Retry PDF' : 'Report unavailable'}
        </Button>
      ) : (
        <Button
          variant="secondary"
          size="sm"
          onClick={generate}
          isLoading={isDiscovering || isRequesting || isGenerating}
          disabled={unavailable || isDiscovering || isRequesting || isGenerating}
          aria-busy={isGenerating || isRequesting}
          title={unavailable ? 'Complete the repository analysis before generating a report.' : undefined}
          leftIcon={<FileDown size={14} aria-hidden="true" />}
        >
          {isGenerating || isRequesting ? 'Generating PDF…' : isDiscovering ? 'Checking report…' : 'Generate PDF'}
        </Button>
      )}
      {(statusText || transportError) && (
        <span
          aria-live="polite"
          role={failed || transportError ? 'alert' : 'status'}
          style={{ maxWidth: '16rem', fontSize: '0.6875rem', color: failed || transportError ? 'var(--error-text)' : 'var(--text-muted)' }}
        >
          {transportError || statusText}
        </span>
      )}
    </div>
  );
}
