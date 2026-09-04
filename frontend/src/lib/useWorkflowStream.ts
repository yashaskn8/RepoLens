'use client';

import { useEffect, useRef, useState } from 'react';
import { WORKFLOW_EVENT_TYPES, WorkflowEvent, WorkflowEventType } from '@/types/domain';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

export type StreamStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'completed' | 'error';

export interface UseWorkflowStreamResult {
  events: WorkflowEvent[];
  status: StreamStatus;
  lastEventId: number;
  error: string | null;
  clearEvents: () => void;
}

export function useWorkflowStream(
  scanId: string | null | undefined,
  enabled: boolean = true,
  changeAnalysisId: string | null | undefined = null
): UseWorkflowStreamResult {
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [status, setStatus] = useState<StreamStatus>('idle');
  const [error, setError] = useState<string | null>(null);

  const lastEventIdRef = useRef<number>(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const terminalReceivedRef = useRef<boolean>(false);

  const targetId = changeAnalysisId || scanId;

  const clearEvents = () => {
    setEvents([]);
    lastEventIdRef.current = 0;
    terminalReceivedRef.current = false;
  };

  useEffect(() => {
    // Reset state for new scan or disabled stream
    terminalReceivedRef.current = false;
    lastEventIdRef.current = 0;
    setEvents([]);

    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }

    if (!targetId || !enabled) {
      setStatus('idle');
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    let isMounted = true;
    let retryCount = 0;
    const maxRetries = 10;

    function handleEvent(messageEvent: MessageEvent) {
      if (!isMounted || terminalReceivedRef.current) return;

      try {
        const parsed = JSON.parse(messageEvent.data) as WorkflowEvent;
        if (parsed && typeof parsed.id === 'number') {
          if (parsed.id > lastEventIdRef.current) {
            lastEventIdRef.current = parsed.id;
          }

          setEvents((prev) => {
            if (prev.some((e) => e.id === parsed.id)) {
              return prev;
            }
            return [...prev, parsed].sort((a, b) => a.id - b.id);
          });

          // Check if terminal event received
          if (
            parsed.event_type === 'SCAN_COMPLETED' ||
            parsed.event_type === 'SCAN_FAILED' ||
            parsed.event_type === 'CHANGE_ANALYSIS_COMPLETED' ||
            parsed.event_type === 'CHANGE_ANALYSIS_FAILED'
          ) {
            terminalReceivedRef.current = true;
            setStatus('completed');

            // Clear any pending retries
            if (retryTimeoutRef.current) {
              clearTimeout(retryTimeoutRef.current);
              retryTimeoutRef.current = null;
            }

            // Close the EventSource immediately to avoid unnecessary reconnect loops
            if (eventSourceRef.current) {
              eventSourceRef.current.close();
              eventSourceRef.current = null;
            }
          }
        }
      } catch {
        // Ignore non-JSON comments or keepalive messages
      }
    }

    function connect() {
      if (!isMounted || terminalReceivedRef.current) return;

      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }

      setStatus(lastEventIdRef.current > 0 ? 'reconnecting' : 'connecting');
      setError(null);

      const streamUrl = changeAnalysisId
        ? `${API_BASE_URL}/api/v1/change-analyses/${changeAnalysisId}/events?after_id=${lastEventIdRef.current}`
        : `${API_BASE_URL}/api/v1/scans/${scanId}/events?after_id=${lastEventIdRef.current}`;
      const es = new EventSource(streamUrl, { withCredentials: true });
      eventSourceRef.current = es;


      es.onopen = () => {
        if (!isMounted) return;
        setStatus('connected');
        retryCount = 0;
      };

      // Register shared event handler for generic messages
      es.onmessage = handleEvent;

      // Register shared event handler for all canonical named SSE events
      WORKFLOW_EVENT_TYPES.forEach((eventType) => {
        es.addEventListener(eventType, handleEvent as EventListener);
      });

      es.onerror = () => {
        if (!isMounted) return;

        es.close();
        if (eventSourceRef.current === es) {
          eventSourceRef.current = null;
        }

        // If a terminal event was already received, do not reconnect
        if (terminalReceivedRef.current) {
          return;
        }

        if (retryCount < maxRetries) {
          retryCount += 1;
          setStatus('reconnecting');
          const delay = Math.min(1000 * 2 ** retryCount, 10000);
          retryTimeoutRef.current = setTimeout(connect, delay);
        } else {
          setStatus('error');
          setError('Live connection lost after multiple retry attempts.');
        }
      };
    }

    connect();

    return () => {
      isMounted = false;
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
        retryTimeoutRef.current = null;
      }
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [scanId, changeAnalysisId, targetId, enabled]);

  return {
    events,
    status,
    lastEventId: lastEventIdRef.current,
    error,
    clearEvents,
  };
}
