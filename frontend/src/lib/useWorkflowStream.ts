'use client';

import { useEffect, useRef, useState } from 'react';
import { WorkflowEvent, WorkflowEventType } from '@/types/domain';

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
  enabled: boolean = true
): UseWorkflowStreamResult {
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [status, setStatus] = useState<StreamStatus>('idle');
  const [error, setError] = useState<string | null>(null);
  const lastEventIdRef = useRef<number>(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const clearEvents = () => {
    setEvents([]);
    lastEventIdRef.current = 0;
  };

  useEffect(() => {
    if (!scanId || !enabled) {
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

    function connect() {
      if (!isMounted) return;

      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      setStatus(lastEventIdRef.current > 0 ? 'reconnecting' : 'connecting');
      setError(null);

      const streamUrl = `${API_BASE_URL}/api/v1/scans/${scanId}/events?after_id=${lastEventIdRef.current}`;
      const es = new EventSource(streamUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        if (!isMounted) return;
        setStatus('connected');
        retryCount = 0;
      };

      es.onmessage = (messageEvent) => {
        if (!isMounted) return;
        try {
          const parsed = JSON.parse(messageEvent.data) as WorkflowEvent;
          if (parsed && typeof parsed.id === 'number') {
            if (parsed.id > lastEventIdRef.current) {
              lastEventIdRef.current = parsed.id;
            }
            setEvents((prev) => {
              // Deduplicate by ID
              if (prev.some((e) => e.id === parsed.id)) {
                return prev;
              }
              return [...prev, parsed].sort((a, b) => a.id - b.id);
            });

            // If terminal event received, mark completed
            if (parsed.event_type === 'SCAN_COMPLETED' || parsed.event_type === 'SCAN_FAILED') {
              setStatus('completed');
            }
          }
        } catch {
          // Ignore heartbeats or non-JSON comments
        }
      };

      es.onerror = () => {
        if (!isMounted) return;
        es.close();
        eventSourceRef.current = null;

        if (status === 'completed') {
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
      }
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [scanId, enabled]);

  return {
    events,
    status,
    lastEventId: lastEventIdRef.current,
    error,
    clearEvents,
  };
}
