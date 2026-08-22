'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { StreamStatus, useWorkflowStream } from '@/lib/useWorkflowStream';
import { WorkflowEvent, WorkflowEventType } from '@/types/domain';

interface WorkflowTimelineProps {
  scanId: string;
  autoScroll?: boolean;
}

type FilterCategory = 'ALL' | 'STAGES' | 'FINDINGS' | 'PATCHES' | 'HUMAN_AUDIT' | 'DELIVERIES';

function getEventBadgeStyle(type: WorkflowEventType): {
  bg: string;
  text: string;
  border: string;
  icon: string;
} {
  switch (type) {
    case 'SCAN_CREATED':
    case 'SCAN_STARTED':
      return { bg: 'bg-blue-950/40', text: 'text-blue-400', border: 'border-blue-800/60', icon: '🚀' };
    case 'STAGE_STARTED':
    case 'STAGE_COMPLETED':
      return { bg: 'bg-cyan-950/40', text: 'text-cyan-400', border: 'border-cyan-800/60', icon: '⚙️' };
    case 'TOOL_STARTED':
    case 'TOOL_COMPLETED':
      return { bg: 'bg-teal-950/40', text: 'text-teal-400', border: 'border-teal-800/60', icon: '🔍' };
    case 'FINDING_CONFIRMED':
      return { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-800/60', icon: '⚠️' };
    case 'PATCH_GENERATED':
    case 'PATCH_VERIFIED':
      return { bg: 'bg-emerald-950/40', text: 'text-emerald-400', border: 'border-emerald-800/60', icon: '🛡️' };
    case 'PATCH_NEEDS_REVIEW':
      return { bg: 'bg-yellow-950/40', text: 'text-yellow-400', border: 'border-yellow-800/60', icon: '🧐' };
    case 'PATCH_REJECTED':
    case 'SCAN_FAILED':
    case 'STAGE_FAILED':
    case 'TOOL_FAILED':
    case 'TOOL_UNAVAILABLE':
    case 'DELIVERY_FAILED':
    case 'WORKFLOW_ERROR':
      return { bg: 'bg-rose-950/40', text: 'text-rose-400', border: 'border-rose-800/60', icon: '❌' };
    case 'HUMAN_APPROVED':
    case 'PATCH_APPROVED':
      return { bg: 'bg-purple-950/40', text: 'text-purple-300', border: 'border-purple-800/60', icon: '👤✅' };
    case 'HUMAN_REJECTED':
      return { bg: 'bg-pink-950/40', text: 'text-pink-300', border: 'border-pink-800/60', icon: '👤❌' };
    case 'HUMAN_REVISION_REQUESTED':
    case 'PATCH_REVISION_CREATED':
      return { bg: 'bg-indigo-950/40', text: 'text-indigo-300', border: 'border-indigo-800/60', icon: '🔄' };
    case 'DELIVERY_REQUESTED':
      return { bg: 'bg-indigo-950/40', text: 'text-indigo-400', border: 'border-indigo-800/60', icon: '📦' };
    case 'DELIVERY_VALIDATED':
      return { bg: 'bg-sky-950/40', text: 'text-sky-400', border: 'border-sky-800/60', icon: '🔍✅' };
    case 'DELIVERY_BLOCKED':
      return { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-800/60', icon: '⚠️🚫' };
    case 'DELIVERY_COMMIT_CREATED':
      return { bg: 'bg-blue-950/40', text: 'text-blue-400', border: 'border-blue-800/60', icon: '💾' };
    case 'DELIVERY_BRANCH_CREATED':
      return { bg: 'bg-teal-950/40', text: 'text-teal-400', border: 'border-teal-800/60', icon: '🌿' };
    case 'DELIVERY_PR_CREATED':
      return { bg: 'bg-emerald-950/60', text: 'text-emerald-300 font-bold', border: 'border-emerald-600', icon: '🚀🎉' };
    case 'SCAN_COMPLETED':
      return { bg: 'bg-emerald-950/40', text: 'text-emerald-300', border: 'border-emerald-700/60', icon: '🎉' };
    default:
      return { bg: 'bg-slate-900/40', text: 'text-slate-400', border: 'border-slate-800', icon: '📋' };
  }
}

function matchesFilter(event: WorkflowEvent, filter: FilterCategory): boolean {
  if (filter === 'ALL') return true;
  if (filter === 'STAGES') {
    return (
      event.event_type.startsWith('STAGE_') ||
      event.event_type.startsWith('SCAN_') ||
      event.event_type.startsWith('TOOL_')
    );
  }
  if (filter === 'FINDINGS') {
    return event.event_type === 'FINDING_CONFIRMED';
  }
  if (filter === 'PATCHES') {
    return event.event_type.startsWith('PATCH_');
  }
  if (filter === 'HUMAN_AUDIT') {
    return (
      event.event_type.startsWith('HUMAN_') ||
      event.event_type === 'PATCH_APPROVED' ||
      event.event_type === 'PATCH_REJECTED' ||
      event.event_type === 'PATCH_REVISION_CREATED'
    );
  }
  if (filter === 'DELIVERIES') {
    return event.event_type.startsWith('DELIVERY_');
  }
  return true;
}

export function WorkflowTimeline({ scanId }: WorkflowTimelineProps) {
  const { events, status, error } = useWorkflowStream(scanId, true);
  const [filter, setFilter] = useState<FilterCategory>('ALL');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [expandedEvents, setExpandedEvents] = useState<Record<number, boolean>>({});
  const bottomRef = useRef<HTMLDivElement | null>(null);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => matchesFilter(e, filter));
  }, [events, filter]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [filteredEvents, autoScroll]);

  const toggleExpand = (id: number) => {
    setExpandedEvents((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getStatusPill = (st: StreamStatus) => {
    switch (st) {
      case 'connected':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Live Stream
          </span>
        );
      case 'connecting':
      case 'reconnecting':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/60 text-amber-400 border border-amber-800/80">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-spin" />
            {st === 'connecting' ? 'Connecting...' : 'Reconnecting...'}
          </span>
        );
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-900/60 text-slate-300 border border-slate-700/80">
            <span className="w-2 h-2 rounded-full bg-slate-400" />
            Complete
          </span>
        );
      case 'error':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/60 text-rose-400 border border-rose-800/80">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            Disconnected
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col h-[520px]">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <span className="text-lg">⚡</span> Workflow Stream & Audit Trail
          </h3>
          {getStatusPill(status)}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            Auto-scroll
          </label>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 py-3 overflow-x-auto text-xs border-b border-slate-800/60">
        {(['ALL', 'STAGES', 'FINDINGS', 'PATCHES', 'HUMAN_AUDIT', 'DELIVERIES'] as FilterCategory[]).map((cat) => {
          const isActive = filter === cat;
          return (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {cat === 'ALL'
                ? 'All Events'
                : cat === 'STAGES'
                ? 'Stages & Scanners'
                : cat === 'FINDINGS'
                ? 'Findings'
                : cat === 'PATCHES'
                ? 'Patches'
                : cat === 'HUMAN_AUDIT'
                ? 'Human Audit'
                : '🚀 GitHub Deliveries'}
            </button>
          );
        })}
      </div>

      {/* Events Stream Feed */}
      <div className="flex-1 overflow-y-auto py-3 space-y-2.5 pr-1 font-mono text-xs">
        {error && (
          <div className="p-3 bg-rose-950/50 border border-rose-800 text-rose-300 rounded-lg text-xs">
            {error}
          </div>
        )}

        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 font-sans text-sm">
            <span className="text-2xl mb-1">⏳</span>
            <span>No workflow events matching current filter.</span>
          </div>
        ) : (
          filteredEvents.map((evt) => {
            const badge = getEventBadgeStyle(evt.event_type);
            const isExpanded = !!expandedEvents[evt.id];
            const hasPayload = evt.metadata_payload && Object.keys(evt.metadata_payload).length > 0;
            const timeStr = new Date(evt.created_at).toLocaleTimeString();

            return (
              <div
                key={evt.id}
                className={`p-3 rounded-lg border transition-all ${badge.bg} ${badge.border} text-slate-200`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm">{badge.icon}</span>
                    <span className={`font-semibold uppercase tracking-wider text-[11px] ${badge.text}`}>
                      {evt.event_type}
                    </span>
                    {evt.stage && (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                        stage:{evt.stage}
                      </span>
                    )}
                    {evt.tool_name && (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-teal-300 text-[10px]">
                        tool:{evt.tool_name}
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-500 shrink-0">{timeStr}</span>
                </div>

                {evt.message && (
                  <p className="mt-1 text-slate-300 font-sans text-xs">{evt.message}</p>
                )}

                {hasPayload && (
                  <div className="mt-2">
                    <button
                      onClick={() => toggleExpand(evt.id)}
                      className="text-[10px] text-slate-400 hover:text-cyan-400 underline cursor-pointer"
                    >
                      {isExpanded ? 'Hide Details' : 'View Payload Details'}
                    </button>
                    {isExpanded && (
                      <pre className="mt-1.5 p-2 bg-slate-950/80 border border-slate-800 rounded text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(evt.metadata_payload, null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
