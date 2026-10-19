'use client';

import React, { useState } from 'react';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';

export interface PipelineStep {
  step: string;
  title: string;
  badge: string;
  desc: string;
  details: string[];
  deepDive: {
    overview: string;
    guarantees: string[];
    technicalDetails: string;
  };
}

export const PIPELINE_STEPS: PipelineStep[] = [
  {
    step: '01',
    title: 'AST Ingestion & Parsing',
    badge: 'Tree-sitter',
    desc: 'Clones repository into ephemeral sandbox. Generates full concrete AST across TypeScript, Python, Go, Rust, Java.',
    details: ['Concrete Syntax Tree', 'Symbol Mapping', 'Route Discovery'],
    deepDive: {
      overview:
        'Tree-sitter provides error-tolerant parsing for supported files, with explicit partial-coverage reporting. We extract full symbol hierarchies, class declarations, function signatures, and route handlers directly from the AST.',
      guarantees: [
        'Deterministic, reproducible symbol graph extraction',
        'AST-derived facts where supported',
        'Native support for TypeScript, JavaScript, Python, Go, Rust, and Java',
      ],
      technicalDetails:
        'AST Nodes are indexed with byte offsets and line/column coordinates, enabling pinpoint accuracy for downstream LLM prompt grounding.',
    },
  },
  {
    step: '02',
    title: 'Static Tool Triangulation',
    badge: 'Semgrep + CVEs',
    desc: 'Runs Semgrep AST pattern rules, Trivy container audits, and OSV dependency vulnerability matching simultaneously.',
    details: ['Semgrep Security Rules', 'Trivy Vuln DB', 'OSV Dependency Scan'],
    deepDive: {
      overview:
        'Combines deterministic static analyzers with vulnerability intelligence feeds. Only available scanner evidence can support a finding; missing coverage must be identified.',
      guarantees: [
        'Triangulation of pattern matching + dependency CVE databases',
        'Direct fingerprinting against known CWE security vulnerabilities',
        'Scanner and vulnerability-database availability is explicitly reported',
      ],
      technicalDetails:
        'Outputs normalized Finding records with exact source code spans, CWE identifiers, severity classifications, and fix suggestions.',
    },
  },
  {
    step: '03',
    title: 'Specialist Analysis and Verification',
    badge: 'Parallel LLMs',
    desc: 'Specialist workflows analyze bounded source evidence; independent verification checks candidates and may abstain.',
    details: ['Parallel Evaluation', 'Cross-Validation', 'Confidence Scoring'],
    deepDive: {
      overview:
        'Specialist workflows use bounded source-derived context; independent evidence checks constrain their conclusions.',
      guarantees: [
        'Evidence checks reduce unsupported claims, but cannot guarantee zero hallucinations',
        'Independent verification without model voting',
        'Verification against repo dependencies and system architecture boundaries',
      ],
      technicalDetails:
        'Model output must pass schema and evidence checks; unverifiable findings cannot be marked confirmed.',
    },
  },
  {
    step: '04',
    title: 'Verifiable Remediation & PR',
    badge: 'Automated Patches',
    desc: 'Proposes bounded patch diffs with deterministic checks and explicit human approval before authorized GitHub delivery.',
    details: ['Patch Diff Synthesis', 'Sandbox Test Pass', 'One-Click PR Delivery'],
    deepDive: {
      overview:
        'Transforms validated security findings into surgical, minimal unified git patch diffs. The patch is statically checked in a temporary worktree without executing untrusted repository tests or scripts.',
      guarantees: [
        'Deterministic checks reduce, but do not eliminate, patch risk',
        'Cryptographic audit trail and RBAC role gating for patch application',
        'Automated GitHub Pull Request creation and inline review comments',
      ],
      technicalDetails:
        'Operators review diff evidence and authorize any allowed delivery separately.',
    },
  },
];

export interface ArchitecturePipelineProps {
  onNavigate?: (mode: WorkspaceMode) => void;
  isStandalonePage?: boolean;
}

export function ArchitecturePipeline({
  onNavigate,
  isStandalonePage = false,
}: ArchitecturePipelineProps) {
  const [selectedStepIdx, setSelectedStepIdx] = useState<number>(0);
  const activeStep = PIPELINE_STEPS[selectedStepIdx];

  return (
    <div className={isStandalonePage ? 'page-view-enter' : 'mt-14 mb-8'}>
      {/* Standalone View Top Bar */}
      {isStandalonePage && onNavigate && (
        <div className="view-top-bar">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="back-to-home-btn"
              onClick={() => onNavigate('LANDING')}
              title="Return to Overview"
            >
              ← Back to Overview
            </button>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">4-Stage Pipeline Architecture</span>
              <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">Deep Dive</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              className="filter-btn text-xs"
              onClick={() => onNavigate('SCAN')}
            >
              🛡️ Security Scan Workspace →
            </button>
            <button
              type="button"
              className="filter-btn text-xs"
              onClick={() => onNavigate('CHANGE_ANALYSIS')}
            >
              🔍 PR Change Intelligence →
            </button>
          </div>
        </div>
      )}

      {/* Main Pipeline Card */}
      <div className="glass-card-glow">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-sm font-bold text-indigo-400 font-mono">PIPELINE ARCHITECTURE</span>
              <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">End-to-End Flow</span>
            </div>
            <h2 id="pipeline-section-title" className="text-xl md:text-2xl font-bold text-white tracking-tight">
              Deterministic Verification &amp; AI Synthesis Engine
            </h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            4-Stage Analysis Lifecycle
          </span>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed mb-6 max-w-3xl">
          RepoLens combines deterministic source analysis with independent evidence verification to reduce unsupported
          claims. Model judgments remain fallible and untrusted repository tests are never executed.
        </p>

        {/* 4 Pipeline Stages */}
        <div className="pipeline-container">
          {PIPELINE_STEPS.map((step, idx) => {
            const isSelected = selectedStepIdx === idx;
            return (
              <div
                key={idx}
                className={`pipeline-step cursor-pointer transition-all ${
                  isSelected ? 'border-indigo-500 bg-indigo-950/40 shadow-lg shadow-indigo-500/20' : ''
                }`}
                onClick={() => setSelectedStepIdx(idx)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    setSelectedStepIdx(idx);
                  }
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="pipeline-num text-indigo-400 font-mono font-bold">STAGE {step.step}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950/60 border border-indigo-800/60 text-indigo-300">
                    {step.badge}
                  </span>
                </div>

                <h3 className="pipeline-title text-sm font-bold text-white mb-1.5">
                  {step.title}
                </h3>

                <p className="pipeline-desc text-xs text-slate-400 mb-3 leading-relaxed">
                  {step.desc}
                </p>

                <div className="flex flex-wrap gap-1 pt-2 border-t border-white/5">
                  {step.details.map((detail, dIdx) => (
                    <span
                      key={dIdx}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900/80 border border-slate-800 text-slate-400"
                    >
                      {detail}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Deep Dive Drill-Down Inspector */}
        <div className="mt-8 p-6 rounded-xl bg-slate-950/70 border border-white/10">
          <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-indigo-400">STAGE {activeStep.step} DRILL-DOWN</span>
              <span className="text-sm font-bold text-white">{activeStep.title}</span>
            </div>
            <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">
              Technology: {activeStep.badge}
            </span>
          </div>

          <p className="text-xs text-slate-300 mb-4 leading-relaxed">
            {activeStep.deepDive.overview}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-white/5">
            <div>
              <h4 className="text-xs font-bold text-slate-200 mb-2 font-mono uppercase">Key Guarantees:</h4>
              <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
                {activeStep.deepDive.guarantees.map((g, gIdx) => (
                  <li key={gIdx}>{g}</li>
                ))}
              </ul>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-200 mb-2 font-mono uppercase">Engine Implementation:</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                {activeStep.deepDive.technicalDetails}
              </p>
            </div>
          </div>
        </div>

        {/* Standalone Bottom CTA Banner */}
        {isStandalonePage && onNavigate && (
          <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-between flex-wrap gap-4">
            <div>
              <h3 className="text-base font-bold text-white">Ready to test the engine on your repository?</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Run an AST-grounded multi-agent scan on any public GitHub repository in seconds.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="btn-hero-primary text-sm"
                onClick={() => onNavigate('SCAN')}
              >
                <span>🛡️ Launch Security Scan</span>
              </button>
              <button
                type="button"
                className="btn-hero-secondary text-sm"
                onClick={() => onNavigate('CHANGE_ANALYSIS')}
              >
                <span>🔍 Analyze PR Impact</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

