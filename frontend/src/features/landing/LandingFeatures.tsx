'use client';

import React from 'react';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';

export interface FeatureItem {
  icon: string;
  title: string;
  badge: string;
  description: string;
  tags: string[];
  targetMode: WorkspaceMode;
  actionText: string;
}

export const FEATURES_DATA: FeatureItem[] = [
  {
    icon: '🌳',
    title: 'Tree-sitter Concrete AST Parsing',
    badge: 'Deterministic',
    description:
      'Parses full concrete syntax trees across TypeScript, Python, Go, Rust, and Java. Maps exact symbols, class hierarchies, API routes, and call chains with sub-second performance.',
    tags: ['AST Parser', 'Symbol Graph', 'Cross-Language'],
    targetMode: 'SCAN',
    actionText: 'Launch AST Scan →',
  },
  {
    icon: '🤖',
    title: 'Multi-Agent Specialist Consensus',
    badge: 'Consensus Engine',
    description:
      'Parallel specialist LLM agents (Security Auditor, Architecture Sentinel, Blast Radius Assessor, and Remediation Engineer) cross-validate each finding against verified evidence.',
    tags: ['Parallel LLMs', 'Cross-Verification', 'Zero Hallucinations'],
    targetMode: 'ARCHITECTURE',
    actionText: 'View Consensus Engine →',
  },
  {
    icon: '💥',
    title: 'PR Blast Radius & Contract Deltas',
    badge: 'Change Intelligence',
    description:
      'Computes semantic diffs between Git commit SHAs, uncovering breaking API schema shifts, altered route signatures, and downstream blast impact zones before you merge.',
    tags: ['Semantic Diff', 'Schema Drift', 'Impact Trees'],
    targetMode: 'CHANGE_ANALYSIS',
    actionText: 'Analyze PR Deltas →',
  },
  {
    icon: '🛠️',
    title: '6-Step Verifiable Remediation',
    badge: 'Automated Patches',
    description:
      'Rigorous 6-step lifecycle: Context discovery, hypothesis synthesis, unified patch generation, sandbox compilation, automated test verification, and operator sign-off.',
    tags: ['Patch Diff', 'Sandbox Verification', 'Human-in-the-Loop'],
    targetMode: 'SCAN',
    actionText: 'Generate Verified Patches →',
  },
  {
    icon: '🛡️',
    title: 'Static Toolchain Synergy',
    badge: 'Static Triangulation',
    description:
      'Combines Semgrep AST pattern rules, Trivy CVE container vulnerability scans, and OSV-Scanner dependency feeds into a unified, deduplicated risk matrix.',
    tags: ['Semgrep', 'Trivy', 'OSV-Scanner'],
    targetMode: 'ARCHITECTURE',
    actionText: 'Inspect Static Pipeline →',
  },
  {
    icon: '🚀',
    title: 'GitHub Operator PR Integration',
    badge: 'CI/CD Delivery',
    description:
      'Publishes line-level automated code reviews directly to GitHub Pull Requests and creates ready-to-merge remediation branches with RBAC audit logs.',
    tags: ['PR Comments', 'Branch Creation', 'RBAC Security'],
    targetMode: 'CHANGE_ANALYSIS',
    actionText: 'Review PR Delivery →',
  },
];

export interface LandingFeaturesProps {
  onNavigate?: (mode: WorkspaceMode) => void;
}

export function LandingFeatures({ onNavigate }: LandingFeaturesProps) {
  return (
    <section className="mt-12" aria-labelledby="features-section-title">
      <div className="text-center max-w-2xl mx-auto mb-8">
        <div className="hero-pill mb-3">
          <span className="hero-pill-dot" aria-hidden="true" />
          <span>Next-Gen Architecture</span>
        </div>
        <h2 id="features-section-title" className="text-2xl md:text-3xl font-extrabold text-white tracking-tight mb-2">
          Engineered for Enterprise Security &amp; Speed
        </h2>
        <p className="text-sm text-slate-400">
          Every finding and patch is grounded in verifiable deterministic evidence — combining static AST parsers,
          CVE databases, and multi-agent AI verification.
        </p>
      </div>

      <div className="feature-grid">
        {FEATURES_DATA.map((feature, idx) => (
          <div key={idx} className="feature-glass-card">
            <div className="flex items-center justify-between">
              <div className="feature-icon-box" aria-hidden="true">
                {feature.icon}
              </div>
              <span className="badge-tag text-[11px] text-cyan-300 border-cyan-500/30 bg-cyan-950/40">
                {feature.badge}
              </span>
            </div>

            <h3 className="feature-title text-lg font-bold text-white mt-1">
              {feature.title}
            </h3>

            <p className="feature-desc text-xs text-slate-400 leading-relaxed">
              {feature.description}
            </p>

            <div className="flex flex-wrap gap-1.5 pt-2 border-t border-white/5">
              {feature.tags.map((tag, tIdx) => (
                <span
                  key={tIdx}
                  className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900/60 border border-slate-800 text-slate-400"
                >
                  {tag}
                </span>
              ))}
            </div>

            {onNavigate && (
              <button
                type="button"
                className="feature-action-btn"
                onClick={() => onNavigate(feature.targetMode)}
                aria-label={`${feature.actionText} for ${feature.title}`}
              >
                <span>{feature.actionText}</span>
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Architecture Deep-Dive Callout Banner */}
      {onNavigate && (
        <div className="mt-8 p-6 rounded-2xl bg-gradient-to-r from-indigo-950/40 via-purple-950/30 to-slate-900/50 border border-indigo-500/30 flex flex-col md:flex-row items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-bold text-indigo-400 font-mono">4-STAGE VERIFICATION PIPELINE</span>
              <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30">Deep Dive</span>
            </div>
            <h3 className="text-lg font-bold text-white">
              Want to see how Tree-sitter &amp; Multi-Agent Consensus eliminate hallucinations?
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Explore the deterministic AST parsing, static toolchain triangulation, and 6-step patch verification sandbox.
            </p>
          </div>
          <button
            type="button"
            className="btn-hero-secondary text-xs shrink-0 whitespace-nowrap"
            onClick={() => onNavigate('ARCHITECTURE')}
          >
            Explore Engine Architecture →
          </button>
        </div>
      )}
    </section>
  );
}

