'use client';

import React from 'react';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { PresetPicker } from './PresetPicker';
import { InteractiveShowcase } from './InteractiveShowcase';

export interface LandingHeroProps {
  onNavigate: (mode: WorkspaceMode) => void;
  onSelectPreset: (url: string, branch: string) => void;
}

export function LandingHero({ onNavigate, onSelectPreset }: LandingHeroProps) {
  return (
    <section className="hero" aria-labelledby="hero-main-title">
      {/* Top Floating Radar Pill */}
      <div className="hero-pill mb-6">
        <span className="hero-pill-dot" aria-hidden="true" />
        <span className="hero-pill-text">Deterministic Multi-Agent Engine v1.0</span>
        <span className="hero-pill-badge">Zero Hallucinations</span>
      </div>

      {/* Main Gradient Headline */}
      <h1 id="hero-main-title" className="hero-title">
        Deterministic Code Intelligence <br />
        <span className="hero-gradient-text">&amp; Verifiable Security Remediation</span>
      </h1>

      {/* Descriptive Lead */}
      <p className="hero-subtitle">
        Analyze public GitHub repositories with Tree-sitter AST concrete parsing, Semgrep, Trivy, OSV-Scanner,
        and parallel specialist agents grounded in mathematical source evidence — zero hallucinations, verifiable patch diffs.
      </p>

      {/* Capability / Trust Metrics Strip */}
      <div className="capability-strip" role="list" aria-label="Key platform capabilities">
        <div className="capability-chip" role="listitem">
          <span className="capability-icon" aria-hidden="true">🛡️</span>
          <span>100% Deterministic Evidence</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span className="capability-icon" aria-hidden="true">🌳</span>
          <span>Tree-sitter AST Concrete Parsing</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span className="capability-icon" aria-hidden="true">💥</span>
          <span>PR Blast Radius &amp; Deltas</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span className="capability-icon" aria-hidden="true">⚡</span>
          <span>6-Step Sandbox Remediation</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span className="capability-icon" aria-hidden="true">🚀</span>
          <span>GitHub CI/CD Publishing</span>
        </div>
      </div>

      {/* Primary Action Buttons */}
      <div className="hero-actions" role="group" aria-label="Primary platform workflows">
        <button
          type="button"
          className="btn-hero-primary"
          onClick={() => onNavigate('SCAN')}
          aria-label="Ready to Fix: Launch Security and AST Scan"
        >
          <span className="btn-icon" aria-hidden="true">⚡</span>
          <span className="btn-text">Ready to Fix &amp; Scan</span>
          <span className="btn-badge">Instant AST</span>
        </button>

        <button
          type="button"
          className="btn-hero-secondary"
          onClick={() => onNavigate('CHANGE_ANALYSIS')}
          aria-label="Analyze Pull Request Blast Radius & Deltas"
        >
          <span className="btn-icon" aria-hidden="true">🔍</span>
          <span className="btn-text">PR Blast Radius &amp; Deltas</span>
        </button>

        <button
          type="button"
          className="btn-hero-ghost"
          onClick={() => onNavigate('ARCHITECTURE')}
          aria-label="Explore 4-Stage Engine Architecture"
        >
          <span className="btn-icon" aria-hidden="true">🏗️</span>
          <span className="btn-text">Engine Architecture</span>
        </button>
      </div>

      {/* Quick Repository Presets (1-Click Launch) */}
      <div className="flex justify-center mt-6 mb-10">
        <PresetPicker onSelect={onSelectPreset} />
      </div>

      {/* Live Interactive Engine Preview Widget */}
      <div className="w-full mt-2 mb-8">
        <InteractiveShowcase onNavigate={onNavigate} />
      </div>
    </section>
  );
}
