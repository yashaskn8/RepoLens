'use client';

import React from 'react';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';
import { PresetPicker } from './PresetPicker';

export interface LandingHeroProps {
  onNavigate: (mode: WorkspaceMode) => void;
  onSelectPreset: (url: string, branch: string) => void;
}

export function LandingHero({ onNavigate, onSelectPreset }: LandingHeroProps) {
  return (
    <section className="hero" aria-labelledby="hero-main-title">
      {/* Radar Tag */}
      <div className="hero-pill">
        <span className="hero-pill-dot" aria-hidden="true" />
        <span>Multi-Agent Static &amp; AST Analysis Platform</span>
      </div>

      {/* Main Gradient Headline */}
      <h1 id="hero-main-title">
        Deterministic Code Intelligence <br />
        <span className="hero-gradient-text">&amp; Verifiable Security Remediation</span>
      </h1>

      {/* Descriptive Lead */}
      <p>
        Analyze public GitHub repositories with Tree-sitter AST structural parsing, Semgrep, Trivy, OSV-Scanner,
        and parallel specialist agents grounded in mathematical source evidence — zero hallucinations, verifiable patch diffs.
      </p>

      {/* Capability / Trust Metrics Strip */}
      <div className="capability-strip" role="list" aria-label="Key platform capabilities">
        <div className="capability-chip" role="listitem">
          <span aria-hidden="true">🛡️</span>
          <span>100% Deterministic Evidence</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span aria-hidden="true">🌳</span>
          <span>Tree-sitter AST Parsing</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span aria-hidden="true">💥</span>
          <span>PR Blast Radius &amp; Deltas</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span aria-hidden="true">⚡</span>
          <span>6-Step Verified Remediation</span>
        </div>
        <div className="capability-chip" role="listitem">
          <span aria-hidden="true">🚀</span>
          <span>GitHub CI/CD Publishing</span>
        </div>
      </div>

      {/* Primary Action Buttons (Multi-Page Entry Points) */}
      <div className="hero-actions" role="group" aria-label="Primary platform workflows">
        <button
          type="button"
          className="btn-hero-primary"
          onClick={() => onNavigate('SCAN')}
          aria-label="Ready to Fix: Launch Security and AST Scan"
        >
          <span aria-hidden="true">⚡</span>
          <span>Ready to Fix &amp; Scan</span>
        </button>

        <button
          type="button"
          className="btn-hero-secondary"
          onClick={() => onNavigate('CHANGE_ANALYSIS')}
          aria-label="Analyze Pull Request Blast Radius & Deltas"
        >
          <span aria-hidden="true">🔍</span>
          <span>PR Blast Radius &amp; Deltas</span>
        </button>

        <button
          type="button"
          className="btn-hero-ghost"
          onClick={() => onNavigate('ARCHITECTURE')}
          aria-label="Explore 4-Stage Engine Architecture"
        >
          <span aria-hidden="true">🏗️</span>
          <span>Engine Architecture</span>
        </button>
      </div>

      {/* Quick Repository Presets (1-Click Launch) */}
      <div className="flex justify-center mt-2">
        <PresetPicker onSelect={onSelectPreset} />
      </div>
    </section>
  );
}

