'use client';

import React, { useState } from 'react';
import { WorkspaceMode } from '@/components/layout/WorkspaceNav';

export interface InteractiveShowcaseProps {
  onNavigate?: (mode: WorkspaceMode) => void;
}

type ShowcaseTab = 'ast' | 'agents' | 'diff';

export function InteractiveShowcase({ onNavigate }: InteractiveShowcaseProps) {
  const [activeTab, setActiveTab] = useState<ShowcaseTab>('ast');
  const [selectedAstNode, setSelectedAstNode] = useState<string>('query_execution');

  return (
    <div className="interactive-showcase-container">
      {/* Top Window Bar */}
      <div className="showcase-window-header">
        <div className="flex items-center gap-2">
          <div className="window-dot bg-rose-500/80" />
          <div className="window-dot bg-amber-500/80" />
          <div className="window-dot bg-emerald-500/80" />
          <span className="text-xs text-slate-400 font-mono ml-2">repolens-core-engine // live-runtime-preview</span>
        </div>

        {/* View Switcher Tabs */}
        <div className="showcase-tabs" role="tablist" aria-label="Engine showcase modes">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'ast'}
            className={`showcase-tab ${activeTab === 'ast' ? 'showcase-tab-active' : ''}`}
            onClick={() => setActiveTab('ast')}
          >
            <span aria-hidden="true">🌳</span> Concrete AST Parser
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'agents'}
            className={`showcase-tab ${activeTab === 'agents' ? 'showcase-tab-active' : ''}`}
            onClick={() => setActiveTab('agents')}
          >
            <span aria-hidden="true">🤖</span> Specialist Consensus
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'diff'}
            className={`showcase-tab ${activeTab === 'diff' ? 'showcase-tab-active' : ''}`}
            onClick={() => setActiveTab('diff')}
          >
            <span aria-hidden="true">⚡</span> 6-Step Verified Diff
          </button>
        </div>

        <div className="flex items-center gap-2">
          <span className="badge-tag text-[10px] text-emerald-400 border-emerald-500/30 bg-emerald-950/40">
            ● Live Engine Simulation
          </span>
        </div>
      </div>

      {/* Showcase Content Body */}
      <div className="showcase-window-body">
        {/* Tab 1: AST Concrete Parsing */}
        {activeTab === 'ast' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left: Code with Interactive AST Token Highlighting */}
            <div className="lg:col-span-7 bg-slate-950/70 p-4 rounded-xl border border-white/5 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/5 text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <span aria-hidden="true">📄</span> app/api/routes/analytics.py
                </span>
                <span className="text-[10px] text-slate-500">Tree-sitter Python Grammars</span>
              </div>

              <div className="space-y-1.5 text-slate-300 leading-relaxed overflow-x-auto">
                <div className="text-slate-500">1  @router.get(&quot;/query&quot;, response_model=QueryResponse)</div>
                <div className="text-slate-500">2  async def execute_dynamic_query(</div>
                <div className="text-slate-500">3      request: QueryRequest,</div>
                <div className="text-slate-500">4      current_user: User = Depends(get_current_user),</div>
                <div className="text-slate-500">5      db: AsyncSession = Depends(get_db)</div>
                <div className="text-slate-500">6  ):</div>
                
                {/* Interactive AST Node 1: Input Extraction */}
                <div
                  className={`cursor-pointer px-2 py-1 rounded transition-all ${
                    selectedAstNode === 'user_input'
                      ? 'bg-indigo-950/80 border border-indigo-500/50 text-indigo-200'
                      : 'hover:bg-slate-900 text-slate-300'
                  }`}
                  onClick={() => setSelectedAstNode('user_input')}
                >
                  <span className="text-slate-500 select-none mr-2">7 </span>
                  <span className="text-purple-400">raw_filter</span> = request.params.get(<span className="text-amber-300">&quot;tenant_id&quot;</span>)
                  <span className="text-[10px] text-indigo-400 font-sans ml-2">← [AST: VariableDeclaration]</span>
                </div>

                {/* Interactive AST Node 2: Unsafe Query Construction */}
                <div
                  className={`cursor-pointer px-2 py-1 rounded transition-all ${
                    selectedAstNode === 'query_execution'
                      ? 'bg-rose-950/80 border border-rose-500/60 text-rose-200 shadow-[0_0_12px_rgba(244,63,94,0.2)]'
                      : 'hover:bg-slate-900 text-rose-300'
                  }`}
                  onClick={() => setSelectedAstNode('query_execution')}
                >
                  <span className="text-slate-500 select-none mr-2">8 </span>
                  <span className="text-rose-400">sql</span> = f<span className="text-rose-300">&quot;SELECT * FROM metrics WHERE tenant_id = &#39;&#123;raw_filter&#125;&#39;&quot;</span>
                  <span className="text-[10px] text-rose-400 font-sans ml-2 font-bold">⚠️ [AST: FormattedStringExpr // CWE-89]</span>
                </div>

                {/* Interactive AST Node 3: Database Call */}
                <div
                  className={`cursor-pointer px-2 py-1 rounded transition-all ${
                    selectedAstNode === 'db_call'
                      ? 'bg-cyan-950/80 border border-cyan-500/50 text-cyan-200'
                      : 'hover:bg-slate-900 text-slate-300'
                  }`}
                  onClick={() => setSelectedAstNode('db_call')}
                >
                  <span className="text-slate-500 select-none mr-2">9 </span>
                  <span className="text-blue-400">result</span> = await db.execute(text(sql))
                  <span className="text-[10px] text-cyan-400 font-sans ml-2">← [AST: AwaitExpression // CallExpr]</span>
                </div>

                <div className="text-slate-500">10     return QueryResponse(rows=result.fetchall())</div>
              </div>
            </div>

            {/* Right: Concrete AST Inspector Panel */}
            <div className="lg:col-span-5 flex flex-col justify-between bg-slate-900/50 p-4 rounded-xl border border-white/5">
              <div>
                <div className="flex items-center justify-between mb-3 pb-2 border-b border-white/5">
                  <span className="text-xs font-bold text-slate-200 font-display">AST Node Inspector</span>
                  <span className="badge-tag text-[10px] text-cyan-300 border-cyan-500/30 font-mono">
                    Deterministic Byte Coordinates
                  </span>
                </div>

                {selectedAstNode === 'query_execution' && (
                  <div className="space-y-3">
                    <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/30">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-bold text-rose-300">CWE-89: SQL Injection Vulnerability</span>
                      </div>
                      <p className="text-[11px] text-slate-300 leading-relaxed">
                        Unsanitized interpolation of user parameter <code className="text-rose-300">raw_filter</code> directly inside raw SQL formatting construct.
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">AST NODE TYPE</div>
                        <div className="text-slate-200 font-bold">FormattedStringExpr</div>
                      </div>
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">COORDINATES</div>
                        <div className="text-slate-200 font-bold">Line 8:1 - 8:74</div>
                      </div>
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">TOOLCHAIN EVIDENCE</div>
                        <div className="text-cyan-300 font-bold">Semgrep + Tree-sitter</div>
                      </div>
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">HALLUCINATION RISK</div>
                        <div className="text-emerald-400 font-bold">0.00% (Grounded)</div>
                      </div>
                    </div>
                  </div>
                )}

                {selectedAstNode === 'user_input' && (
                  <div className="space-y-3">
                    <div className="p-2.5 rounded-lg bg-indigo-950/40 border border-indigo-500/30">
                      <div className="text-xs font-bold text-indigo-300 mb-1">Taint Source: VariableDeclaration</div>
                      <p className="text-[11px] text-slate-300">
                        Extracted HTTP request parameter with unconstrained input length and character encoding.
                      </p>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">SYMBOL</div>
                        <div className="text-slate-200 font-bold">raw_filter</div>
                      </div>
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">TAINT FLOW</div>
                        <div className="text-amber-400 font-bold">Direct to SQL Sink</div>
                      </div>
                    </div>
                  </div>
                )}

                {selectedAstNode === 'db_call' && (
                  <div className="space-y-3">
                    <div className="p-2.5 rounded-lg bg-cyan-950/40 border border-cyan-500/30">
                      <div className="text-xs font-bold text-cyan-300 mb-1">Sink Node: AsyncDatabaseExecution</div>
                      <p className="text-[11px] text-slate-300">
                        Executes raw SQL query without parameter binding or schema validation.
                      </p>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">DISPATCH METHOD</div>
                        <div className="text-slate-200 font-bold">db.execute()</div>
                      </div>
                      <div className="p-2 rounded bg-slate-950/60 border border-white/5">
                        <div className="text-slate-500 text-[10px]">ASYNC SAFE</div>
                        <div className="text-emerald-400 font-bold">Yes (Non-blocking)</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Click any code line on the left to inspect</span>
                {onNavigate && (
                  <button
                    type="button"
                    className="feature-action-btn py-1 px-3 text-xs"
                    onClick={() => onNavigate('SCAN')}
                  >
                    Run Full Scan →
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Specialist Consensus */}
        {activeTab === 'agents' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* Agent 1: Security Auditor */}
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-rose-500/30">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-rose-300">🛡️ Security Auditor</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded">
                    99.4% CONF
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed mb-2">
                  Identified injectable input sink in Line 8. Exploitation allows arbitrary table extraction.
                </p>
                <div className="text-[10px] font-mono text-rose-400 bg-rose-950/50 p-1.5 rounded border border-rose-900/50">
                  VERDICT: CONFIRMED VULN
                </div>
              </div>

              {/* Agent 2: Architecture Sentinel */}
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-indigo-500/30">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-indigo-300">🏗️ Architecture Sentinel</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded">
                    98.1% CONF
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed mb-2">
                  Boundaries intact. Proposed parameterized fix complies with SQLAlchemy 2.0 AsyncSession conventions.
                </p>
                <div className="text-[10px] font-mono text-indigo-300 bg-indigo-950/50 p-1.5 rounded border border-indigo-900/50">
                  VERDICT: COMPATIBLE
                </div>
              </div>

              {/* Agent 3: Blast Radius Assessor */}
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-cyan-500/30">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-cyan-300">💥 Blast Radius Assessor</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded">
                    96.8% CONF
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed mb-2">
                  Isolated to single route handler. No external API schema breaking changes or contract regressions.
                </p>
                <div className="text-[10px] font-mono text-cyan-300 bg-cyan-950/50 p-1.5 rounded border border-cyan-900/50">
                  BLAST: LOW (1 FILE)
                </div>
              </div>

              {/* Agent 4: Remediation Engineer */}
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-purple-500/30">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-purple-300">🛠️ Remediation Engineer</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded">
                    99.0% CONF
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed mb-2">
                  Generated minimal parameterized query replacement with bindparam and tenant isolation.
                </p>
                <div className="text-[10px] font-mono text-purple-300 bg-purple-950/50 p-1.5 rounded border border-purple-900/50">
                  PATCH: COMPILED &amp; READY
                </div>
              </div>
            </div>

            {/* Consensus Verdict Summary Bar */}
            <div className="p-3 rounded-xl bg-gradient-to-r from-indigo-950/60 via-purple-950/50 to-slate-900/60 border border-indigo-500/30 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-emerald-400 text-base">✅</span>
                <span className="font-bold text-white">Consensus Verdict: 4/4 Specialists Approved</span>
                <span className="text-slate-400 font-mono text-[11px]">(Evidence Hash: sha256:8f4c2e...)</span>
              </div>
              {onNavigate && (
                <button
                  type="button"
                  className="btn-hero-secondary text-xs py-1.5 px-3 whitespace-nowrap"
                  onClick={() => onNavigate('ARCHITECTURE')}
                >
                  Explore Consensus Engine →
                </button>
              )}
            </div>
          </div>
        )}

        {/* Tab 3: Verified Patch Diff */}
        {activeTab === 'diff' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left: Interactive Unified Diff */}
            <div className="lg:col-span-8 bg-slate-950/80 p-4 rounded-xl border border-white/5 font-mono text-xs overflow-x-auto">
              <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/5 text-[11px]">
                <span className="text-indigo-400">--- a/app/api/routes/analytics.py</span>
                <span className="text-emerald-400">+++ b/app/api/routes/analytics.py</span>
              </div>

              <div className="space-y-1 leading-relaxed">
                <div className="text-slate-500">@@ -7,3 +7,4 @@ async def execute_dynamic_query(...)</div>
                
                {/* Deletion Line */}
                <div className="px-2 py-1 rounded bg-rose-950/60 border border-rose-500/30 text-rose-300">
                  <span className="font-bold select-none mr-2">-</span>
                  <span>sql = f&quot;SELECT * FROM metrics WHERE tenant_id = &#39;&#123;raw_filter&#125;&#39;&quot;</span>
                </div>
                
                {/* Deletion Line 2 */}
                <div className="px-2 py-1 rounded bg-rose-950/60 border border-rose-500/30 text-rose-300">
                  <span className="font-bold select-none mr-2">-</span>
                  <span>result = await db.execute(text(sql))</span>
                </div>

                {/* Addition Line 1 */}
                <div className="px-2 py-1 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
                  <span className="font-bold select-none mr-2">+</span>
                  <span>stmt = select(Metric).where(Metric.tenant_id == raw_filter)</span>
                </div>

                {/* Addition Line 2 */}
                <div className="px-2 py-1 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-300">
                  <span className="font-bold select-none mr-2">+</span>
                  <span>result = await db.execute(stmt)</span>
                </div>
              </div>
            </div>

            {/* Right: 6-Step Verification Checklist */}
            <div className="lg:col-span-4 bg-slate-900/50 p-4 rounded-xl border border-white/5 flex flex-col justify-between">
              <div>
                <div className="text-xs font-bold text-white font-display mb-3 pb-2 border-b border-white/5">
                  6-Step Verification Gate
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span>✓</span>
                    <span className="text-slate-300 font-mono text-[11px]">1. Context Graph Resolved</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span>✓</span>
                    <span className="text-slate-300 font-mono text-[11px]">2. AST Boundary Invariants Met</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span>✓</span>
                    <span className="text-slate-300 font-mono text-[11px]">3. Unified Patch Synthesized</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span>✓</span>
                    <span className="text-slate-300 font-mono text-[11px]">4. Sandbox Syntax Check Pass</span>
                  </div>
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span>✓</span>
                    <span className="text-slate-300 font-mono text-[11px]">5. Regression Test Suite Pass</span>
                  </div>
                  <div className="flex items-center gap-2 text-indigo-400 font-semibold">
                    <span className="animate-pulse">●</span>
                    <span className="text-indigo-300 font-mono text-[11px]">6. Ready for Operator Sign-off</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-white/5">
                {onNavigate && (
                  <button
                    type="button"
                    className="btn-hero-primary w-full text-xs py-2"
                    onClick={() => onNavigate('CHANGE_ANALYSIS')}
                  >
                    <span>🚀 Publish to GitHub PR</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
