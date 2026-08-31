# RepoLens Frontend Architecture Plan
## Post-v1 Strengthening Track (Batches 1–4)

**Status:** Approved Architecture Plan  
**Target:** Frontend Maintainability, Modular Feature Ownership, Design System Baseline, Accessibility & Polish  
**Scope Boundary:** `frontend/` only (Zero backend/contract drift)

---

## 1. Current Frontend Topology & Audit Findings

### 1.1 Architecture & Code Topology (Baseline)
Prior to Batch 1, the RepoLens frontend was structured as a monolithic client-rendered application centered around four oversized source files:

| File | Baseline Lines | Baseline Size | Primary Mixed Responsibilities |
| :--- | :--- | :--- | :--- |
| `frontend/src/app/page.tsx` | 616 lines | 26.8 KB | Health check, Header/Auth inline presentation, Mode switching, Hero, Scan submission, 2s Scan polling, Scan status/progress, Architecture summary, Telemetry summary, Findings filtering/rendering/expansion, Remediation invocation, and AuthModal wiring. |
| `frontend/src/components/ChangeAnalysisExperience.tsx` | 1,434 lines | 65.4 KB | PR/Exact form inputs, PR metadata loading, SSE workflow streaming, 2s analysis polling, Artifact loading, 6-tab navigation (Impacts, Contracts, Review, Report, Telemetry, Publish), Blast radius tree rendering, Route/Schema/Dependency/Config delta views, PR review findings filtering, Markdown report display & export, Telemetry metrics, and Phase 7 GitHub review publication & operator authorization modal. |
| `frontend/src/components/RemediationLifecycle.tsx` | 681 lines | 31.4 KB | Step 1 Research API/state, Step 2 Fix Plan API/state, Step 3 Patch Generation/Verification API/state, Steps 4–6 Human Approval/Rejection/Revision forms, DiffViewer embedding, and Phase 5 Delivery Preview modal/submission. |
| `frontend/src/components/WorkflowTimeline.tsx` | 289 lines | 11.9 KB | Live SSE event stream receiver, filter pills, auto-scroll management, event payload viewer. |
| `frontend/src/components/auth/AuthModal.tsx` | 158 lines | 5.7 KB | Sign-in and account creation tabs, form submission, error handling. |
| `frontend/src/components/DiffViewer.tsx` | 96 lines | 3.3 KB | Line-by-line unified diff parser and colorizer. |

### 1.2 Identified Problems
1. **Monolithic Feature Controllers**: `ChangeAnalysisExperience` (1,434 lines) and `page.tsx` (616 lines) violate the single-responsibility principle, combining data fetching, polling lifecycles, complex nested state machines, and dense UI presentation in single components.
2. **Style Fragmentation & Inline Duplication**: Heavy reliance on duplicated inline `style={{ ... }}` objects across `page.tsx` (e.g. hardcoded colors `#94a3b8`, `#38bdf8`, `#4ade80`, `#fca5a5`, badges, borders) alongside mixed Tailwind classes in child components.
3. **Accessibility (A11y) Deficits**:
   - `AuthModal` lacked standard modal dialog attributes (`role="dialog"`, `aria-modal="true"`, `aria-labelledby`, Escape key handling, and focus containment).
   - Mode navigation lacked ARIA semantics (`aria-pressed` or `role="tab"`).
   - Form inputs lacked explicit accessible labels (`<label>` or `aria-label`).
   - Global animations lacked `@media (prefers-reduced-motion: reduce)` dampening.
   - Interactive elements lacked a unified `:focus-visible` ring.
4. **Missing UI Primitives**: No reusable design system primitives (Button, Card, Badge, Input, Alert, EmptyState, Spinner), leading to copy-pasted HTML and styling logic across components.
5. **State Locality Issues**: Scan form inputs, polling, and results were held directly at the root `page.tsx` level instead of encapsulated inside a dedicated scan workspace feature.

---

## 2. Target Component Hierarchy & Feature Boundaries

```
frontend/src/
├── app/
│   ├── layout.tsx                     # Global HTML/body shell, AuthProvider
│   ├── page.tsx                       # Orchestration shell (AppShell, AppHeader, WorkspaceNav)
│   └── globals.css                    # Design tokens, CSS resets, focus-visible, reduced-motion
│
├── components/
│   ├── ui/                            # Shared UI Design System Primitives
│   │   ├── Alert.tsx                  # Error, warning, info, and success alert banners
│   │   ├── Badge.tsx                  # Severity, verdict, status, and custom badges
│   │   ├── Button.tsx                 # Standardized action buttons with variants and loading state
│   │   ├── Card.tsx                   # Glassmorphism container card with header and body
│   │   ├── EmptyState.tsx             # Standard empty-state display with icon and actions
│   │   ├── Input.tsx                  # Styled text/search input with label and helper text
│   │   └── Spinner.tsx                # Lightweight SVG spinner
│   │
│   └── layout/                        # Core Layout & Shell Components
│       ├── AppShell.tsx               # Centered page container wrapper
│       ├── AppHeader.tsx              # Brand identity, ServiceStatus, User status, Sign In/Out
│       ├── RoleBadge.tsx              # Authoritative USER / OPERATOR role presentation
│       ├── ServiceStatus.tsx          # Backend service health & database status badge
│       └── WorkspaceNav.tsx           # Accessible mode switcher (Scan vs Change Analysis)
│
├── features/
│   ├── auth/
│   │   └── AuthModal.tsx              # Fully accessible dialog with focus handling & Escape key
│   │
│   ├── scan/                          # Repository Security & Multi-Agent Scan Feature
│   │   ├── RepositoryScanWorkspace.tsx # Scan state manager, submission, and polling controller
│   │   ├── RepositoryScanForm.tsx      # Repository URL & branch submission form
│   │   ├── ScanStatusPanel.tsx         # Active scan progress, metadata, and status badge
│   │   ├── ScanOverview.tsx            # Architecture summary, languages, frameworks, export
│   │   └── ScanTelemetryPanel.tsx      # Execution telemetry, stage counts, and tool stats
│   │
│   ├── findings/                      # Grounded Findings Feature
│   │   ├── FindingsToolbar.tsx         # Severity & verdict filter controls
│   │   ├── FindingsList.tsx            # Filtered list container with empty state
│   │   ├── FindingCard.tsx             # Finding header, description, verification reason
│   │   └── FindingEvidence.tsx         # Code snippet, line numbers, and file location
│   │
│   ├── change-analysis/               # Change Intelligence & Blast Radius Feature
│   │   ├── ChangeAnalysisWorkspace.tsx # Workspace container, tab controller, polling manager
│   │   ├── ChangeAnalysisInput.tsx     # PR URL vs Exact Commit pair input form
│   │   ├── ChangeAnalysisStatus.tsx    # Ingestion & pipeline execution status with SSE timeline
│   │   ├── ChangeSummary.tsx           # Blast radius summary & top risk factors
│   │   ├── ImpactExplorer.tsx          # Interactive blast radius impact tree & details
│   │   ├── ContractDeltasPanel.tsx     # Route, schema, dependency, and config deltas
│   │   └── ChangeTelemetryPanel.tsx    # Timing metrics, LLM tokens, and stage breakdown
│   │
│   ├── review/                        # PR Review & GitHub Delivery Publication Feature
│   │   ├── ChangeReviewPanel.tsx       # PR review findings list & severity filtering
│   │   ├── ReviewReportPanel.tsx       # Markdown report viewer with copy & download
│   │   └── ReviewPublicationPanel.tsx  # GitHub review preview, approval, and operator delivery
│   │
│   ├── remediation/                   # Evidence-Grounded Remediation Feature
│   │   ├── RemediationLifecycle.tsx    # 6-step lifecycle coordinator
│   │   ├── ResearchPanel.tsx           # Step 1: Research findings display
│   │   ├── FixPlanPanel.tsx            # Step 2: Fix plan presentation
│   │   ├── PatchCandidatePanel.tsx     # Step 3: Verified patch diff & machine verdict
│   │   ├── HumanReviewControls.tsx     # Steps 4–6: Human approval, rejection, and revision
│   │   └── DeliveryPreviewModal.tsx    # Step 7: Operator GitHub branch/PR delivery modal
│   │
│   ├── diff/
│   │   └── DiffViewer.tsx              # Line-by-line syntax-colored diff viewer
│   │
│   └── workflow/
│       └── WorkflowTimeline.tsx        # Live SSE event stream receiver and audit timeline
│
├── context/
│   └── AuthContext.tsx                # Authoritative session context (cookies & CSRF)
│
├── lib/
│   ├── api.ts                         # Centralized backend API client (credentials: include)
│   └── useWorkflowStream.ts           # SSE event stream React hook
│
└── types/
    └── domain.ts                      # Strict TypeScript types matching backend schemas
```

---

## 3. Design System & Style Architecture

### 3.1 Design Tokens (`globals.css`)
Expanded CSS custom properties under `:root`:
- **Surfaces**: `--bg-primary` (`#0a0d14`), `--bg-secondary` (`#101522`), `--bg-card` (`rgba(22, 29, 46, 0.7)`), `--bg-card-hover` (`rgba(30, 41, 59, 0.8)`).
- **Borders**: `--border-subtle` (`rgba(255, 255, 255, 0.08)`), `--border-active` (`rgba(99, 102, 241, 0.4)`), `--border-focus` (`#38bdf8`).
- **Typography & Colors**: `--text-primary` (`#f1f5f9`), `--text-secondary` (`#94a3b8`), `--text-muted` (`#64748b`).
- **Accents**: `--accent-primary` (`#6366f1`), `--accent-gradient` (`linear-gradient(135deg, #6366f1 0%, #a855f7 50%, #ec4899 100%)`).
- **Semantic Statuses**:
  - Critical: `--critical` (`#ef4444`), `--critical-bg` (`rgba(239, 68, 68, 0.15)`), `--critical-border` (`rgba(239, 68, 68, 0.35)`)
  - High: `--high` (`#f97316`), `--high-bg` (`rgba(249, 115, 22, 0.15)`), `--high-border` (`rgba(249, 115, 22, 0.35)`)
  - Medium: `--medium` (`#eab308`), `--medium-bg` (`rgba(234, 179, 8, 0.15)`), `--medium-border` (`rgba(234, 179, 8, 0.35)`)
  - Low: `--low` (`#38bdf8`), `--low-bg` (`rgba(56, 189, 248, 0.15)`), `--low-border` (`rgba(56, 189, 248, 0.35)`)
  - Success / Passed: `--success` (`#10b981`), `--success-bg` (`rgba(16, 185, 129, 0.15)`)
  - Operator: `--operator-bg` (`rgba(168, 85, 247, 0.25)`), `--operator-border` (`#a855f7`), `--operator-text` (`#d8b4fe`)
  - User: `--user-bg` (`rgba(56, 189, 248, 0.15)`), `--user-border` (`rgba(56, 189, 248, 0.5)`), `--user-text` (`#7dd3fc`)
- **Radii**: `--radius-sm` (`6px`), `--radius-md` (`10px`), `--radius-lg` (`16px`), `--radius-full` (`9999px`).

### 3.2 Accessibility Foundations
1. **Focus Rings**: Standardized `:focus-visible` outline (`2px solid var(--border-focus)`, `outline-offset: 2px`).
2. **Reduced Motion**: Full `@media (prefers-reduced-motion: reduce)` block disabling pulses, spin loops, and smooth transitions for users with vestibular sensitivities.
3. **Semantic Hierarchy**: Proper `<header>`, `<nav>`, `<main>`, `<section>`, `<article>`, and `<dialog>` elements.
4. **Accessible Forms & Modals**: Explicit labels, `aria-describedby` error announcements, `role="dialog"` with Escape listeners and focus management.

---

## 4. Four-Batch Frontend Strengthening Roadmap

### Batch 1: Architecture & Design System Foundation (Current)
- Decompose monolithic `page.tsx`, `ChangeAnalysisExperience.tsx`, and `RemediationLifecycle.tsx`.
- Create core UI primitives (`Button`, `Card`, `Badge`, `Input`, `Alert`, `EmptyState`, `Spinner`).
- Establish `AppShell`, `AppHeader`, `RoleBadge`, `ServiceStatus`, `WorkspaceNav`.
- Standardize design tokens, `:focus-visible`, and `@media (prefers-reduced-motion: reduce)`.
- Improve modal accessibility in `AuthModal`.
- Verify full regression suite (Playwright E2E, Chrome DevTools, local build/lint/typecheck, remote CI).

### Batch 2: Data Architecture, Streaming & UX Error Resilience (Planned)
- Evaluate SSE-first workflow streaming with graceful polling fallback across scans and change analyses.
- URL-driven deep-linking and state sync (e.g. `?mode=change_analysis&analysis_id=...`).
- Unified API error normalization with actionable retry mechanisms.
- Optimistic UI updates and refined loading states.

### Batch 3: Premium Evidence, AST Graph & Diff Experience (Planned)
- High-fidelity interactive dependency and blast-radius graph visualization.
- Split / side-by-side diff mode with line-level commentary.
- Enhanced remediation workbench with syntax highlight enhancements.
- Fine-tuned keyboard shortcuts and command palette.

### Batch 4: Comprehensive Test Suite, A11y Audit & Performance (Planned)
- Complete React Testing Library + Vitest unit and integration test suite.
- Automated axe-core accessibility compliance test suite.
- Lighthouse performance profiling and bundle optimization.
- Final post-v1 frontend release verification.
