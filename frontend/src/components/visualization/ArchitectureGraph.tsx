'use client';

import React, { useState } from 'react';
import {
  Code,
  Globe,
  Server,
  FileCode,
  Database,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';

export interface ArchitectureNode {
  id: string;
  layer: 'frontend' | 'route' | 'handler' | 'schema' | 'model';
  name: string;
  file: string;
  lineRange: string;
  contract: string;
  status: 'verified' | 'breaking_change' | 'warning' | 'synced';
  details: string;
  evidenceSnippet?: string;
}

export interface ArchitectureEdge {
  from: string;
  to: string;
  label?: string;
  breaking?: boolean;
}

const DEFAULT_NODES: ArchitectureNode[] = [
  {
    id: 'fe-form',
    layer: 'frontend',
    name: 'RepositoryScanForm.tsx',
    file: 'frontend/src/features/scan/RepositoryScanForm.tsx',
    lineRange: 'L42-L88',
    contract: 'POST payload { repository_url, branch }',
    status: 'synced',
    details: 'React component dispatching mutation to backend with CSRF header injection.',
    evidenceSnippet: `const response = await startScan({\n  repository_url: repoUrl,\n  branch: branchName,\n});`,
  },
  {
    id: 'fe-client',
    layer: 'frontend',
    name: 'api.ts:startScan()',
    file: 'frontend/src/lib/api.ts',
    lineRange: 'L155-L167',
    contract: 'ScanCreate -> Promise<Scan>',
    status: 'synced',
    details: 'Typed client invoking /api/v1/scans with automatic credentials.',
    evidenceSnippet: `export async function startScan(payload: ScanCreate): Promise<Scan> {\n  return apiFetch('/api/v1/scans', { method: 'POST', body: JSON.stringify(payload) });\n}`,
  },
  {
    id: 'api-route',
    layer: 'route',
    name: 'POST /api/v1/scans',
    file: 'backend/src/api/routes/scans.py',
    lineRange: 'L74-L95',
    contract: 'Request: ScanCreate -> Response: ScanRead',
    status: 'verified',
    details: 'FastAPI route enforcing authentication and rate limits before task delegation.',
    evidenceSnippet: `@router.post('/api/v1/scans', response_model=ScanRead, status_code=202)\nasync def initiate_scan(payload: ScanCreate, current_user = Depends(get_current_user)):`,
  },
  {
    id: 'handler-svc',
    layer: 'handler',
    name: 'ScanService.execute()',
    file: 'backend/src/services/scan_service.py',
    lineRange: 'L120-L165',
    contract: 'execute(repo_url, branch) -> ScanWorkflow',
    status: 'verified',
    details: 'Orchestrates sandbox cloning, AST extraction, deterministic rules, and LLM verification.',
    evidenceSnippet: `async def execute_scan(self, repo_url: str, branch: Optional[str] = None):\n    manifest = await self.git_cloner.clone_and_parse(repo_url, branch)\n    return await self.engine.run_pipeline(manifest)`,
  },
  {
    id: 'schema-pydantic',
    layer: 'schema',
    name: 'ScanCreate & ScanRead',
    file: 'backend/src/schemas/scan.py',
    lineRange: 'L15-L48',
    contract: 'Pydantic BaseModel with strict url validation',
    status: 'verified',
    details: 'Strict schema with URL sanitation and regex branch validation.',
    evidenceSnippet: `class ScanCreate(BaseModel):\n    repository_url: HttpUrl\n    branch: Optional[str] = Field(default='main')`,
  },
  {
    id: 'db-model',
    layer: 'model',
    name: 'ScanRecord (SQLAlchemy)',
    file: 'backend/src/models/scan.py',
    lineRange: 'L30-L75',
    contract: 'Table "scans" (id, repo_url, status, commit_sha)',
    status: 'synced',
    details: 'SQLAlchemy model mapped to SQLite/PostgreSQL with indexed foreign keys for findings.',
    evidenceSnippet: `class ScanRecord(Base):\n    __tablename__ = "scans"\n    id = Column(String, primary_key=True, default=generate_uuid)\n    status = Column(Enum(ScanStatus), nullable=False)`,
  },
];

const DEFAULT_EDGES: ArchitectureEdge[] = [
  { from: 'fe-form', to: 'fe-client', label: 'calls' },
  { from: 'fe-client', to: 'api-route', label: 'HTTP POST' },
  { from: 'api-route', to: 'schema-pydantic', label: 'validates with' },
  { from: 'api-route', to: 'handler-svc', label: 'dispatches to' },
  { from: 'handler-svc', to: 'schema-pydantic', label: 'constructs' },
  { from: 'handler-svc', to: 'db-model', label: 'persists to' },
];

export interface ArchitectureGraphProps {
  nodes?: ArchitectureNode[];
  edges?: ArchitectureEdge[];
  onSelectNode?: (node: ArchitectureNode) => void;
  interactive?: boolean;
}

export function ArchitectureGraph({
  nodes = DEFAULT_NODES,
  edges = DEFAULT_EDGES,
  onSelectNode,
  interactive = true,
}: ArchitectureGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string>(nodes[0]?.id || 'fe-form');
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[0];

  // Group nodes by layer
  const layers: { key: ArchitectureNode['layer']; label: string; icon: React.ReactNode }[] = [
    { key: 'frontend', label: '1. Frontend (Client)', icon: <Code size={14} /> },
    { key: 'route', label: '2. API Endpoint', icon: <Globe size={14} /> },
    { key: 'handler', label: '3. Service / Logic', icon: <Server size={14} /> },
    { key: 'schema', label: '4. Contract Schema', icon: <FileCode size={14} /> },
    { key: 'model', label: '5. Database Model', icon: <Database size={14} /> },
  ];

  const handleNodeClick = (node: ArchitectureNode) => {
    setSelectedNodeId(node.id);
    if (onSelectNode) onSelectNode(node);
  };

  const isConnected = (nodeId: string) => {
    if (!selectedNodeId) return true;
    if (nodeId === selectedNodeId) return true;
    return edges.some(
      (e) =>
        (e.from === selectedNodeId && e.to === nodeId) ||
        (e.to === selectedNodeId && e.from === nodeId)
    );
  };

  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.5rem',
        background: 'rgba(9, 13, 26, 0.85)',
      }}
    >
      {/* Visualizer Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '1rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h3
              style={{
                fontSize: '1.125rem',
                fontWeight: 700,
                fontFamily: 'var(--font-display)',
                color: 'var(--text-primary)',
              }}
            >
              Cross-Layer Contract & Relationship Graph
            </h3>
            <Badge variant="cyan" size="sm">
              Live AST Trace
            </Badge>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Deterministic end-to-end evidence linking UI components down to database schemas.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click any node to inspect evidence</span>
        </div>
      </div>

      {/* 5-Column Interactive Architecture Visualizer */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
          position: 'relative',
        }}
      >
        {layers.map((layer) => {
          const layerNodes = nodes.filter((n) => n.layer === layer.key);
          return (
            <div
              key={layer.key}
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
                padding: '0.85rem',
                background: 'rgba(5, 8, 18, 0.6)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {/* Column Header */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                  paddingBottom: '0.4rem',
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                {layer.icon}
                {layer.label}
              </div>

              {/* Node Cards */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                {layerNodes.map((node) => {
                  const isSelected = selectedNodeId === node.id;
                  const isHovered = hoveredNodeId === node.id;
                  const connected = isConnected(node.id);

                  return (
                    <div
                      key={node.id}
                      onClick={() => handleNodeClick(node)}
                      onMouseEnter={() => setHoveredNodeId(node.id)}
                      onMouseLeave={() => setHoveredNodeId(null)}
                      style={{
                        padding: '0.75rem',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: isSelected
                          ? 'rgba(99, 102, 241, 0.22)'
                          : isHovered
                          ? 'rgba(255, 255, 255, 0.08)'
                          : 'rgba(13, 19, 36, 0.7)',
                        border: isSelected
                          ? '1px solid var(--border-focus)'
                          : '1px solid var(--border-glass)',
                        cursor: interactive ? 'pointer' : 'default',
                        transition: 'all var(--transition-fast)',
                        boxShadow: isSelected ? '0 0 15px rgba(56, 189, 248, 0.3)' : 'none',
                        opacity: !connected && hoveredNodeId ? 0.4 : 1,
                      }}
                    >
                      <div
                        style={{
                          fontSize: '0.8125rem',
                          fontWeight: 600,
                          color: isSelected ? '#ffffff' : 'var(--text-primary)',
                          marginBottom: '0.2rem',
                          wordBreak: 'break-word',
                        }}
                      >
                        {node.name}
                      </div>

                      <div
                        style={{
                          fontSize: '0.7rem',
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-muted)',
                          marginBottom: '0.4rem',
                        }}
                      >
                        {node.lineRange}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span
                          style={{
                            fontSize: '0.6875rem',
                            color: node.status === 'verified' ? 'var(--success-text)' : 'var(--text-secondary)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                          }}
                        >
                          <CheckCircle2 size={11} /> {node.status}
                        </span>
                        {isSelected && (
                          <span style={{ fontSize: '0.65rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                            ACTIVE
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Node Evidence Inspector Box */}
      {selectedNode && (
        <div
          style={{
            padding: '1.25rem',
            background: 'rgba(6, 9, 20, 0.95)',
            border: '1px solid var(--border-glass-hover)',
            borderRadius: 'var(--radius-lg)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedNode.name}
                </span>
                <Badge variant="cyan" size="sm">
                  {selectedNode.layer.toUpperCase()}
                </Badge>
                <Badge variant="success" size="sm">
                  Verified AST Node
                </Badge>
              </div>
              <div
                style={{
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-muted)',
                  marginTop: '0.2rem',
                }}
              >
                {selectedNode.file} : {selectedNode.lineRange}
              </div>
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', background: 'rgba(255, 255, 255, 0.04)', padding: '0.35rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <strong>Contract:</strong> {selectedNode.contract}
            </div>
          </div>

          <p style={{ fontSize: '0.8125rem', color: 'var(--text-light)', lineHeight: 1.5 }}>
            {selectedNode.details}
          </p>

          {selectedNode.evidenceSnippet && (
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>
                Verified AST Source Evidence
              </div>
              <pre
                style={{
                  padding: '0.75rem 1rem',
                  background: 'var(--bg-code)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-code)',
                  overflowX: 'auto',
                  lineHeight: 1.45,
                }}
              >
                <code>{selectedNode.evidenceSnippet}</code>
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
