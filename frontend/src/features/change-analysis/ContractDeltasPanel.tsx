import React from 'react';
import {
  ConfigDelta,
  DependencyDelta,
  RouteContractDelta,
  SchemaModelDelta,
} from '@/types/domain';
import { Badge } from '@/components/ui/Badge';

export interface ContractDeltasPanelProps {
  routeDeltas: RouteContractDelta[];
  schemaDeltas: SchemaModelDelta[];
  dependencyDeltas: DependencyDelta[];
  configDeltas: ConfigDelta[];
}

export const ContractDeltasPanel: React.FC<ContractDeltasPanelProps> = ({
  routeDeltas,
  schemaDeltas,
  dependencyDeltas,
  configDeltas,
}) => {
  return (
    <div className="flex flex-col gap-6">
      {/* Route Contract Deltas */}
      <div>
        <div className="text-base font-semibold mb-3 text-slate-100 flex items-center gap-2">
          <span>🌐</span> API Route Contract Changes ({routeDeltas.length})
        </div>
        {routeDeltas.length === 0 ? (
          <div className="text-slate-400 text-xs">
            No API route contract changes detected.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {routeDeltas.map((r, idx) => (
              <div key={idx} className="finding-card">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="high">{r.change_type}</Badge>
                  <span className="font-mono font-semibold text-xs text-slate-100">{r.route_name}</span>
                  <Badge variant="tag">{r.file_path}</Badge>
                </div>
                <div className="mt-2 text-xs text-slate-300">
                  {r.details || `${r.base_path || ''} → ${r.head_path || ''}`}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Schema & Model Deltas */}
      <div>
        <div className="text-base font-semibold mb-3 text-slate-100 flex items-center gap-2">
          <span>📐</span> Data Schema & Model Deltas ({schemaDeltas.length})
        </div>
        {schemaDeltas.length === 0 ? (
          <div className="text-slate-400 text-xs">
            No schema or model field changes detected.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {schemaDeltas.map((s, idx) => (
              <div key={idx} className="finding-card">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="medium">{s.change_type}</Badge>
                  <span className="font-mono font-semibold text-xs text-slate-100">
                    {s.model_name}.{s.field_name}
                  </span>
                  <Badge variant="tag">{s.file_path}</Badge>
                </div>
                <div className="mt-2 text-xs text-slate-300">
                  Type:{' '}
                  <span className="font-mono text-sky-400">{s.base_type || 'none'}</span> →{' '}
                  <span className="font-mono text-purple-400">{s.head_type || 'none'}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Dependency Deltas */}
      <div>
        <div className="text-base font-semibold mb-3 text-slate-100 flex items-center gap-2">
          <span>📦</span> Package Dependencies ({dependencyDeltas.length})
        </div>
        {dependencyDeltas.length === 0 ? (
          <div className="text-slate-400 text-xs">
            No dependency manifest changes detected.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {dependencyDeltas.map((d, idx) => (
              <div key={idx} className="finding-card">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="info">{d.change_type}</Badge>
                  <span className="font-semibold text-xs text-slate-100">{d.package_name}</span>
                  <Badge variant="tag">{d.manifest_file}</Badge>
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  Version: {d.base_version || 'N/A'} → {d.head_version || 'N/A'}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Config Deltas */}
      {configDeltas.length > 0 && (
        <div>
          <div className="text-base font-semibold mb-3 text-slate-100 flex items-center gap-2">
            <span>⚙️</span> Configuration Deltas ({configDeltas.length})
          </div>
          <div className="flex flex-col gap-3">
            {configDeltas.map((c, idx) => (
              <div key={idx} className="finding-card">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="info">{c.change_type}</Badge>
                  <span className="font-mono font-semibold text-xs text-slate-100">{c.key}</span>
                  <Badge variant="tag">{c.file_path}</Badge>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
