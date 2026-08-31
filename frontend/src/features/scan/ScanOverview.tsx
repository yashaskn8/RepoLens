import React from 'react';
import { Scan } from '@/types/domain';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';

export interface ScanOverviewProps {
  scan: Scan;
}

export const ScanOverview: React.FC<ScanOverviewProps> = ({ scan }) => {
  const archOverview = scan.model_metadata?.extra_metadata?.architecture_overview as string | undefined;
  const frameworks = (scan.model_metadata?.extra_metadata?.frameworks as string[]) || [];
  const languages = (scan.model_metadata?.extra_metadata?.languages as Record<string, number>) || {};

  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

  return (
    <Card
      title="Repository Intelligence & Architecture"
      badge={<Badge variant="tag">Mapper Analysis</Badge>}
      style={{ marginBottom: '2rem' }}
    >
      {archOverview && (
        <div className="mb-4 leading-relaxed text-slate-300 text-sm">
          {archOverview}
        </div>
      )}

      <div className="flex gap-2 flex-wrap mt-3">
        {Object.entries(languages).map(([lang, count]) => (
          <span key={lang} className="pill-tag">
            {lang}: {count} files
          </span>
        ))}
        {frameworks.map((fw) => (
          <span key={fw} className="pill-tag pill-tag-framework">
            Framework: {fw}
          </span>
        ))}
      </div>

      <div className="mt-5 pt-4 border-t border-white/10 flex gap-3 flex-wrap">
        <a
          href={`${apiBase}/api/v1/scans/${scan.id}/report?format=markdown`}
          download={`repolens-report-${scan.id}.md`}
          target="_blank"
          rel="noopener noreferrer"
          className="filter-btn text-emerald-400 bg-emerald-950/20 border-emerald-800/40 hover:bg-emerald-900/40"
        >
          <span aria-hidden="true">📄</span> Export Markdown Report
        </a>
        <a
          href={`${apiBase}/api/v1/scans/${scan.id}/report?format=json`}
          download={`repolens-report-${scan.id}.json`}
          target="_blank"
          rel="noopener noreferrer"
          className="filter-btn text-sky-400 bg-sky-950/20 border-sky-800/40 hover:bg-sky-900/40"
        >
          <span aria-hidden="true">📊</span> Export JSON Report
        </a>
      </div>
    </Card>
  );
};
