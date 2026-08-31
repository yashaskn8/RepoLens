'use client';

import React from 'react';

export interface PresetRepo {
  name: string;
  url: string;
  branch: string;
  tag: string;
  icon: string;
}

export const SAMPLE_REPOSITORIES: PresetRepo[] = [
  {
    name: 'RepoLens',
    url: 'https://github.com/yashaskn8/RepoLens',
    branch: 'main',
    tag: 'Next.js + FastAPI',
    icon: '⚡',
  },
  {
    name: 'FastAPI',
    url: 'https://github.com/fastapi/fastapi',
    branch: 'master',
    tag: 'Python Framework',
    icon: '🚀',
  },
  {
    name: 'Flask',
    url: 'https://github.com/pallets/flask',
    branch: 'main',
    tag: 'Python WSGI',
    icon: '🌶️',
  },
  {
    name: 'Express',
    url: 'https://github.com/expressjs/express',
    branch: 'master',
    tag: 'Node.js Backend',
    icon: '🌐',
  },
];

export interface PresetPickerProps {
  onSelect: (url: string, branch: string) => void;
  disabled?: boolean;
}

export const PresetPicker: React.FC<PresetPickerProps> = ({ onSelect, disabled = false }) => {
  return (
    <div className="preset-bar" role="group" aria-label="Sample repositories quick selection">
      <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
        <span aria-hidden="true">💡</span> Quick Presets:
      </span>
      {SAMPLE_REPOSITORIES.map((repo) => (
        <button
          key={repo.url}
          type="button"
          disabled={disabled}
          onClick={() => onSelect(repo.url, repo.branch)}
          className="preset-chip"
          title={`Load ${repo.name} (${repo.tag})`}
        >
          <span aria-hidden="true">{repo.icon}</span>
          <span>{repo.name}</span>
          <span className="text-[10px] text-slate-500 font-mono">({repo.branch})</span>
        </button>
      ))}
    </div>
  );
};
