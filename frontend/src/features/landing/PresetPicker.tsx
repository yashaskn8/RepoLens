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
      <span className="preset-label">
        <span className="preset-label-icon" aria-hidden="true">⚡</span> Quick Launch:
      </span>
      <div className="preset-chips-container">
        {SAMPLE_REPOSITORIES.map((repo) => (
          <button
            key={repo.url}
            type="button"
            disabled={disabled}
            onClick={() => onSelect(repo.url, repo.branch)}
            className="preset-chip"
            title={`Load ${repo.name} (${repo.tag})`}
          >
            <span className="preset-icon" aria-hidden="true">{repo.icon}</span>
            <span className="preset-name">{repo.name}</span>
            <span className="preset-branch">{repo.branch}</span>
          </button>
        ))}
      </div>
    </div>
  );
};
