import React from 'react';

export interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  badge?: React.ReactNode;
  action?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const Card: React.FC<CardProps> = ({
  title,
  badge,
  action,
  children,
  className = '',
  style,
  ...props
}) => {
  return (
    <div className={`glass-card ${className}`} style={style} {...props}>
      {(title || badge || action) && (
        <div className="card-title">
          <div className="flex items-center gap-2 flex-wrap">
            {typeof title === 'string' ? <span>{title}</span> : title}
            {badge}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
};
