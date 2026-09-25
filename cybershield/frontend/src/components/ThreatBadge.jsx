import React from 'react';
import { getSeverityStyle } from '../utils/formatters';

export default function ThreatBadge({ severity, size = 'md' }) {
  const style = getSeverityStyle(severity);
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-semibold rounded-md border ${style.badge} ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: style.color }} />
      <span>{(severity || 'BENIGN').toUpperCase()}</span>
    </span>
  );
}
