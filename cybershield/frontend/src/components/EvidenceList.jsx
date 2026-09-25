import React from 'react';
import { CheckCircle2, AlertCircle } from 'lucide-react';

export default function EvidenceList({ evidence = [] }) {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="text-xs text-slate-500 italic py-2">
        No specific threat indicators recorded.
      </div>
    );
  }

  return (
    <ul className="space-y-2">
      {evidence.map((item, idx) => (
        <li 
          key={idx} 
          className="flex items-start gap-2.5 text-xs text-slate-300 bg-slate-900/50 p-2.5 rounded-lg border border-slate-800/80"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
          <span className="leading-relaxed font-mono">{item}</span>
        </li>
      ))}
    </ul>
  );
}
