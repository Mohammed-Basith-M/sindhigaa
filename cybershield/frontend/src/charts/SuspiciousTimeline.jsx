import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert } from 'lucide-react';

export default function SuspiciousTimeline({ events = [] }) {
  if (!events || events.length === 0) {
    return (
      <div className="h-32 flex items-center justify-center text-xs text-slate-500 font-mono">
        No anomalous telemetry timeline markers.
      </div>
    );
  }

  const getIcon = (type) => {
    switch (type) {
      case 'ALERT':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      case 'WARNING':
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      case 'INFO':
      default:
        return <Info className="w-4 h-4 text-cyan-400" />;
    }
  };

  return (
    <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
      {events.map((evt, idx) => (
        <div key={idx} className="relative flex items-start gap-3">
          <div className="absolute -left-6 mt-0.5 w-5 h-5 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center shrink-0">
            {getIcon(evt.type)}
          </div>
          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80 flex-1 font-mono text-xs">
            <div className="flex items-center justify-between mb-1">
              <span className="text-cyan-400 font-bold">{evt.time}</span>
              <span className="text-[10px] text-slate-500 uppercase">{evt.type}</span>
            </div>
            <p className="text-slate-300 leading-relaxed text-[11px]">
              {evt.description}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
