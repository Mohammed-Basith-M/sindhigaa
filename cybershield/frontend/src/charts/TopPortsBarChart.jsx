import React from 'react';

export default function TopPortsBarChart({ ports = [] }) {
  if (!ports || ports.length === 0) {
    return (
      <div className="h-44 flex items-center justify-center text-xs text-slate-500 font-mono">
        No port telemetry recorded.
      </div>
    );
  }

  const maxCount = Math.max(...ports.map(d => d.count), 1);

  return (
    <div className="p-4 space-y-3">
      {ports.slice(0, 6).map((item, idx) => {
        const pctWidth = Math.round((item.count / maxCount) * 100);
        return (
          <div key={idx} className="space-y-1 font-mono text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <div className="flex items-center gap-2">
                <span className="font-bold text-white tracking-wide">{item.port}</span>
                <span className="text-[11px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                  {item.service || 'Unknown'}
                </span>
              </div>
              <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                <span>{item.count} pkts</span>
                <span className="text-cyan-400 font-bold w-12 text-right">{item.percentage}%</span>
              </div>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-500"
                style={{ width: `${pctWidth}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
