import React from 'react';
import { formatBytes } from '../utils/formatters';

export default function TopIPsBarChart({ ips = [] }) {
  if (!ips || ips.length === 0) {
    return (
      <div className="h-44 flex items-center justify-center text-xs text-slate-500 font-mono">
        No IP telemetry recorded.
      </div>
    );
  }

  const maxCount = Math.max(...ips.map(d => d.count), 1);

  return (
    <div className="p-4 space-y-3">
      {ips.slice(0, 6).map((item, idx) => {
        const pctWidth = Math.round((item.count / maxCount) * 100);
        return (
          <div key={idx} className="space-y-1 font-mono text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-semibold text-cyan-300 tracking-wide">{item.ip}</span>
              <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                <span>{item.count} pkts</span>
                <span className="text-slate-500">({formatBytes(item.bytes)})</span>
                <span className="text-cyan-400 font-bold w-12 text-right">{item.percentage}%</span>
              </div>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
                style={{ width: `${pctWidth}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
