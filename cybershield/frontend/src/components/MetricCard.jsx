import React from 'react';

export default function MetricCard({ title, value, subtitle, icon: Icon, color = 'cyan', glow = false }) {
  const colorMap = {
    cyan: 'text-cyan-400 border-cyan-500/30 bg-cyan-950/20',
    emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20',
    amber: 'text-amber-400 border-amber-500/30 bg-amber-950/20',
    rose: 'text-rose-400 border-rose-500/30 bg-rose-950/20',
    purple: 'text-purple-400 border-purple-500/30 bg-purple-950/20',
  };

  const accent = colorMap[color] || colorMap.cyan;

  return (
    <div className={`p-4 rounded-xl bg-[#0c1222] border border-slate-800/90 relative overflow-hidden transition-all hover:border-slate-700 ${
      glow ? 'shadow-[0_0_15px_rgba(6,182,212,0.06)]' : ''
    }`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
          {title}
        </span>
        {Icon && (
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${accent}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>
      <div className="text-2xl font-bold font-mono text-white tracking-tight">
        {value}
      </div>
      {subtitle && (
        <div className="text-[11px] text-slate-500 mt-1 font-mono">
          {subtitle}
        </div>
      )}
    </div>
  );
}
