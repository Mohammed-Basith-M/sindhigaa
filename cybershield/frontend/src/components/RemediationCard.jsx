import React from 'react';
import { ShieldAlert, ShieldCheck, AlertCircle, Info } from 'lucide-react';

export default function RemediationCard({ remediation }) {
  if (!remediation) return null;

  const { actions = [], disclaimer, insufficient_notice } = remediation;

  const getPriorityStyle = (priority) => {
    const p = (priority || '').toUpperCase();
    if (p.includes('CRITICAL')) {
      return {
        badge: 'bg-rose-500/10 text-rose-400 border-rose-500/40',
        border: 'border-l-rose-500',
        text: 'text-rose-400'
      };
    }
    if (p.includes('HIGH')) {
      return {
        badge: 'bg-red-500/10 text-red-400 border-red-500/30',
        border: 'border-l-red-500',
        text: 'text-red-400'
      };
    }
    if (p.includes('MEDIUM')) {
      return {
        badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        border: 'border-l-amber-500',
        text: 'text-amber-400'
      };
    }
    return {
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      border: 'border-l-emerald-500',
      text: 'text-emerald-400'
    };
  };

  return (
    <div className="space-y-4">
      {/* Insufficient Evidence Notice */}
      {insufficient_notice && (
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 leading-relaxed font-mono">
            {insufficient_notice}
          </div>
        </div>
      )}

      {/* Action Items */}
      {actions.map((item, idx) => {
        const style = getPriorityStyle(item.priority);
        return (
          <div 
            key={idx} 
            className={`p-4 rounded-xl bg-[#0c1222] border border-slate-800/90 border-l-4 ${style.border} space-y-2`}
          >
            <div className="flex items-center justify-between">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${style.badge}`}>
                {item.priority}
              </span>
            </div>
            <h4 className="text-sm font-semibold text-white tracking-wide">
              {item.action}
            </h4>
            <div className="text-xs text-slate-400 leading-relaxed font-mono">
              <span className="text-slate-500 font-semibold uppercase text-[10px] block mb-0.5">Reason:</span>
              {item.reason}
            </div>
          </div>
        );
      })}

      {/* Mandatory Validation Disclaimer */}
      {disclaimer && (
        <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/20 flex items-start gap-3 text-xs text-cyan-300/90">
          <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed font-mono text-[11px]">
            {disclaimer}
          </p>
        </div>
      )}
    </div>
  );
}
