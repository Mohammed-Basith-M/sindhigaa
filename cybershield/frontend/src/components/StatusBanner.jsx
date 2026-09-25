import React from 'react';
import { AlertTriangle, CheckCircle, ShieldCheck } from 'lucide-react';

export default function StatusBanner({ isDemo, filename }) {
  if (isDemo) {
    return (
      <div className="w-full bg-amber-500/10 border-b border-amber-500/30 px-6 py-2.5 flex items-center justify-between text-xs text-amber-300">
        <div className="flex items-center gap-2.5 font-medium">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
          <span className="font-semibold tracking-wider uppercase text-amber-400">DEMO MODE:</span>
          <span>Sample data is being displayed. No real PCAP analysis was performed.</span>
        </div>
        <div className="hidden md:flex items-center gap-2 text-amber-400/80 font-mono text-[11px]">
          <span>Scenario: SYN Recon Probe Capture</span>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full bg-cyan-500/10 border-b border-cyan-500/30 px-6 py-2.5 flex items-center justify-between text-xs text-cyan-300">
      <div className="flex items-center gap-2.5 font-medium">
        <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
        <span className="font-semibold tracking-wider uppercase text-cyan-400">LIVE ANALYSIS:</span>
        <span>Results generated from uploaded PCAP.</span>
      </div>
      {filename && (
        <div className="hidden md:flex items-center gap-2 font-mono text-[11px] text-cyan-400/90">
          <span className="text-slate-400">Target File:</span>
          <span className="bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">{filename}</span>
        </div>
      )}
    </div>
  );
}
