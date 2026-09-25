import React from 'react';
import { 
  LayoutDashboard, 
  UploadCloud, 
  History, 
  ShieldAlert, 
  UserCheck, 
  Settings, 
  FlaskConical,
  ExternalLink
} from 'lucide-react';

export default function Sidebar({ currentPage, onNavigate, onDemoTrigger }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyze', label: 'Analyze PCAP', icon: UploadCloud, highlight: true },
    { id: 'history', label: 'History Ledger', icon: History },
    { id: 'threats', label: 'Threat Intel', icon: ShieldAlert },
    { id: 'profile', label: 'Analyst Profile', icon: UserCheck },
    { id: 'settings', label: 'SOC Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-slate-800/80 flex flex-col shrink-0 min-h-[calc(100vh-4rem)]">
      {/* Navigation */}
      <div className="p-4 space-y-1">
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 py-2">
          Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span className="tracking-wide">{item.label}</span>
              {item.highlight && !isActive && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              )}
            </button>
          );
        })}
      </div>

      {/* Quick Demo Section */}
      <div className="p-4 mt-auto">
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-2.5">
          <div className="flex items-center gap-2 text-amber-400 font-semibold font-mono text-[11px]">
            <FlaskConical className="w-4 h-4 text-amber-400" />
            <span>SANDBOX DEMO</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Test the SOC dashboard with simulated SYN reconnaissance telemetry.
          </p>
          <button
            onClick={onDemoTrigger}
            className="w-full py-1.5 px-3 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-medium transition-colors flex items-center justify-center gap-1.5"
          >
            <span>Launch Demo Mode</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        {/* Footer info */}
        <div className="mt-4 px-2 text-[10px] text-slate-600 font-mono flex items-center justify-between">
          <span>CyberShield Core</span>
          <span className="text-slate-500">College Prototype</span>
        </div>
      </div>
    </aside>
  );
}
