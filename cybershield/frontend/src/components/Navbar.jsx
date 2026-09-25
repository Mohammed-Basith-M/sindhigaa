import React, { useState, useEffect } from 'react';
import { Shield, Radio, User, LogOut, Terminal, Bell } from 'lucide-react';
import api from '../services/api';

export default function Navbar({ user, onLogout, onNavigate }) {
  const [backendHealth, setBackendHealth] = useState('checking');

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const res = await api.checkHealth();
        if (mounted) {
          setBackendHealth(res.status === 'ok' ? 'online' : 'offline');
        }
      } catch {
        if (mounted) setBackendHealth('offline');
      }
    };

    check();
    const interval = setInterval(check, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#0a0f1d]/90 backdrop-blur-md sticky top-0 z-30 px-4 md:px-6 flex items-center justify-between">
      {/* Brand */}
      <div 
        onClick={() => onNavigate('dashboard')} 
        className="flex items-center gap-3 cursor-pointer group"
      >
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.15)] group-hover:border-cyan-400 transition-colors">
          <Shield className="w-5 h-5 text-cyan-400 transition-transform group-hover:scale-105" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-base tracking-wider text-white">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </span>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/40">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block tracking-wide">
            PCAP Threat Intelligence & Network Analysis
          </p>
        </div>
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-4">
        {/* Backend Heartbeat */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-xs font-mono">
          <span className={`w-2 h-2 rounded-full ${
            backendHealth === 'online' ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 
            backendHealth === 'checking' ? 'bg-amber-400 animate-pulse' : 'bg-rose-500'
          }`} />
          <span className="text-slate-400 text-[11px]">
            {backendHealth === 'online' ? 'Engine: Ready' : backendHealth === 'checking' ? 'Connecting...' : 'Engine: Offline'}
          </span>
        </div>

        {/* User Badge */}
        {user && (
          <div className="flex items-center gap-3 pl-2 border-l border-slate-800">
            <div 
              onClick={() => onNavigate('profile')} 
              className="flex items-center gap-2.5 cursor-pointer hover:opacity-85 transition-opacity"
            >
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-mono text-xs font-semibold">
                {user.email ? user.email.slice(0, 2).toUpperCase() : 'SOC'}
              </div>
              <div className="hidden lg:block text-left text-xs">
                <div className="text-slate-200 font-medium truncate max-w-[130px]">{user.name || 'SOC Analyst'}</div>
                <div className="text-slate-500 text-[10px] font-mono">CLEARANCE: L3</div>
              </div>
            </div>

            <button
              onClick={onLogout}
              title="Sign Out"
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
