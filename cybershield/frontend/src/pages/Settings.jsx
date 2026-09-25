import React, { useState } from 'react';
import { Settings as SettingsIcon, Moon, Bell, RefreshCw, Cpu, ShieldCheck } from 'lucide-react';

export default function Settings() {
  const [darkMode, setDarkMode] = useState(true);
  const [notifications, setNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [scanSensitivity, setScanSensitivity] = useState('Standard (15 Ports)');

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div className="space-y-1">
        <h1 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
          SOC Environment Settings
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          Configure detection parameters, telemetry preferences, and console behavior
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-6">
        {/* Toggle options */}
        <div className="space-y-4 divide-y divide-slate-800/80">
          <div className="flex items-center justify-between pt-2">
            <div className="space-y-0.5 font-mono">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Moon className="w-4 h-4 text-cyan-400" /> Dark SOC Mode
              </div>
              <p className="text-[11px] text-slate-500">
                High contrast deep navy/black theme optimized for SOC analysts
              </p>
            </div>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`w-11 h-6 rounded-full transition-colors relative ${
                darkMode ? 'bg-cyan-500' : 'bg-slate-700'
              }`}
            >
              <span
                className={`block w-4 h-4 rounded-full bg-slate-950 transition-transform absolute top-1 ${
                  darkMode ? 'right-1' : 'left-1'
                }`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between pt-4">
            <div className="space-y-0.5 font-mono">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Bell className="w-4 h-4 text-cyan-400" /> Real-Time Telemetry Alerts
              </div>
              <p className="text-[11px] text-slate-500">
                Trigger visual notifications when critical threat indicators occur
              </p>
            </div>
            <button
              onClick={() => setNotifications(!notifications)}
              className={`w-11 h-6 rounded-full transition-colors relative ${
                notifications ? 'bg-cyan-500' : 'bg-slate-700'
              }`}
            >
              <span
                className={`block w-4 h-4 rounded-full bg-slate-950 transition-transform absolute top-1 ${
                  notifications ? 'right-1' : 'left-1'
                }`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between pt-4">
            <div className="space-y-0.5 font-mono">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <RefreshCw className="w-4 h-4 text-cyan-400" /> Auto-Refresh Ledger
              </div>
              <p className="text-[11px] text-slate-500">
                Poll backend health and update dashboard history automatically
              </p>
            </div>
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`w-11 h-6 rounded-full transition-colors relative ${
                autoRefresh ? 'bg-cyan-500' : 'bg-slate-700'
              }`}
            >
              <span
                className={`block w-4 h-4 rounded-full bg-slate-950 transition-transform absolute top-1 ${
                  autoRefresh ? 'right-1' : 'left-1'
                }`}
              />
            </button>
          </div>
        </div>

        {/* Heuristic thresholds */}
        <div className="space-y-3 pt-4 border-t border-slate-800 font-mono text-xs">
          <div className="space-y-1">
            <span className="font-semibold text-slate-200 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" /> Port-Scan Detection Threshold
            </span>
            <p className="text-[11px] text-slate-500">
              Minimum unique destination ports targeted before flagging reconnaissance
            </p>
          </div>
          <select
            value={scanSensitivity}
            onChange={(e) => setScanSensitivity(e.target.value)}
            className="w-full px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option>Aggressive (8 Ports + SYN probes)</option>
            <option>Standard (15 Ports)</option>
            <option>Relaxed (30 Ports)</option>
          </select>
        </div>

        {/* System Information - Section 39 requirement */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between text-slate-300">
            <span className="font-semibold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" /> Application Details
            </span>
            <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              OPERATIONAL
            </span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1 pt-1">
            <div>Application: <strong className="text-white">CyberShield PCAP Analyzer</strong></div>
            <div>Version: <strong className="text-cyan-300">1.0.0</strong></div>
            <div>Engine Core: <span className="text-slate-300">Rule-Based Behavioral Dissection</span></div>
            <div>Database: <span className="text-slate-300">SQLite (cybershield.db)</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
