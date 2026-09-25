import React, { useState, useEffect } from 'react';
import { 
  FileSearch, 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  UploadCloud, 
  ArrowUpRight, 
  FlaskConical,
  Inbox,
  AlertTriangle
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import ThreatBadge from '../components/ThreatBadge';
import { formatDate, formatBytes } from '../utils/formatters';
import api from '../services/api';

export default function Dashboard({ onNavigate, onSelectAnalysis, onDemoTrigger }) {
  const [stats, setStats] = useState({
    total_analyses: 0,
    pcap_files: 0,
    threats_detected: 0,
    high_risk_events: 0
  });
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const loadData = async () => {
      try {
        const [statsData, historyData] = await Promise.all([
          api.getStats().catch(() => ({ total_analyses: 0, pcap_files: 0, threats_detected: 0, high_risk_events: 0 })),
          api.getHistory('', 'all').catch(() => [])
        ]);
        if (mounted) {
          setStats(statsData);
          setRecentAnalyses(historyData.slice(0, 5));
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    loadData();
    return () => { mounted = false; };
  }, []);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-[#0c1322] via-[#0f172a] to-[#0c1322] border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="space-y-1.5 z-10">
          <div className="flex items-center gap-2 font-mono text-xs text-cyan-400 font-semibold tracking-wider">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            SECURITY OPERATIONS CONSOLE
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Network Threat Intelligence Overview
          </h1>
          <p className="text-xs text-slate-400 max-w-xl font-mono leading-relaxed">
            Real-time binary packet inspection, flow analysis, and evidence-grounded threat detection.
          </p>
        </div>

        <div className="flex items-center gap-3 z-10">
          <button
            onClick={() => onNavigate('analyze')}
            className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono tracking-wider uppercase transition-all shadow-[0_0_20px_rgba(6,182,212,0.3)] flex items-center gap-2"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Analyze PCAP</span>
          </button>
          <button
            onClick={onDemoTrigger}
            className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-amber-300 border border-amber-500/30 font-medium text-xs font-mono transition-colors flex items-center gap-2"
          >
            <FlaskConical className="w-4 h-4 text-amber-400" />
            <span>Demo Mode</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Analyses"
          value={stats.total_analyses}
          subtitle="Captures processed"
          icon={Layers}
          color="cyan"
          glow={true}
        />
        <MetricCard
          title="PCAP Files"
          value={stats.pcap_files}
          subtitle="Live uploaded captures"
          icon={FileSearch}
          color="emerald"
        />
        <MetricCard
          title="Threats Detected"
          value={stats.threats_detected}
          subtitle="Non-benign incidents"
          icon={ShieldAlert}
          color="amber"
        />
        <MetricCard
          title="High Risk Events"
          value={stats.high_risk_events}
          subtitle="High & Critical severity"
          icon={AlertTriangle}
          color="rose"
        />
      </div>

      {/* Recent Analyses Section */}
      <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800/90 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide font-mono uppercase">
              Recent Network Captures
            </h3>
            <p className="text-[11px] text-slate-400 font-mono">
              Direct audit trail of previously parsed and correlated captures
            </p>
          </div>
          {recentAnalyses.length > 0 && (
            <button
              onClick={() => onNavigate('history')}
              className="text-xs text-cyan-400 hover:underline font-mono flex items-center gap-1"
            >
              <span>View Full Ledger</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {loading ? (
          <div className="py-12 text-center text-xs text-slate-500 font-mono">
            Accessing database ledger...
          </div>
        ) : recentAnalyses.length === 0 ? (
          /* Empty State - Section 33 requirement */
          <div className="py-12 text-center space-y-3 bg-slate-950/40 rounded-xl border border-dashed border-slate-800">
            <Inbox className="w-10 h-10 text-slate-600 mx-auto" />
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-slate-300 font-mono">
                No analyses recorded yet
              </h4>
              <p className="text-xs text-slate-500 max-w-sm mx-auto font-mono">
                Upload a real .pcap or .pcapng file to perform packet dissection, or launch Demo Mode to explore sample telemetry.
              </p>
            </div>
            <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
              <button
                onClick={() => onNavigate('analyze')}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shadow-[0_0_10px_rgba(6,182,212,0.3)]"
              >
                Upload PCAP
              </button>
              <button
                onClick={onDemoTrigger}
                className="px-3.5 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono transition-colors"
              >
                Run Demo Scenario
              </button>
            </div>
          </div>
        ) : (
          /* Real Analysis Table */
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="pb-3 font-semibold">Capture File</th>
                  <th className="pb-3 font-semibold">Timestamp</th>
                  <th className="pb-3 font-semibold">Packets</th>
                  <th className="pb-3 font-semibold">Classification</th>
                  <th className="pb-3 font-semibold">Severity Risk</th>
                  <th className="pb-3 font-semibold">Mode</th>
                  <th className="pb-3 font-semibold text-right">Dossier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentAnalyses.map((item) => (
                  <tr 
                    key={item.analysis_id} 
                    className="hover:bg-slate-900/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectAnalysis(item.analysis_id)}
                  >
                    <td className="py-3 font-medium text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-400">{item.filename}</span>
                      </div>
                    </td>
                    <td className="py-3 text-slate-400">{formatDate(item.created_at)}</td>
                    <td className="py-3 text-slate-300">{item.total_packets.toLocaleString()}</td>
                    <td className="py-3 font-semibold text-white">{item.threat}</td>
                    <td className="py-3">
                      <ThreatBadge severity={item.severity} size="sm" />
                    </td>
                    <td className="py-3">
                      {item.is_demo ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/40">
                          DEMO
                        </span>
                      ) : (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
                          LIVE
                        </span>
                      )}
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAnalysis(item.analysis_id);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 transition-colors text-[11px]"
                      >
                        Inspect Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
