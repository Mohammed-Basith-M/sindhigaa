import React, { useState, useEffect } from 'react';
import { ShieldAlert, Shield, Layers, ArrowUpRight } from 'lucide-react';
import ThreatBadge from '../components/ThreatBadge';
import { formatDate } from '../utils/formatters';
import api from '../services/api';

const THREAT_CATEGORIES = [
  { id: 'Port Scan', label: 'Port Scan Reconnaissance', desc: 'Horizontal / vertical multi-port SYN probes' },
  { id: 'DoS/DDoS', label: 'Denial of Service / DDoS', desc: 'Volumetric packet rate spikes and SYN floods' },
  { id: 'Brute Force', label: 'Authentication Brute Force', desc: 'Repeated credential attempts on SSH, RDP, FTP' },
  { id: 'Possible Botnet/C2', label: 'Botnet & C2 Activity', desc: 'Low-jitter periodic beaconing heartbeats' },
  { id: 'Suspicious Connection', label: 'Suspicious / Trojan Sockets', desc: 'Direct engagement with backdoor exploitation ports' }
];

export default function Threats({ onSelectAnalysis }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api.getHistory('', 'all')
      .then(data => { if (mounted) setHistory(data); })
      .catch(console.error)
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  const threatsOnly = history.filter(h => h.threat !== 'Benign' && h.threat !== 'Insufficient Evidence');

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="space-y-1">
        <h1 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
          Threat Intelligence Correlation Matrix
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          Catalog of detected attack vectors across recorded network captures
        </p>
      </div>

      {loading ? (
        <div className="py-16 text-center text-xs text-slate-500 font-mono">
          Correlating threat intelligence matrix...
        </div>
      ) : threatsOnly.length === 0 ? (
        /* Section 37 requirement */
        <div className="p-12 text-center rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-3">
          <Shield className="w-10 h-10 text-emerald-400 mx-auto" />
          <h3 className="text-sm font-semibold text-white font-mono">
            No threat events recorded.
          </h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto font-mono">
            All stored captures are benign or contain insufficient evidence to classify an attack.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {THREAT_CATEGORIES.map((cat) => {
            const matches = threatsOnly.filter(t => t.threat === cat.id);
            if (matches.length === 0) return null;

            return (
              <div key={cat.id} className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyan-400" />
                      <span>{cat.label}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-normal">
                        {matches.length} incident{matches.length > 1 ? 's' : ''}
                      </span>
                    </h3>
                    <p className="text-[11px] text-slate-400 font-mono">{cat.desc}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {matches.map((item) => (
                    <div
                      key={item.analysis_id}
                      onClick={() => onSelectAnalysis(item.analysis_id)}
                      className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-cyan-500/40 transition-all cursor-pointer flex items-center justify-between font-mono text-xs"
                    >
                      <div className="space-y-1">
                        <div className="text-slate-200 font-semibold">{item.filename}</div>
                        <div className="text-slate-500 text-[11px]">
                          {formatDate(item.created_at)} · {item.total_packets} pkts
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <ThreatBadge severity={item.severity} size="sm" />
                        <ArrowUpRight className="w-4 h-4 text-slate-500 hover:text-cyan-400" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
