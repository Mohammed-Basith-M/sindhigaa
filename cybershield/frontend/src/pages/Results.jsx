import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  Clock, 
  Activity, 
  ArrowLeft, 
  Download, 
  Layers, 
  Server, 
  Share2,
  Sparkles,
  HelpCircle,
  AlertTriangle
} from 'lucide-react';
import StatusBanner from '../components/StatusBanner';
import ThreatBadge from '../components/ThreatBadge';
import EvidenceList from '../components/EvidenceList';
import RemediationCard from '../components/RemediationCard';
import MetricCard from '../components/MetricCard';
import ProtocolPieChart from '../charts/ProtocolPieChart';
import TrafficTimelineChart from '../charts/TrafficTimelineChart';
import TopIPsBarChart from '../charts/TopIPsBarChart';
import TopPortsBarChart from '../charts/TopPortsBarChart';
import SuspiciousTimeline from '../charts/SuspiciousTimeline';
import { formatDate, formatBytes, formatDuration, getSeverityStyle } from '../utils/formatters';

export default function Results({ analysis, onNavigateBack }) {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'traffic', 'evidence', 'remediation'

  if (!analysis) {
    return (
      <div className="p-12 text-center text-xs text-slate-500 font-mono">
        No analysis data loaded.
      </div>
    );
  }

  const {
    analysis_id,
    filename,
    file_size,
    created_at,
    is_demo,
    threat,
    severity,
    confidence,
    evidence = [],
    summary = {},
    protocols = {},
    top_source_ips = [],
    top_ports = [],
    suspicious_ips = [],
    attack_summary = [],
    timeline = [],
    timeline_events = [],
    xai = {},
    remediation = {}
  } = analysis;

  const style = getSeverityStyle(severity);

  const downloadJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `cybershield_dossier_${analysis_id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Permanent Status Banner - Section 29 */}
      <StatusBanner isDemo={is_demo} filename={filename} />

      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Navigation & Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <button
            onClick={onNavigateBack}
            className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Dashboard</span>
          </button>

          <div className="flex items-center gap-3">
            <button
              onClick={downloadJSON}
              className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-300 hover:text-white transition-colors flex items-center gap-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Dossier (JSON)</span>
            </button>
          </div>
        </div>

        {/* Dossier Header Card */}
        <div className={`p-6 rounded-2xl bg-[#0c1222] border ${style.border} shadow-xl relative overflow-hidden`}>
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <span>PCAP Analysis Report</span>
                <span>·</span>
                <span className="text-cyan-400 font-semibold">ID: {analysis_id}</span>
                <span>·</span>
                <span>{formatDate(created_at)}</span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight font-mono">
                {filename}
              </h1>
              <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400 pt-1">
                <span>Size: <strong className="text-slate-200">{formatBytes(file_size)}</strong></span>
                <span>·</span>
                <span>Capture Duration: <strong className="text-slate-200">{formatDuration(summary.duration_seconds)}</strong></span>
                <span>·</span>
                <span>Avg Rate: <strong className="text-slate-200">{summary.packets_per_second} pkt/s</strong></span>
              </div>
            </div>

            {/* Severity & Evidence-Based Confidence Card */}
            <div className={`p-4 rounded-xl bg-slate-950/60 border ${style.border} flex items-center gap-6 min-w-[280px]`}>
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">
                  Threat Classification
                </span>
                <div className="text-xl font-bold text-white font-mono flex items-center gap-2">
                  <ThreatBadge severity={severity} size="md" />
                </div>
                <div className="text-xs font-semibold text-slate-300 font-mono">
                  {threat}
                </div>
              </div>

              <div className="pl-6 border-l border-slate-800 space-y-1">
                <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">
                  Confidence
                </span>
                <div className="text-lg font-bold font-mono text-cyan-300">
                  {confidence !== null && confidence !== undefined ? `${(confidence * 100).toFixed(0)}%` : 'Not available'}
                </div>
                <span className="text-[9px] font-mono text-slate-500 block">
                  Evidence-based confidence
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Telemetry Summary Metric Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Total Packets"
            value={summary.total_packets?.toLocaleString() || 0}
            subtitle={`${summary.packets_per_second || 0} packets/sec`}
            icon={Layers}
            color="cyan"
          />
          <MetricCard
            title="Total Bytes"
            value={formatBytes(summary.total_bytes)}
            subtitle={`Throughput: ${formatBytes(summary.bytes_per_second)}/s`}
            icon={Activity}
            color="blue"
          />
          <MetricCard
            title="Active Flows"
            value={summary.total_flows?.toLocaleString() || 0}
            subtitle="5-tuple conversations"
            icon={Server}
            color="purple"
          />
          <MetricCard
            title="Destination Ports"
            value={analysis.unique_destination_ports || 0}
            subtitle="Targeted service sockets"
            icon={ShieldAlert}
            color="amber"
          />
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1 border-b border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2.5 font-medium border-b-2 transition-all ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Threat Dossier & XAI
          </button>
          <button
            onClick={() => setActiveTab('traffic')}
            className={`px-4 py-2.5 font-medium border-b-2 transition-all ${
              activeTab === 'traffic'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Traffic Distributions & Flow
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`px-4 py-2.5 font-medium border-b-2 transition-all ${
              activeTab === 'evidence'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Suspicious Sockets & Events
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`px-4 py-2.5 font-medium border-b-2 transition-all ${
              activeTab === 'remediation'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Remedial Playbooks
          </button>
        </div>

        {/* TAB 1: OVERVIEW & EXPLAINABLE ANALYSIS */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Section 16 & 17: EXPLAINABLE ANALYSIS (XAI) */}
            <div className="p-6 rounded-2xl bg-[#0a0f1d] border border-cyan-500/30 space-y-4 shadow-[0_0_20px_rgba(6,182,212,0.06)]">
              <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold uppercase tracking-wider">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>Explainable Threat Analysis (XAI)</span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-wide font-mono">
                Why was this traffic classified this way?
              </h2>

              {/* Observed Features Grid */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                  Important Observed Telemetry Features:
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  {Object.entries(xai.observed_features || {}).map(([key, val]) => (
                    <div key={key} className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase block truncate">
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span className="text-sm font-bold text-cyan-300">
                        {typeof val === 'number' ? val.toLocaleString() : String(val)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dynamic Generated Explanation */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider font-semibold block">
                  Ground-Truth Reasoning:
                </span>
                <p className="text-xs text-slate-200 leading-relaxed font-mono">
                  {xai.explanation || 'Traffic analysis concluded based on heuristic signatures.'}
                </p>
              </div>
            </div>

            {/* Verifiable Evidence Dossier */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-3">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Verifiable Packet Evidence</span>
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Observed behavioral anomalies extracted directly from packet streams:
                </p>
                <EvidenceList evidence={evidence} />
              </div>

              {/* Attack Summary Table - Section 21 */}
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-3">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Attack Summary Matrix</span>
                </h3>
                {attack_summary.length === 0 ? (
                  <div className="text-xs text-slate-400 font-mono py-6 text-center italic">
                    No suspicious activity was identified by the implemented detection rules.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                          <th className="pb-2">Attack Type</th>
                          <th className="pb-2">Severity</th>
                          <th className="pb-2">Confidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {attack_summary.map((atk, idx) => (
                          <tr key={idx}>
                            <td className="py-2.5 font-semibold text-white">{atk.attack_type}</td>
                            <td className="py-2.5">
                              <ThreatBadge severity={atk.severity} size="sm" />
                            </td>
                            <td className="py-2.5 text-cyan-400 font-bold">
                              {atk.confidence !== null ? `${(atk.confidence * 100).toFixed(0)}%` : 'N/A'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: TRAFFIC & FLOWS */}
        {activeTab === 'traffic' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Protocol Distribution */}
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-2">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                  Protocol Distribution
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Layer-3 / Layer-4 packet protocol composition
                </p>
                <ProtocolPieChart protocols={protocols} />
              </div>

              {/* Traffic Velocity Timeline */}
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-2">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                  Traffic Velocity Timeline
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Volume transmission rate across binned intervals
                </p>
                <TrafficTimelineChart timeline={timeline} />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Top Source IPs */}
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-2">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                  Top Source IP Addresses
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Highest volume packet transmitters
                </p>
                <TopIPsBarChart ips={top_source_ips} />
              </div>

              {/* Top Destination Ports */}
              <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-2">
                <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                  Top Destination Service Ports
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Targeted service sockets and port frequencies
                </p>
                <TopPortsBarChart ports={top_ports} />
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: SUSPICIOUS SOCKETS & TIMELINE */}
        {activeTab === 'evidence' && (
          <div className="space-y-6">
            {/* Real Suspicious IP Table - Section 20 */}
            <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>Suspicious IP & Conversation Sockets</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Actual host-to-host conversations correlating with threat behavior
              </p>

              {suspicious_ips.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500 font-mono italic">
                  No anomalous socket pairs flagged in this capture.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                        <th className="pb-2 font-semibold">Source IP</th>
                        <th className="pb-2 font-semibold">Destination IP</th>
                        <th className="pb-2 font-semibold">Port Sockets</th>
                        <th className="pb-2 font-semibold">Protocol</th>
                        <th className="pb-2 font-semibold">Packets</th>
                        <th className="pb-2 font-semibold">Threat Rule</th>
                        <th className="pb-2 font-semibold">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {suspicious_ips.map((row, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/50">
                          <td className="py-2.5 font-bold text-cyan-300">{row.source_ip}</td>
                          <td className="py-2.5 text-slate-200">{row.destination_ip}</td>
                          <td className="py-2.5 text-slate-400">
                            {row.source_port} → <strong className="text-white">{row.destination_port}</strong>
                          </td>
                          <td className="py-2.5 text-slate-300">{row.protocol}</td>
                          <td className="py-2.5 text-slate-400">{row.packets}</td>
                          <td className="py-2.5 text-rose-300 font-semibold">{row.threat}</td>
                          <td className="py-2.5">
                            <ThreatBadge severity={row.severity} size="sm" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Suspicious Event Timeline - Section 26 */}
            <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Chronological Incident Timeline</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Actual chronological sequence of detected packet capture events
              </p>
              <SuspiciousTimeline events={timeline_events} />
            </div>
          </div>
        )}

        {/* TAB 4: REMEDIATION */}
        {activeTab === 'remediation' && (
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
                Recommended Remedial Measures
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Evidence-driven mitigation actions formulated for SOC operators
              </p>
            </div>
            <RemediationCard remediation={remediation} />
          </div>
        )}
      </div>
    </div>
  );
}
