import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileCheck, 
  AlertCircle, 
  CheckCircle2, 
  Loader2, 
  ShieldAlert, 
  FileText,
  FlaskConical,
  ArrowRight
} from 'lucide-react';
import { formatBytes } from '../utils/formatters';
import api from '../services/api';

const STAGES = [
  { id: 'upload', label: 'Uploading PCAP capture file' },
  { id: 'parse', label: 'Parsing packet layers & protocols' },
  { id: 'features', label: 'Extracting 5-tuple network flows' },
  { id: 'detection', label: 'Running rule-based detection correlation' },
  { id: 'xai', label: 'Generating explainable feature attribution' },
  { id: 'remediation', label: 'Formulating prioritized remedial playbooks' }
];

export default function Analyze({ onAnalysisComplete, onDemoTrigger }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentStageIndex, setCurrentStageIndex] = useState(-1);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateFile = (file) => {
    setError(null);
    const validExtensions = ['.pcap', '.pcapng'];
    const name = file.name.toLowerCase();
    const isValidExt = validExtensions.some(ext => name.endsWith(ext));

    if (!isValidExt) {
      setError('Invalid file type. Only .pcap and .pcapng files are supported.');
      return false;
    }

    if (file.size > 50 * 1024 * 1024) {
      setError('File exceeds the 50 MB limit.');
      return false;
    }

    return true;
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  };

  const startAnalysis = async () => {
    if (!selectedFile) return;

    setIsProcessing(true);
    setError(null);
    setUploadProgress(0);
    setCurrentStageIndex(0);

    const stageTimer = setInterval(() => {
      setCurrentStageIndex((prev) => {
        if (prev < STAGES.length - 1) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      const result = await api.uploadPCAP(selectedFile, (pct) => {
        setUploadProgress(pct);
      });

      clearInterval(stageTimer);
      setCurrentStageIndex(STAGES.length - 1);
      setTimeout(() => {
        onAnalysisComplete(result);
      }, 500);
    } catch (err) {
      clearInterval(stageTimer);
      setIsProcessing(false);
      setError(err.message || 'PCAP analysis failed.');
    }
  };

  const handleRunSample = async (sampleName) => {
    setIsProcessing(true);
    setSelectedFile({ name: sampleName, size: 102400 });
    setError(null);
    setUploadProgress(100);
    setCurrentStageIndex(0);

    const stageTimer = setInterval(() => {
      setCurrentStageIndex((prev) => {
        if (prev < STAGES.length - 1) return prev + 1;
        return prev;
      });
    }, 380);

    try {
      const result = await api.analyzeSample(sampleName);
      clearInterval(stageTimer);
      setCurrentStageIndex(STAGES.length - 1);
      setTimeout(() => {
        onAnalysisComplete(result);
      }, 400);
    } catch (err) {
      clearInterval(stageTimer);
      setIsProcessing(false);
      setError(err.message || 'Sample analysis failed.');
    }
  };

  const sampleFiles = [
    { id: 'port_scan.pcap', name: 'Port Scan Recon', badge: 'CRITICAL', desc: '35 probed ports with SYN probes' },
    { id: 'dos_syn_flood.pcap', name: 'DoS / SYN Flood', badge: 'HIGH', desc: '>300 pkt/s targeting 10.0.0.50' },
    { id: 'ssh_brute_force.pcap', name: 'SSH Brute Force', badge: 'HIGH', desc: '18 attempts on Port 22' },
    { id: 'botnet_beacon.pcap', name: 'C2 Heartbeat', badge: 'MEDIUM', desc: 'Periodic 1.0s beacon intervals' },
    { id: 'normal_traffic.pcap', name: 'Clean HTTP / Web', badge: 'BENIGN', desc: 'Normal 3-way handshake traffic' },
    { id: 'insufficient_evidence.pcap', name: 'Low Packet Capture', badge: 'INFO', desc: '2 packets only (safe handling)' },
    { id: 'valid_test.pcapng', name: 'PCAPNG Binary', badge: 'PCAPNG', desc: 'Modern PCAPNG block format' }
  ];

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div className="space-y-1">
        <h1 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
          PCAP Threat Intelligence Analyzer
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          Upload network traffic captures (.pcap or .pcapng up to 50 MB) for real packet inspection
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 flex items-start gap-3 text-rose-300 text-xs font-mono">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-bold text-rose-400">Analysis Error:</span>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Upload Box */}
      {!isProcessing ? (
        <div className="space-y-4">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all ${
              dragActive 
                ? 'border-cyan-400 bg-cyan-950/20 shadow-[0_0_25px_rgba(6,182,212,0.2)]' 
                : 'border-slate-800 hover:border-slate-700 bg-[#0a0f1d]'
            }`}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".pcap,.pcapng"
              className="hidden"
              onChange={handleFileSelect}
            />

            <div className="space-y-4 max-w-md mx-auto">
              <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.15)]">
                <UploadCloud className="w-8 h-8 text-cyan-400" />
              </div>

              <div className="space-y-1">
                <h3 className="text-base font-bold text-white tracking-wide">
                  Drag and drop your network capture file here
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Supported formats: <span className="text-cyan-400 font-semibold">.pcap</span> and <span className="text-cyan-400 font-semibold">.pcapng</span> (Max: 50 MB)
                </p>
              </div>

              <button
                type="button"
                className="px-4 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:bg-slate-800 text-xs font-mono text-slate-200 transition-colors"
              >
                Browse Local Files
              </button>
            </div>
          </div>

          {/* Selected File Card */}
          {selectedFile && (
            <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-500/30 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                  <FileCheck className="w-5 h-5 text-cyan-400" />
                </div>
                <div className="space-y-0.5 text-xs font-mono">
                  <div className="text-slate-100 font-semibold">{selectedFile.name}</div>
                  <div className="text-slate-500">
                    {formatBytes(selectedFile.size)} · {selectedFile.name.endsWith('.pcapng') ? 'PCAP Next Generation' : 'Classic Libpcap'}
                  </div>
                </div>
              </div>

              <button
                onClick={startAnalysis}
                className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] flex items-center gap-2"
              >
                <span>Execute Deep Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Sample Captures Card */}
          <div className="p-4 rounded-xl bg-[#0c1222] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider flex items-center gap-2">
                <FlaskConical className="w-4 h-4 text-cyan-400" /> Pre-Synthesized Test Captures (1-Click Run)
              </span>
              <button
                onClick={onDemoTrigger}
                className="text-xs text-amber-400 hover:underline font-mono"
              >
                Launch Demo Scenario
              </button>
            </div>
            <p className="text-xs text-slate-400 font-mono leading-relaxed">
              Don't have a PCAP file ready on your machine? Click any scenario below to dissect actual binary packets immediately:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
              {sampleFiles.map((sf) => (
                <div
                  key={sf.id}
                  className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 transition-all flex items-center justify-between gap-3 text-xs font-mono"
                >
                  <div className="space-y-0.5 truncate">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-200">{sf.name}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {sf.badge}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 truncate">{sf.desc}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <a
                      href={api.getSampleDownloadUrl(sf.id)}
                      download={sf.id}
                      title="Download file to test manual upload"
                      className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 transition-colors text-[11px]"
                    >
                      DL
                    </a>
                    <button
                      onClick={() => handleRunSample(sf.id)}
                      className="px-2.5 py-1.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 font-semibold text-[11px] transition-colors"
                    >
                      Analyze
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        /* Multi-Stage Analysis Progress */
        <div className="p-8 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-6">
          <div className="space-y-2 text-center">
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center animate-pulse shadow-[0_0_25px_rgba(6,182,212,0.2)]">
              <Loader2 className="w-7 h-7 text-cyan-400 animate-spin" />
            </div>
            <h3 className="text-base font-bold text-white font-mono">
              Dissecting Network Capture
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Processing: <span className="text-cyan-300">{selectedFile?.name}</span> ({formatBytes(selectedFile?.size)})
            </p>
          </div>

          {/* Upload Bar */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono text-slate-400">
              <span>Transmission Progress</span>
              <span className="text-cyan-400">{uploadProgress}%</span>
            </div>
            <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>

          {/* Multi-Stage Pipeline Indicator */}
          <div className="space-y-3 pt-2">
            {STAGES.map((stage, idx) => {
              const isDone = idx < currentStageIndex;
              const isCurrent = idx === currentStageIndex;
              return (
                <div
                  key={stage.id}
                  className={`p-3 rounded-lg flex items-center gap-3 text-xs font-mono transition-all ${
                    isDone
                      ? 'bg-emerald-950/20 border border-emerald-500/30 text-emerald-300'
                      : isCurrent
                      ? 'bg-cyan-950/30 border border-cyan-500/40 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                      : 'bg-slate-900/40 border border-slate-800/60 text-slate-600'
                  }`}
                >
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
                  ) : (
                    <span className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] text-slate-600 shrink-0">
                      {idx + 1}
                    </span>
                  )}
                  <span className="font-medium">{stage.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
