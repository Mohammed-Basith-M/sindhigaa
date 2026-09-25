import React, { useState } from 'react';
import { formatBytes } from '../utils/formatters';

export default function TrafficTimelineChart({ timeline = [] }) {
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [metric, setMetric] = useState('packets'); // 'packets' or 'bytes'

  if (!timeline || timeline.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-xs text-slate-500 font-mono">
        No traffic timeline points recorded.
      </div>
    );
  }

  const values = timeline.map(d => metric === 'packets' ? (d.packets || 0) : (d.bytes || 0));
  const maxVal = Math.max(...values, 1);
  const chartHeight = 140;
  const chartWidth = 500;
  const paddingX = 20;
  const paddingY = 15;
  const innerW = chartWidth - paddingX * 2;
  const innerH = chartHeight - paddingY * 2;

  // Generate SVG path points
  const points = timeline.map((d, i) => {
    const val = metric === 'packets' ? (d.packets || 0) : (d.bytes || 0);
    const x = paddingX + (i / Math.max(timeline.length - 1, 1)) * innerW;
    const y = paddingY + innerH - (val / maxVal) * innerH;
    return { x, y, data: d, val };
  });

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
  const areaPath = `${linePath} L ${points[points.length - 1].x} ${paddingY + innerH} L ${points[0].x} ${paddingY + innerH} Z`;

  const hoveredPoint = hoveredIndex !== null ? points[hoveredIndex] : null;

  return (
    <div className="p-4 space-y-3">
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-slate-400">
          Peak: <span className="text-cyan-400 font-semibold">{metric === 'packets' ? `${maxVal} pkts` : formatBytes(maxVal)}</span>
        </div>
        <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800 text-[11px] font-mono">
          <button
            onClick={() => setMetric('packets')}
            className={`px-2.5 py-1 rounded transition-colors ${
              metric === 'packets' ? 'bg-cyan-500/20 text-cyan-300 font-medium' : 'text-slate-400 hover:text-white'
            }`}
          >
            Packets / Time
          </button>
          <button
            onClick={() => setMetric('bytes')}
            className={`px-2.5 py-1 rounded transition-colors ${
              metric === 'bytes' ? 'bg-cyan-500/20 text-cyan-300 font-medium' : 'text-slate-400 hover:text-white'
            }`}
          >
            Bytes / Time
          </button>
        </div>
      </div>

      {/* SVG Chart */}
      <div className="relative w-full h-44 bg-slate-950/60 rounded-xl border border-slate-800/80 p-2 overflow-hidden">
        <svg 
          viewBox={`0 0 ${chartWidth} ${chartHeight}`} 
          className="w-full h-full overflow-visible"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="cyberGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={paddingX} y1={paddingY} x2={chartWidth - paddingX} y2={paddingY} stroke="#1e293b" strokeDasharray="3 3" />
          <line x1={paddingX} y1={paddingY + innerH / 2} x2={chartWidth - paddingX} y2={paddingY + innerH / 2} stroke="#1e293b" strokeDasharray="3 3" />
          <line x1={paddingX} y1={paddingY + innerH} x2={chartWidth - paddingX} y2={paddingY + innerH} stroke="#334155" />

          {/* Area & Line */}
          <path d={areaPath} fill="url(#cyberGradient)" />
          <path d={linePath} fill="none" stroke="#06b6d4" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />

          {/* Interactive Points */}
          {points.map((p, i) => (
            <circle
              key={i}
              cx={p.x}
              cy={p.y}
              r={hoveredIndex === i ? 5 : 2.5}
              fill={hoveredIndex === i ? '#ffffff' : '#06b6d4'}
              stroke="#0891b2"
              strokeWidth="1.5"
              className="cursor-pointer transition-all"
              onMouseEnter={() => setHoveredIndex(i)}
            />
          ))}

          {/* Active Crosshair */}
          {hoveredPoint && (
            <line
              x1={hoveredPoint.x}
              y1={paddingY}
              x2={hoveredPoint.x}
              y2={paddingY + innerH}
              stroke="#22d3ee"
              strokeDasharray="2 2"
              strokeWidth="1"
            />
          )}
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredPoint && (
          <div 
            className="absolute top-2 left-1/2 transform -translate-x-1/2 bg-slate-900/95 border border-cyan-500/40 px-3 py-1.5 rounded-lg shadow-xl text-xs font-mono z-10 flex items-center gap-3 pointer-events-none"
          >
            <span className="text-slate-400">{hoveredPoint.data.time_offset}</span>
            <span className="text-cyan-300 font-bold">
              {metric === 'packets' ? `${hoveredPoint.data.packets} packets` : formatBytes(hoveredPoint.data.bytes)}
            </span>
            <span className="text-[11px] text-slate-500">
              TCP: {hoveredPoint.data.tcp || 0} · UDP: {hoveredPoint.data.udp || 0}
            </span>
          </div>
        )}
      </div>

      {/* Axis Labels */}
      <div className="flex justify-between text-[10px] font-mono text-slate-500 px-2">
        <span>{timeline[0]?.time_offset || '+0.0s'}</span>
        <span>{timeline[Math.floor(timeline.length / 2)]?.time_offset || ''}</span>
        <span>{timeline[timeline.length - 1]?.time_offset || ''}</span>
      </div>
    </div>
  );
}
