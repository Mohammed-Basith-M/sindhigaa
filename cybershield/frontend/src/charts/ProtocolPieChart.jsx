import React, { useState } from 'react';

export default function ProtocolPieChart({ protocols = {} }) {
  const [hovered, setHovered] = useState(null);

  const data = [
    { name: 'TCP', count: protocols.TCP || 0, color: '#06b6d4' },
    { name: 'UDP', count: protocols.UDP || 0, color: '#3b82f6' },
    { name: 'ICMP', count: protocols.ICMP || 0, color: '#a855f7' },
    { name: 'Other', count: protocols.OTHER || 0, color: '#64748b' }
  ].filter(d => d.count > 0);

  const total = data.reduce((acc, cur) => acc + cur.count, 0);

  if (total === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-mono">
        No protocol telemetry available
      </div>
    );
  }

  // Calculate SVG donut slices
  let accumulatedAngle = 0;
  const slices = data.map((item, idx) => {
    const percentage = item.count / total;
    const angle = percentage * 360;
    const startAngle = accumulatedAngle;
    accumulatedAngle += angle;
    const endAngle = accumulatedAngle;

    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (endAngle - 90) * (Math.PI / 180);

    const r = 70;
    const innerR = 45;
    const cx = 100;
    const cy = 100;

    const x1 = cx + r * Math.cos(startRad);
    const y1 = cy + r * Math.sin(startRad);
    const x2 = cx + r * Math.cos(endRad);
    const y2 = cy + r * Math.sin(endRad);

    const x3 = cx + innerR * Math.cos(endRad);
    const y3 = cy + innerR * Math.sin(endRad);
    const x4 = cx + innerR * Math.cos(startRad);
    const y4 = cy + innerR * Math.sin(startRad);

    const largeArc = angle > 180 ? 1 : 0;

    const pathData = [
      `M ${x1} ${y1}`,
      `A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`,
      `L ${x3} ${y3}`,
      `A ${innerR} ${innerR} 0 ${largeArc} 0 ${x4} ${y4}`,
      'Z'
    ].join(' ');

    return {
      ...item,
      percentage: Math.round(percentage * 100),
      pathData
    };
  });

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6 p-4">
      {/* Donut Graphic */}
      <div className="relative w-48 h-48 shrink-0 flex items-center justify-center">
        <svg viewBox="0 0 200 200" className="w-full h-full transform -rotate-90">
          {slices.map((slice, idx) => (
            <path
              key={idx}
              d={slice.pathData}
              fill={slice.color}
              className="transition-all duration-200 cursor-pointer opacity-90 hover:opacity-100 hover:scale-[1.03] origin-center"
              onMouseEnter={() => setHovered(slice)}
              onMouseLeave={() => setHovered(null)}
            />
          ))}
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
            {hovered ? hovered.name : 'Total'}
          </span>
          <span className="text-sm font-bold font-mono text-white">
            {hovered ? `${hovered.percentage}%` : total}
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            {hovered ? `${hovered.count} pkts` : 'packets'}
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex-1 w-full space-y-2">
        {data.map((item, idx) => {
          const pct = Math.round((item.count / total) * 100);
          return (
            <div
              key={idx}
              className={`p-2 rounded-lg flex items-center justify-between text-xs font-mono transition-colors ${
                hovered?.name === item.name ? 'bg-slate-800/80 border border-slate-700' : 'bg-slate-900/50'
              }`}
              onMouseEnter={() => setHovered({ ...item, percentage: pct })}
              onMouseLeave={() => setHovered(null)}
            >
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-200 font-medium">{item.name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-slate-400">{item.count}</span>
                <span className="text-cyan-400 font-semibold w-9 text-right">{pct}%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
