/**
 * CyberShield Formatting Utilities
 */

export function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatDuration(seconds) {
  if (seconds === undefined || seconds === null) return '0.00s';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = (seconds % 60).toFixed(1);
  return `${mins}m ${secs}s`;
}

export function formatDate(timestamp) {
  if (!timestamp) return 'Just now';
  const d = new Date(typeof timestamp === 'number' && timestamp < 1e11 ? timestamp * 1000 : timestamp);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

export function getSeverityStyle(severity) {
  const s = (severity || 'BENIGN').toUpperCase();
  switch (s) {
    case 'CRITICAL':
      return {
        bg: 'bg-rose-950/60',
        text: 'text-rose-400',
        border: 'border-rose-500/40',
        badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
        glow: 'shadow-[0_0_15px_rgba(244,63,94,0.25)]',
        color: '#f43f5e'
      };
    case 'HIGH':
      return {
        bg: 'bg-red-950/50',
        text: 'text-red-400',
        border: 'border-red-500/30',
        badge: 'bg-red-500/10 text-red-400 border-red-500/30',
        glow: 'shadow-[0_0_12px_rgba(239,68,68,0.2)]',
        color: '#ef4444'
      };
    case 'MEDIUM':
      return {
        bg: 'bg-amber-950/50',
        text: 'text-amber-400',
        border: 'border-amber-500/30',
        badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        glow: 'shadow-[0_0_10px_rgba(245,158,11,0.15)]',
        color: '#f59e0b'
      };
    case 'LOW':
      return {
        bg: 'bg-blue-950/40',
        text: 'text-blue-400',
        border: 'border-blue-500/30',
        badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
        glow: 'shadow-[0_0_8px_rgba(59,130,246,0.15)]',
        color: '#3b82f6'
      };
    case 'BENIGN':
    default:
      return {
        bg: 'bg-emerald-950/40',
        text: 'text-emerald-400',
        border: 'border-emerald-500/30',
        badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        glow: 'shadow-[0_0_8px_rgba(16,185,129,0.15)]',
        color: '#10b981'
      };
  }
}
