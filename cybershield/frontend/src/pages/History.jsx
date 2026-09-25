import React, { useState, useEffect } from 'react';
import { Search, Filter, Trash2, ArrowUpRight, Inbox, RefreshCw, FileText } from 'lucide-react';
import ThreatBadge from '../components/ThreatBadge';
import { formatDate, formatBytes } from '../utils/formatters';
import api from '../services/api';

export default function History({ onSelectAnalysis }) {
  const [history, setHistory] = useState([]);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [loading, setLoading] = useState(true);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory(search, severityFilter);
      setHistory(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [severityFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHistory();
  };

  const [deletingId, setDeletingId] = useState(null);
  const [historyError, setHistoryError] = useState(null);

  const handleDeleteClick = (id, e) => {
    e.stopPropagation();
    setDeletingId(id);
  };

  const handleConfirmDelete = async (id, e) => {
    e.stopPropagation();
    try {
      await api.deleteAnalysis(id);
      setHistory(prev => prev.filter(item => item.analysis_id !== id));
      setDeletingId(null);
    } catch (err) {
      setHistoryError(`Deletion failed: ${err.message}`);
      setDeletingId(null);
      setTimeout(() => setHistoryError(null), 4000);
    }
  };

  const handleCancelDelete = (e) => {
    e.stopPropagation();
    setDeletingId(null);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Historical Analysis Ledger
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Persistent audit history of parsed network captures and correlated findings
          </p>
        </div>

        <button
          onClick={fetchHistory}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-[#0a0f1d] border border-slate-800">
        <form onSubmit={handleSearchSubmit} className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search captures by filename or threat..."
            className="w-full pl-9 pr-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </form>

        {/* Severity Filter Tabs - Section 36 */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800 text-xs font-mono">
          {['all', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setSeverityFilter(f)}
              className={`px-3 py-1.5 rounded transition-colors uppercase text-[11px] font-medium ${
                severityFilter === f
                  ? 'bg-cyan-500/20 text-cyan-300 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* History Table */}
      <div className="p-5 rounded-2xl bg-[#0a0f1d] border border-slate-800">
        {loading ? (
          <div className="py-16 text-center text-xs text-slate-500 font-mono">
            Querying SQLite database ledger...
          </div>
        ) : history.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Inbox className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs text-slate-400 font-mono">
              No matching records found in audit ledger.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="pb-3">Capture File</th>
                  <th className="pb-3">Analysis Date</th>
                  <th className="pb-3">Packets</th>
                  <th className="pb-3">Classification</th>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Type</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {history.map((row) => (
                  <tr
                    key={row.analysis_id}
                    onClick={() => onSelectAnalysis(row.analysis_id)}
                    className="hover:bg-slate-900/50 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 font-semibold text-slate-200">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                        <span className="group-hover:text-cyan-300 transition-colors">{row.filename}</span>
                      </div>
                    </td>
                    <td className="py-3 text-slate-400">{formatDate(row.created_at)}</td>
                    <td className="py-3 text-slate-300">{row.total_packets?.toLocaleString()}</td>
                    <td className="py-3 font-bold text-white">{row.threat}</td>
                    <td className="py-3">
                      <ThreatBadge severity={row.severity} size="sm" />
                    </td>
                    <td className="py-3">
                      {row.is_demo ? (
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
                      <div className="flex items-center justify-end gap-2">
                        {deletingId === row.analysis_id ? (
                          <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={(e) => handleConfirmDelete(row.analysis_id, e)}
                              className="px-2 py-0.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-mono text-[10px]"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={handleCancelDelete}
                              className="px-2 py-0.5 rounded bg-slate-850 hover:bg-slate-700 text-slate-300 font-mono text-[10px]"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectAnalysis(row.analysis_id);
                              }}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 transition-colors text-[11px]"
                            >
                              View Report
                            </button>
                            <button
                              onClick={(e) => handleDeleteClick(row.analysis_id, e)}
                              title="Delete Record"
                              className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </>
                        )}
                      </div>
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
