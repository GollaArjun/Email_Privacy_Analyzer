import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  Download,
  AlertCircle,
  FileText,
  RefreshCw,
} from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { reportsService } from '../services/api';

const AnalysisHistory = ({ onSelectReport }) => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('All');
  const [total, setTotal] = useState(0);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const params = {};
      if (selectedRisk !== 'All') params.risk_level = selectedRisk;
      if (search.trim()) params.search = search.trim();
      const data = await reportsService.list(params);
      setReports(data.reports || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [selectedRisk]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchReports();
  };

  const handleDelete = async (e, reportId) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this analysis report?')) return;
    try {
      await reportsService.delete(reportId);
      setReports((prev) => prev.filter((r) => r.report_id !== reportId));
      setTotal((prev) => Math.max(0, prev - 1));
    } catch (err) {
      alert('Failed to delete report.');
    }
  };

  const riskFilters = ['All', 'Critical', 'Very High', 'High', 'Moderate', 'Low'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
            Report Archive
          </span>
          <h2 className="text-xl font-bold text-white mt-1">Analysis History & Audits</h2>
          <p className="text-xs text-slate-400 mt-1">
            Searchable repository of past security inspections ({total} total scans)
          </p>
        </div>

        <button
          onClick={fetchReports}
          className="p-2 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by subject, sender email, or report ID..."
            className="w-full bg-cyber-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </form>

        {/* Risk Filter Buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {riskFilters.map((lvl) => (
            <button
              key={lvl}
              onClick={() => setSelectedRisk(lvl)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all whitespace-nowrap ${
                selectedRisk === lvl
                  ? 'bg-cyan-500 text-cyber-950 font-bold shadow-sm shadow-cyan-500/20'
                  : 'bg-slate-800/80 text-slate-400 hover:text-white border border-slate-700/60'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Reports Table */}
      <div className="glass-panel overflow-hidden">
        {loading ? (
          <div className="py-20 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">SEARCHING ARCHIVE...</p>
          </div>
        ) : reports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-cyber-950/80 text-[10px] font-mono uppercase tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Subject</th>
                  <th className="py-3 px-4">Sender</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4 font-mono">Score</th>
                  <th className="py-3 px-4">Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {reports.map((r) => {
                  const meta = r.email_metadata || {};
                  const risk = r.risk_assessment || {};
                  return (
                    <tr
                      key={r.report_id}
                      onClick={() => onSelectReport && onSelectReport(r.report_id)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3.5 px-4 font-sans font-medium text-white max-w-xs truncate">
                        {meta.subject || '(No Subject)'}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 max-w-[180px] truncate">
                        {meta.sender || 'Unknown'}
                      </td>
                      <td className="py-3.5 px-4">
                        <RiskBadge level={risk.risk_category} size="sm" />
                      </td>
                      <td className="py-3.5 px-4 font-bold" style={{ color: risk.category_color }}>
                        {risk.overall_score}/100
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {r.created_at ? new Date(r.created_at).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onSelectReport) onSelectReport(r.report_id);
                            }}
                            className="p-1.5 rounded text-cyan-400 hover:bg-cyan-500/10 border border-slate-700 hover:border-cyan-500/40"
                            title="Inspect report"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(e, r.report_id)}
                            className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-700 hover:border-red-500/40"
                            title="Delete report"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center text-slate-500 text-xs space-y-2">
            <History className="w-8 h-8 mx-auto text-slate-600" />
            <p>No analysis reports found matching the selected filters.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisHistory;
