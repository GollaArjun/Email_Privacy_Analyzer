import React, { useState, useEffect } from 'react';
import { Radio, Search, ExternalLink, ShieldAlert, CheckCircle, RefreshCw, AlertTriangle } from 'lucide-react';
import { threatIntelService } from '../services/api';

const PhishingIntel = () => {
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchPhishingData = async () => {
    try {
      setLoading(true);
      const res = await threatIntelService.getPhishingIntel({
        search: search || undefined,
        limit: 100
      });
      setIndicators(res.indicators || []);
    } catch (err) {
      console.error('Failed to load phishing intelligence:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPhishingData();
  }, []);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchPhishingData();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase tracking-wider">
          Threat Indicator Stream
        </span>
        <h2 className="text-xl font-bold text-white mt-1">Phishing & Malicious URL Intelligence</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Live stream of verified credential-theft phishing URLs and deceptive hostnames synchronized from OpenPhish community feeds.
        </p>
      </div>

      {/* Search */}
      <div className="glass-panel p-4">
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search phishing indicator or domain (e.g. paypa1, micros0ft, github.io)..."
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2 rounded-lg text-xs font-bold font-mono bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110"
          >
            SEARCH IOCS
          </button>
        </form>
      </div>

      {/* Indicators List */}
      <div className="glass-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-white">
            Active Verified Phishing Indicators ({indicators.length})
          </h3>
          <span className="text-xs font-mono text-purple-400">SOURCE: OPENPHISH</span>
        </div>

        {loading ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">RETRIEVING PHISHING INDICATORS...</p>
          </div>
        ) : indicators.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800 bg-cyber-950/40">
                <tr>
                  <th className="py-2.5 px-3">Target Domain</th>
                  <th className="py-2.5 px-3">Malicious URL Indicator</th>
                  <th className="py-2.5 px-3">Threat Type</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3 text-right">Last Verified</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {indicators.map((ind, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-bold text-cyan-300 whitespace-nowrap">
                      {ind.domain || 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-red-300 max-w-md truncate select-all">
                      {ind.indicator_value}
                    </td>
                    <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                      {ind.threat_type || 'Phishing'}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                        {ind.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        {ind.confidence}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right text-slate-400 text-[11px] whitespace-nowrap">
                      {ind.last_seen ? new Date(ind.last_seen).toLocaleDateString() : 'Active'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs">
            No phishing indicators found matching query.
          </div>
        )}
      </div>
    </div>
  );
};

export default PhishingIntel;
