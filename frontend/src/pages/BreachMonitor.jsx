import React, { useState, useEffect } from 'react';
import { Database, Search, AlertCircle, ExternalLink, ShieldAlert, CheckCircle, Clock, ShieldCheck, Info } from 'lucide-react';
import { threatIntelService } from '../services/api';

const CATEGORY_TABS = [
  { id: 'All', label: 'All Breach & Leak Disclosures' },
  { id: 'Data Breach', label: 'Confirmed Data Breaches' },
  { id: 'Data Leak', label: 'Data Leaks & Exposures' },
  { id: 'Unverified Threat-Actor Claim', label: 'Dark-Web Threat-Actor Claims' }
];

const BreachMonitor = () => {
  const [breaches, setBreaches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');

  const fetchBreaches = async () => {
    try {
      setLoading(true);
      const params = {
        search: search || undefined,
        limit: 100
      };
      if (activeCategory !== 'All') {
        params.category = activeCategory;
      }
      const res = await threatIntelService.getThreats(params);
      const allInc = res.incidents || [];
      // If 'All', include Data Breach, Data Leak, and Unverified Threat-Actor Claim
      const filtered = activeCategory === 'All'
        ? allInc.filter((i) => ['Data Breach', 'Data Leak', 'Unverified Threat-Actor Claim', 'Ransomware'].includes(i.category))
        : allInc;
      setBreaches(filtered);
    } catch (err) {
      console.error('Failed to load breach monitor:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBreaches();
  }, [activeCategory]);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchBreaches();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 uppercase tracking-wider">
          Enterprise Security Monitoring
        </span>
        <h2 className="text-xl font-bold text-white mt-1">Data Breach & Exposure Intelligence</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Tracks verified customer records, credential exposures, cloud bucket leaks (e.g. Zoomcar, Snowflake), and dark-web claims with rigorous evidence corroboration.
        </p>
      </div>

      {/* Ethics & Legal Compliance Notice */}
      <div className="p-3.5 rounded-lg border border-slate-800 bg-cyber-900/60 flex items-start gap-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <span className="font-semibold text-white font-mono text-[11px] uppercase tracking-wide">
            Ethical Intelligence Standard
          </span>
          <p className="text-slate-400 leading-relaxed">
            The platform monitors public disclosures, regulatory filings, and verified security publications. It never scrapes private dark-web forums, purchases stolen databases, or exposes raw compromised personal data. All dark-web forum advertisements are strictly categorized as <em>Unverified Threat-Actor Claims</em> unless independently corroborated.
          </p>
        </div>
      </div>

      {/* Search & Tabs */}
      <div className="glass-panel p-4 space-y-3">
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search breaches (e.g. Zoomcar, Snowflake, Customer records)..."
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2 rounded-lg text-xs font-bold font-mono bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110"
          >
            SEARCH
          </button>
        </form>

        <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/80">
          {CATEGORY_TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveCategory(tab.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                activeCategory === tab.id
                  ? 'bg-amber-500 text-cyber-950 font-bold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Breach Records List */}
      <div className="space-y-4">
        {loading ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">RETRIEVING BREACH RECORDS...</p>
          </div>
        ) : breaches.length > 0 ? (
          breaches.map((b) => (
            <div key={b.incident_id} className="glass-panel p-5 border-slate-800 space-y-3 hover:border-slate-700 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    b.category === 'Unverified Threat-Actor Claim'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                      : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                  }`}>
                    {b.category}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    b.verification_status === 'Confirmed'
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : b.verification_status === 'Unverified'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  }`}>
                    {b.verification_status} ({b.confidence_score}%)
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    DISCLOSED: {b.date_reported}
                  </span>
                </div>
                <div className="text-xs font-mono text-cyan-400 font-semibold">
                  {b.company} ({b.country})
                </div>
              </div>

              <div>
                <h3 className="text-sm font-bold text-white">{b.title}</h3>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">{b.description}</p>
              </div>

              {b.affected_users && (
                <div className="p-2.5 rounded bg-cyber-950 border border-slate-800 text-xs font-mono text-amber-300">
                  <span className="text-slate-500 font-bold">EXPOSURE VOLUME: </span>
                  <span>{b.affected_users}</span>
                </div>
              )}

              <div className="pt-2 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono text-slate-400">
                <div>
                  <span>Source: </span>
                  <span className="text-slate-300">{b.source_publication}</span>
                </div>
                {b.direct_source_link && (
                  <a
                    href={b.direct_source_link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5"
                  >
                    <span>Verification Reference</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="glass-panel p-8 text-center text-xs text-slate-500">
            No breach records found matching your query.
          </div>
        )}
      </div>
    </div>
  );
};

export default BreachMonitor;
