import React, { useState, useEffect } from 'react';
import {
  Radio,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Search,
  Filter,
  ShieldAlert,
  Server,
  Globe,
  Lock,
  Building,
  Clock,
  Info,
  X,
  Database,
  ArrowUpRight
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie
} from 'recharts';
import { threatIntelService } from '../services/api';

const CATEGORY_COLORS = {
  'Service Outage': '#3B82F6', // Blue (infrastructure, not cyberattack)
  'Cyberattack': '#EF4444',
  'Data Breach': '#F97316',
  'Ransomware': '#DC2626',
  'Data Leak': '#F59E0B',
  'Phishing Campaign': '#8B5CF6',
  'Malware Campaign': '#EC4899',
  'Vulnerability Disclosure': '#10B981',
  'Supply-Chain Compromise': '#E11D48',
  'Unverified Threat-Actor Claim': '#64748B' // Muted slate
};

const CONFIDENCE_BADGES = {
  'Confirmed': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  'Corroborated': 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  'Reported': 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  'Unverified': 'bg-slate-500/20 text-slate-400 border-slate-500/30'
};

const LiveThreats = () => {
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');

  // Filters
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedConfidence, setSelectedConfidence] = useState('All');
  const [selectedCountry, setSelectedCountry] = useState('All');

  // Modal Detail
  const [activeIncident, setActiveIncident] = useState(null);

  const fetchThreatData = async () => {
    try {
      setLoading(true);
      const [incRes, statsRes, srcRes] = await Promise.all([
        threatIntelService.getThreats({
          search: search || undefined,
          category: selectedCategory !== 'All' ? selectedCategory : undefined,
          confidence: selectedConfidence !== 'All' ? selectedConfidence : undefined,
          country: selectedCountry !== 'All' ? selectedCountry : undefined,
          limit: 100
        }),
        threatIntelService.getStatistics(),
        threatIntelService.getSources()
      ]);
      setIncidents(incRes.incidents || []);
      setStats(statsRes);
      setSources(srcRes.sources || []);
    } catch (err) {
      console.error('Failed to load threat intelligence:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
    // Auto-refresh feed every 5 minutes
    const interval = setInterval(fetchThreatData, 300000);
    return () => clearInterval(interval);
  }, [selectedCategory, selectedConfidence, selectedCountry]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchThreatData();
  };

  const handleManualSync = async () => {
    try {
      setSyncing(true);
      setSyncMsg('Polling live CISA, OpenPhish & incident feeds...');
      await threatIntelService.triggerSync();
      setTimeout(async () => {
        await fetchThreatData();
        setSyncing(false);
        setSyncMsg('Feeds synchronized successfully.');
        setTimeout(() => setSyncMsg(''), 4000);
      }, 3000);
    } catch (err) {
      setSyncing(false);
      setSyncMsg('Synchronization request failed.');
    }
  };

  // Check if data is older than 2 hours for stale data warning
  const isStale = stats?.last_synchronization
    ? (Date.now() - new Date(stats.last_synchronization).getTime()) > 7200000
    : false;

  return (
    <div className="space-y-6">
      {/* Live Operations Header */}
      <div className="glass-panel p-6 border-cyan-500/30 bg-gradient-to-r from-cyber-900 via-cyber-950 to-cyber-900 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 tracking-wider">
              LIVE CYBER THREAT OPERATIONS
            </span>
            <span className="text-xs font-mono text-slate-400">
              // 5-MIN AUTO-REFRESH
            </span>
          </div>

          <h2 className="text-xl font-bold text-white mt-2">
            Real-Time Cyber Incident & Threat Intelligence Center
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Continuous correlation of actively exploited vulnerabilities (CISA KEV), live verified phishing URLs (OpenPhish), corporate data breaches (Zoomcar, Snowflake), infrastructure service outages (Microsoft 365), and CERT-In advisories.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 shrink-0">
          <div className="text-right text-[11px] font-mono text-slate-400 hidden sm:block">
            <span>LAST SYNC: </span>
            <span className="text-cyan-400 font-bold">
              {stats?.last_synchronization
                ? new Date(stats.last_synchronization).toLocaleTimeString()
                : 'Connecting...'}
            </span>
          </div>

          <button
            onClick={handleManualSync}
            disabled={syncing}
            className="px-4 py-2 rounded-lg text-xs font-mono font-bold bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 flex items-center gap-2 transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'SYNCING FEEDS...' : 'SYNC LIVE FEEDS'}</span>
          </button>
        </div>
      </div>

      {syncMsg && (
        <div className="p-3 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 text-xs flex items-center gap-2">
          <Info className="w-4 h-4 shrink-0" />
          <span>{syncMsg}</span>
        </div>
      )}

      {isStale && (
        <div className="p-3 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>
            STALE DATA WARNING: Feeds were last synchronized over 2 hours ago. Click 'Sync Live Feeds' to update telemetry.
          </span>
        </div>
      )}

      {/* Key Live Threat Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel p-5 border-slate-800 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Total Verified Incidents</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {stats?.total_incidents || 0}
          </div>
          <p className="text-[11px] text-slate-500">Real-world tracked events</p>
        </div>

        <div className="glass-panel p-5 border-slate-800 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Actively Exploited (CISA)</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {stats?.total_exploited_vulnerabilities || 0}
          </div>
          <p className="text-[11px] text-slate-500">Known exploited CVEs</p>
        </div>

        <div className="glass-panel p-5 border-slate-800 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Active Phishing Lures</span>
            <Radio className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {stats?.total_threat_indicators || 0}
          </div>
          <p className="text-[11px] text-slate-500">Live verified URLs (OpenPhish)</p>
        </div>

        <div className="glass-panel p-5 border-slate-800 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Intelligence Feeds</span>
            <CheckCircle className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {stats?.sources_online || 0} / {sources.length || 3}
          </div>
          <p className="text-[11px] text-slate-500">Public feeds responding</p>
        </div>
      </div>

      {/* Visual Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Category Breakdown Bar Chart */}
        <div className="glass-panel p-5 lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Threat Category Distribution</h3>
              <p className="text-xs text-slate-400">10-tier strict categorization</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              CATEGORIES
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={stats?.categories || []}
                margin={{ top: 10, right: 10, left: -10, bottom: 25 }}
              >
                <XAxis
                  dataKey="name"
                  stroke="#64748b"
                  fontSize={10}
                  tickLine={false}
                  angle={-15}
                  textAnchor="end"
                />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {(stats?.categories || []).map((entry, index) => (
                    <Cell
                      key={`cat-cell-${index}`}
                      fill={CATEGORY_COLORS[entry.name] || '#38BDF8'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Affected Sectors Breakdown */}
        <div className="glass-panel p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Sector Vulnerability</h3>
              <p className="text-xs text-slate-400">Targeted industries</p>
            </div>
            <Building className="w-4 h-4 text-slate-500" />
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-60 pr-1">
            {(stats?.sectors || []).map((sec, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300 truncate max-w-[200px]">{sec.name}</span>
                  <span className="text-cyan-400 font-bold">{sec.count}</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-cyan-500 h-full rounded-full"
                    style={{
                      width: `${Math.min(100, (sec.count / (stats?.total_incidents || 1)) * 100)}%`
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Multi-Filter Search Bar */}
      <div className="glass-panel p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Search Box */}
          <div className="relative md:col-span-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title, company, CVE..."
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Category Filter */}
          <div>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Categories (10 Types)</option>
              <option value="Service Outage">Service Outage (Infrastructure)</option>
              <option value="Cyberattack">Cyberattack</option>
              <option value="Data Breach">Data Breach</option>
              <option value="Ransomware">Ransomware</option>
              <option value="Data Leak">Data Leak</option>
              <option value="Phishing Campaign">Phishing Campaign</option>
              <option value="Malware Campaign">Malware Campaign</option>
              <option value="Vulnerability Disclosure">Vulnerability Disclosure</option>
              <option value="Supply-Chain Compromise">Supply-Chain Compromise</option>
              <option value="Unverified Threat-Actor Claim">Unverified Threat-Actor Claim</option>
            </select>
          </div>

          {/* Confidence Filter */}
          <div>
            <select
              value={selectedConfidence}
              onChange={(e) => setSelectedConfidence(e.target.value)}
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Confidence Levels</option>
              <option value="Confirmed">Confirmed (Official Disclosure)</option>
              <option value="Corroborated">Corroborated (Multiple Sources)</option>
              <option value="Reported">Reported (Single Source)</option>
              <option value="Unverified">Unverified (Actor Claim)</option>
            </select>
          </div>

          {/* Country Filter */}
          <div>
            <select
              value={selectedCountry}
              onChange={(e) => setSelectedCountry(e.target.value)}
              className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Geographies</option>
              <option value="India">India (CERT-In / Domestic)</option>
              <option value="United States">United States</option>
              <option value="Global">Global Enterprise</option>
            </select>
          </div>
        </form>
      </div>

      {/* Real Incidents Timeline & Table */}
      <div className="glass-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">
              Verified Real-World Threat Incidents ({incidents.length})
            </h3>
            <p className="text-xs text-slate-400">
              Correlated from official advisories, breach reports, and public intelligence feeds
            </p>
          </div>
        </div>

        {loading ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">RETRIEVING LIVE INCIDENT RECORDS...</p>
          </div>
        ) : incidents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800 bg-cyber-950/40 font-mono">
                <tr>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Incident Title & Details</th>
                  <th className="py-2.5 px-3">Organization</th>
                  <th className="py-2.5 px-3">Country / Sector</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3 text-right">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => setActiveIncident(inc)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                      {inc.date_reported}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-mono font-bold"
                        style={{
                          backgroundColor: `${CATEGORY_COLORS[inc.category] || '#64748B'}20`,
                          color: CATEGORY_COLORS[inc.category] || '#94A3B8',
                          border: `1px solid ${CATEGORY_COLORS[inc.category] || '#64748B'}40`
                        }}
                      >
                        {inc.category}
                      </span>
                    </td>
                    <td className="py-3 px-3 max-w-sm">
                      <div className="font-semibold text-white truncate">{inc.title}</div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {inc.description}
                      </div>
                    </td>
                    <td className="py-3 px-3 font-medium text-slate-300 whitespace-nowrap">
                      {inc.company}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="text-white text-[11px]">{inc.country}</div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-[120px]">
                        {inc.affected_sector}
                      </div>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          CONFIDENCE_BADGES[inc.verification_status] || 'text-slate-400 border-slate-700'
                        }`}
                      >
                        {inc.verification_status} ({inc.confidence_score}%)
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <span className="text-cyan-400 hover:text-cyan-300 font-mono text-[11px] flex items-center justify-end gap-1">
                        <span>Details</span>
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs">
            No incidents found matching the selected filters.
          </div>
        )}
      </div>

      {/* Incident Detail Modal */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-cyber-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setActiveIncident(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Header */}
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span
                  className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold"
                  style={{
                    backgroundColor: `${CATEGORY_COLORS[activeIncident.category] || '#64748B'}20`,
                    color: CATEGORY_COLORS[activeIncident.category] || '#94A3B8',
                    border: `1px solid ${CATEGORY_COLORS[activeIncident.category] || '#64748B'}40`
                  }}
                >
                  {activeIncident.category}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    CONFIDENCE_BADGES[activeIncident.verification_status]
                  }`}
                >
                  {activeIncident.verification_status} ({activeIncident.confidence_score}%)
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  ID: {activeIncident.incident_id}
                </span>
              </div>
              <h3 className="text-lg font-bold text-white leading-snug">
                {activeIncident.title}
              </h3>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg bg-cyber-950 border border-slate-800 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px]">COMPANY:</span>
                <span className="text-white font-semibold">{activeIncident.company}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">COUNTRY:</span>
                <span className="text-cyan-300 font-semibold">{activeIncident.country}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">REPORTED:</span>
                <span className="text-slate-300">{activeIncident.date_reported}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">STATUS:</span>
                <span className="text-emerald-400 font-semibold truncate block">
                  {activeIncident.investigation_status || 'Under Review'}
                </span>
              </div>
            </div>

            {/* Affected Users & Scope */}
            {activeIncident.affected_users && (
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                <span className="text-slate-400 font-semibold block mb-0.5">AFFECTED POPULATION & SCOPE:</span>
                <span className="text-amber-300 font-mono">{activeIncident.affected_users}</span>
              </div>
            )}

            {/* Detailed Description */}
            <div className="space-y-1.5">
              <span className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
                Incident Assessment & Forensic Summary
              </span>
              <p className="text-xs text-slate-300 leading-relaxed bg-cyber-950/60 p-3.5 rounded-lg border border-slate-800/80">
                {activeIncident.description}
              </p>
            </div>

            {/* Extracted CVE Identifiers */}
            {activeIncident.cve_identifiers && activeIncident.cve_identifiers.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-400 font-mono">ASSOCIATED CVE VULNERABILITIES:</span>
                <div className="flex flex-wrap gap-2">
                  {activeIncident.cve_identifiers.map((cve, idx) => (
                    <a
                      key={idx}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-mono flex items-center gap-1.5"
                    >
                      <span>{cve}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* IOCs / URLs if any */}
            {activeIncident.iocs && activeIncident.iocs.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-400 font-mono">EXTRACTED INDICATORS OF COMPROMISE (IOCS):</span>
                <div className="p-3 bg-cyber-950 border border-slate-800 rounded-lg max-h-36 overflow-y-auto space-y-1 text-[11px] font-mono text-red-300">
                  {activeIncident.iocs.map((ioc, idx) => (
                    <div key={idx} className="truncate select-all">{ioc}</div>
                  ))}
                </div>
              </div>
            )}

            {/* Direct Source Attribution */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
              <div className="text-slate-400 font-mono truncate max-w-sm">
                <span>Source: </span>
                <span className="text-slate-200">{activeIncident.source_publication}</span>
              </div>
              {activeIncident.direct_source_link && (
                <a
                  href={activeIncident.direct_source_link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-mono flex items-center gap-1.5 transition-colors"
                >
                  <span>Direct Source Link</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveThreats;
