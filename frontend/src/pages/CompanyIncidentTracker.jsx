import React, { useState, useEffect } from 'react';
import { Building, Search, ExternalLink, AlertTriangle, CheckCircle, Server, ShieldAlert } from 'lucide-react';
import { threatIntelService } from '../services/api';

const COMPANY_STATUS_PAGES = [
  { name: 'Microsoft 365 & Outlook', url: 'https://admin.microsoft.com/#/servicehealth', status: 'Active Monitoring' },
  { name: 'Google Workspace', url: 'https://www.google.com/appsstatus/dashboard/', status: 'Active Monitoring' },
  { name: 'Zoom Video Communications', url: 'https://status.zoom.us/', status: 'Active Monitoring' },
  { name: 'Zoomcar Mobility', url: 'https://haveibeenpwned.com/PwnedWebsites#Zoomcar', status: 'Disclosed Archive' },
  { name: 'CERT-In Incident Portal', url: 'https://www.cert-in.org.in/', status: 'Advisory Feed' }
];

const CompanyIncidentTracker = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCompany, setSelectedCompany] = useState('All');

  const fetchCompanyIncidents = async () => {
    try {
      setLoading(true);
      const res = await threatIntelService.getThreats({
        limit: 100
      });
      // Filter for company-specific events
      const allInc = res.incidents || [];
      const filtered = selectedCompany === 'All'
        ? allInc.filter((i) => i.company && !i.company.toLowerCase().includes('multiple'))
        : allInc.filter((i) => i.company.toLowerCase().includes(selectedCompany.toLowerCase()));
      setIncidents(filtered);
    } catch (err) {
      console.error('Failed to load company incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCompanyIncidents();
  }, [selectedCompany]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
          Enterprise Infrastructure & Breaches
        </span>
        <h2 className="text-xl font-bold text-white mt-1">Company Incident & Status Tracker</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Monitors official status disclosures, infrastructure service outages, and data security incidents for Microsoft 365, Google Workspace, Zoom, Zoomcar, and global cloud providers.
        </p>
      </div>

      {/* Official Status Portals Quick Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {COMPANY_STATUS_PAGES.map((p, idx) => (
          <a
            key={idx}
            href={p.url}
            target="_blank"
            rel="noopener noreferrer"
            className="glass-panel p-3.5 border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
          >
            <div>
              <span className="text-[10px] font-mono text-emerald-400 font-bold block mb-1">
                {p.status}
              </span>
              <span className="text-xs font-semibold text-white block truncate">{p.name}</span>
            </div>
            <div className="mt-2 text-[11px] font-mono text-cyan-400 flex items-center gap-1">
              <span>Status Page</span>
              <ExternalLink className="w-3 h-3" />
            </div>
          </a>
        ))}
      </div>

      {/* Company Selector Filter */}
      <div className="flex flex-wrap gap-2 pt-2">
        {['All', 'Microsoft', 'Google', 'Zoomcar', 'AIIMS', 'UnitedHealth', 'Snowflake'].map((comp) => (
          <button
            key={comp}
            onClick={() => setSelectedCompany(comp)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
              selectedCompany === comp
                ? 'bg-cyan-500 text-cyber-950 font-bold'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {comp}
          </button>
        ))}
      </div>

      {/* Incidents List */}
      <div className="space-y-4">
        {loading ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">RETRIEVING COMPANY INCIDENTS...</p>
          </div>
        ) : incidents.length > 0 ? (
          incidents.map((inc) => (
            <div key={inc.incident_id} className="glass-panel p-5 border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      inc.category === 'Service Outage'
                        ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        : inc.category === 'Data Breach'
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {inc.category}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    DISCLOSED: {inc.date_reported}
                  </span>
                </div>
                <span className="text-xs font-mono text-cyan-400 font-bold">
                  {inc.company} ({inc.country})
                </span>
              </div>

              <div>
                <h3 className="text-sm font-bold text-white">{inc.title}</h3>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">{inc.description}</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-2.5 rounded bg-cyber-950 border border-slate-800 text-xs font-mono">
                <div>
                  <span className="text-slate-500">SECTOR: </span>
                  <span className="text-white">{inc.affected_sector}</span>
                </div>
                <div>
                  <span className="text-slate-500">STATUS: </span>
                  <span className="text-emerald-400">{inc.investigation_status}</span>
                </div>
                <div>
                  <span className="text-slate-500">VERIFICATION: </span>
                  <span className="text-cyan-300">{inc.verification_status}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">
                  Publication: <span className="text-slate-300">{inc.source_publication}</span>
                </span>
                {inc.direct_source_link && (
                  <a
                    href={inc.direct_source_link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <span>View Official Source</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            </div>
          ))
        ) : (
          <div className="glass-panel p-8 text-center text-xs text-slate-500">
            No incidents found for the selected company.
          </div>
        )}
      </div>
    </div>
  );
};

export default CompanyIncidentTracker;
