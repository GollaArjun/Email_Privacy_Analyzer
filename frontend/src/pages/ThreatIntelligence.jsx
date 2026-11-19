import React, { useState, useEffect } from 'react';
import {
  Radio,
  EyeOff,
  Globe,
  AlertTriangle,
  Search,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { settingsService } from '../services/api';

const ThreatIntelligence = () => {
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(true);
  const [urlInput, setUrlInput] = useState('');
  const [urlAnalysis, setUrlAnalysis] = useState(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectError, setInspectError] = useState('');

  useEffect(() => {
    const fetchIntel = async () => {
      try {
        setLoading(true);
        const data = await settingsService.getThreatIntel();
        setIntel(data);
      } catch (err) {
        console.error('Failed to load threat intelligence:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchIntel();
  }, []);

  const handleInspectUrl = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setInspectError('');
    setInspecting(true);
    try {
      const res = await settingsService.inspectUrl(urlInput.trim());
      setUrlAnalysis(res);
    } catch (err) {
      setInspectError('Failed to inspect URL.');
    } finally {
      setInspecting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-mono text-slate-400">LOADING CYBER THREAT SIGNATURES...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
          Threat Intelligence
        </span>
        <h2 className="text-xl font-bold text-white mt-1">
          Cyber Threat & Tracking Network Repository
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Curated signature dictionary of deceptive domains, known telemetry beacons, punycode targets, and an on-demand link analyzer.
        </p>
      </div>

      {/* Interactive Standalone URL Inspector */}
      <div className="glass-panel p-6 border-cyan-500/30 bg-cyber-900/60 space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            Interactive On-Demand URL Inspector
          </h3>
        </div>
        <p className="text-xs text-slate-300">
          Deconstruct any link to detect punycode homographs, shorteners, IP hostnames, or hidden open-redirect parameters.
        </p>

        <form onSubmit={handleInspectUrl} className="flex gap-2">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Paste URL (e.g., http://bit.ly/login or http://192.168.1.1/verify)..."
            className="flex-1 bg-cyber-950 border border-slate-800 rounded-lg px-4 py-2 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={inspecting || !urlInput.trim()}
            className="px-5 py-2 rounded-lg text-xs font-bold font-mono bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 disabled:opacity-50"
          >
            {inspecting ? 'ANALYZING...' : 'INSPECT'}
          </button>
        </form>

        {inspectError && <p className="text-xs text-red-400">{inspectError}</p>}

        {urlAnalysis && (
          <div className="p-4 rounded-lg bg-cyber-950 border border-slate-800 space-y-2 mt-3 font-mono text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Target Host:</span>
              <span className="text-cyan-300 font-bold">{urlAnalysis.url_analysis?.domain || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Risk Assessment:</span>
              <span
                className={`font-bold ${
                  urlAnalysis.url_analysis?.risk_factors?.length > 0 ? 'text-red-400' : 'text-emerald-400'
                }`}
              >
                {urlAnalysis.url_analysis?.risk_factors?.length > 0 ? 'SUSPICIOUS INDICATORS DETECTED' : 'CLEAN / LOW RISK'}
              </span>
            </div>
            {urlAnalysis.url_analysis?.risk_factors?.length > 0 && (
              <div className="pt-2 border-t border-slate-800 space-y-1">
                <span className="text-slate-500 text-[11px] uppercase">Identified Vulnerabilities:</span>
                <ul className="space-y-1 text-slate-300">
                  {urlAnalysis.url_analysis.risk_factors.map((rf, idx) => (
                    <li key={idx} className="flex items-center gap-1.5 text-red-300/90">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                      <span>{rf}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Threat Advisories Cards */}
      <div>
        <h3 className="text-sm font-bold text-white font-mono uppercase mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Active Cyber Threat Advisories</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {intel?.threat_advisories?.map((adv) => (
            <div key={adv.id} className="glass-panel p-4 border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  {adv.id}
                </span>
                <span className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                  {adv.severity}
                </span>
              </div>
              <h4 className="text-xs font-bold text-white">{adv.title}</h4>
              <p className="text-xs text-slate-400 leading-relaxed">{adv.summary}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Known Tracking Beacons & ESP Networks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
              <EyeOff className="w-4 h-4 text-blue-400" />
              <span>Known Tracking Networks ({intel?.tracking_services_count || 0})</span>
            </h3>
          </div>
          <p className="text-xs text-slate-400">
            Email marketing platforms and web beacons automatically identified and flagged by EPA.
          </p>

          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {intel?.tracking_services?.map((svc, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded bg-cyber-950/60 border border-slate-800/80 flex items-center justify-between text-xs"
              >
                <div>
                  <span className="font-semibold text-white">{svc.service_name}</span>
                  <span className="text-[11px] text-slate-400 font-mono block">{svc.domain}</span>
                </div>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  TRACKER
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Suspicious TLDs and Brands */}
        <div className="space-y-6">
          <div className="glass-panel p-5 space-y-3">
            <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
              <Globe className="w-4 h-4 text-yellow-400" />
              <span>Suspicious High-Risk TLDs ({intel?.suspicious_tlds_count || 0})</span>
            </h3>
            <p className="text-xs text-slate-400">
              Top Level Domains frequently exploited for bulk spam, phishing lures, and malware hosting.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {intel?.suspicious_tlds?.map((tld, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800 text-amber-300 border border-slate-700"
                >
                  .{tld}
                </span>
              ))}
            </div>
          </div>

          <div className="glass-panel p-5 space-y-3">
            <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>Frequently Targeted Brand Targets</span>
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {intel?.targeted_brands?.map((brand, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700"
                >
                  {brand}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelligence;
