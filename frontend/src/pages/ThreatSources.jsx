import React, { useState, useEffect } from 'react';
import { Server, CheckCircle, AlertTriangle, RefreshCw, ExternalLink, ShieldCheck, Key, Clock } from 'lucide-react';
import { threatIntelService } from '../services/api';

const ThreatSources = () => {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');

  const fetchSources = async () => {
    try {
      setLoading(true);
      const res = await threatIntelService.getSources();
      setSources(res.sources || []);
    } catch (err) {
      console.error('Failed to load threat sources:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSources();
  }, []);

  const handleSyncAll = async () => {
    try {
      setSyncing(true);
      setSyncMsg('Polling all external threat intelligence sources...');
      await threatIntelService.triggerSync();
      setTimeout(async () => {
        await fetchSources();
        setSyncing(false);
        setSyncMsg('All sources refreshed successfully.');
        setTimeout(() => setSyncMsg(''), 4000);
      }, 3000);
    } catch (err) {
      setSyncing(false);
      setSyncMsg('Sync trigger failed.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
            Feed Telemetry & Health
          </span>
          <h2 className="text-xl font-bold text-white mt-1">Threat Intelligence Sources</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Live operational status, latency, error telemetry, and ingested indicator counts for all connected public feeds.
          </p>
        </div>

        <button
          onClick={handleSyncAll}
          disabled={syncing}
          className="px-4 py-2 rounded-lg text-xs font-mono font-bold bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 flex items-center gap-2 self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
          <span>{syncing ? 'REFRESHING...' : 'SYNC ALL SOURCES'}</span>
        </button>
      </div>

      {syncMsg && (
        <div className="p-3 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 text-xs">
          {syncMsg}
        </div>
      )}

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {loading ? (
          <div className="col-span-full py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">POLLING SOURCE TELEMETRY...</p>
          </div>
        ) : (
          sources.map((s) => (
            <div key={s.source_id} className="glass-panel p-5 border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 ${
                      s.status === 'healthy'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${s.status === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                    <span>{s.status.toUpperCase()}</span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">
                    EVERY {s.sync_interval_minutes}M
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white">{s.name}</h3>
                <p className="text-xs text-slate-400 font-mono">{s.category}</p>
              </div>

              <div className="space-y-2 pt-3 border-t border-slate-800 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-500">INGESTED RECORDS:</span>
                  <span className="text-cyan-300 font-bold">{s.items_ingested_total}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">API KEY REQ:</span>
                  <span className="text-slate-300">{s.requires_api_key ? 'REQUIRED' : 'NONE (PUBLIC)'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">LAST SYNC:</span>
                  <span className="text-slate-300">
                    {s.last_sync ? new Date(s.last_sync).toLocaleTimeString() : 'Pending'}
                  </span>
                </div>
              </div>

              {s.last_error && (
                <div className="p-2 rounded bg-red-500/10 border border-red-500/20 text-[11px] text-red-300 font-mono truncate">
                  Error: {s.last_error}
                </div>
              )}

              <div className="pt-2 border-t border-slate-800 flex justify-between items-center text-xs font-mono">
                <a
                  href={s.homepage_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  <span>Portal</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
                {s.feed_url && (
                  <a
                    href={s.feed_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-slate-400 hover:text-white flex items-center gap-1"
                  >
                    <span>Feed Endpoint</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ThreatSources;
