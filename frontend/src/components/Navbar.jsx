import React, { useEffect, useState, useRef } from 'react';
import { Menu, ShieldAlert, Cpu, Bell, AlertTriangle, CheckCircle, ExternalLink } from 'lucide-react';
import { systemService, dashboardService } from '../services/api';

const Navbar = ({ currentPage, setCurrentPage, setIsSidebarOpen }) => {
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [isAlertsOpen, setIsAlertsOpen] = useState(false);
  const alertsRef = useRef(null);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await systemService.getHealth();
        setHealth(data);
      } catch (e) {
        setHealth({ status: 'offline' });
      }
    };

    const fetchAlerts = async () => {
      try {
        const stats = await dashboardService.getStats();
        if (stats?.security_alerts) {
          setAlerts(stats.security_alerts);
        }
      } catch (e) {
        // silent fail on demo/guest
      }
    };

    checkHealth();
    fetchAlerts();
    const interval = setInterval(() => {
      checkHealth();
      fetchAlerts();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (alertsRef.current && !alertsRef.current.contains(event.target)) {
        setIsAlertsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const pageTitles = {
    dashboard: 'Cybersecurity Operations Dashboard',
    analyze: 'Advanced Email Threat & Privacy Scanner',
    'live-threats': 'Live Cyber Threat Intelligence Operations',
    'breach-monitor': 'Data Breach & Exposure Intelligence',
    'phishing-intel': 'Real-Time Phishing & Malicious URL Stream',
    'vulnerability-intel': 'CISA Known Exploited Vulnerabilities Catalog',
    'company-tracker': 'Company Incident & Cloud Status Monitor',
    'threat-sources': 'Threat Intelligence Feeds & Telemetry',
    gmail: 'Gmail Read-Only OAuth Integration',
    history: 'Historical Security Reports Archive',
    'threat-intel': 'Threat Intelligence & Tracker Repository',
    settings: 'Security Engine & Privacy Configuration',
    profile: 'Operator Profile & Credentials',
    about: 'Project Architecture & Intelligence Framework',
  };

  return (
    <header className="h-16 border-b border-slate-800/80 bg-cyber-900/60 backdrop-blur-md sticky top-0 z-30 flex items-center justify-between px-4 lg:px-8">
      {/* Left: Hamburger & Breadcrumb */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setIsSidebarOpen(true)}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 lg:hidden"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <h1 className="text-sm font-semibold text-white tracking-wide flex items-center gap-2">
            <span>{pageTitles[currentPage] || 'Security Console'}</span>
          </h1>
          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline-block">
            DEFENSE STATUS // HYBRID RULE & AI ENGINE ACTIVE
          </span>
        </div>
      </div>

      {/* Right: Engine Telemetry Badges & Notifications */}
      <div className="flex items-center gap-3">
        {/* Backend & DB Health Badge */}
        <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full border border-slate-800 bg-cyber-950/80 text-[11px] font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              health?.status === 'healthy'
                ? 'bg-emerald-400 shadow-emerald-400/50 shadow-sm animate-pulse'
                : 'bg-red-400'
            }`}
          />
          <span className="text-slate-300">
            {health?.status === 'healthy' ? 'EPA CORE ACTIVE' : 'CONNECTING...'}
          </span>
        </div>

        {/* Presidio / AI Badge */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-cyan-500/20 bg-cyan-500/5 text-[11px] font-mono text-cyan-300">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>PRESIDIO + AI</span>
        </div>

        {/* Security Alerts Dropdown */}
        <div className="relative" ref={alertsRef}>
          <button
            onClick={() => setIsAlertsOpen(!isAlertsOpen)}
            className="relative p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Security Notifications"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full animate-ping" />
            )}
            {alerts.length > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
            )}
          </button>

          {isAlertsOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-cyber-900 border border-slate-800 rounded-xl shadow-2xl z-50 p-3 space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-xs">
                <span className="font-semibold text-white flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  Security Alerts ({alerts.length})
                </span>
                <span className="text-[10px] font-mono text-cyan-400">TELEMETRY</span>
              </div>

              {alerts.length > 0 ? (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {alerts.map((al, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-left cursor-pointer hover:bg-red-500/20 transition-all"
                      onClick={() => {
                        setIsAlertsOpen(false);
                        setCurrentPage('history');
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-red-300 truncate max-w-[190px]">
                          {al.title}
                        </span>
                        <span className="text-[10px] font-mono text-red-400 bg-red-500/20 px-1.5 py-0.5 rounded">
                          SCORE {al.score}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 truncate mt-1">
                        Sender: {al.sender}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-4 text-center text-xs text-slate-400 space-y-1">
                  <CheckCircle className="w-6 h-6 text-emerald-400 mx-auto" />
                  <p>All scanned mail within safe boundaries</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Quick Scan Action Button */}
        {currentPage !== 'analyze' && (
          <button
            onClick={() => setCurrentPage('analyze')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 transition-all shadow-sm shadow-cyan-500/20"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Scan Email</span>
          </button>
        )}
      </div>
    </header>
  );
};

export default Navbar;
