import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Mail,
  FileText,
  History,
  Radio,
  Settings,
  Info,
  User,
  LogOut,
  ChevronRight,
  ShieldCheck,
  Database,
  Server,
  Globe,
  Building
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const navItems = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'analyze', label: 'Email Scanner', icon: ShieldAlert, badge: 'Scanner' },
  { id: 'live-threats', label: 'Live Cyber Threats', icon: Radio, badge: 'Live' },
  { id: 'breach-monitor', label: 'Data Breach Monitor', icon: Database },
  { id: 'phishing-intel', label: 'Phishing Intelligence', icon: Globe },
  { id: 'vulnerability-intel', label: 'Vulnerability Intelligence', icon: Server },
  { id: 'company-tracker', label: 'Company Incident Tracker', icon: Building },
  { id: 'threat-sources', label: 'Threat Intelligence Sources', icon: ShieldCheck },
  { id: 'history', label: 'Reports Archive', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'profile', label: 'Operator Profile', icon: User },
  { id: 'about', label: 'About Platform', icon: Info },
];

const Sidebar = ({ currentPage, setCurrentPage, isOpen, setIsOpen }) => {
  const { user, logout } = useAuth();

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-64 bg-cyber-900 border-r border-slate-800/80 flex flex-col transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand / Logo */}
        <div className="h-16 px-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-5 h-5 text-cyber-950 font-bold" />
            </div>
            <div>
              <span className="font-bold text-sm tracking-wide text-white block">
                EPA <span className="text-cyan-400 font-mono text-xs">v2.0</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono tracking-wider block">
                CYBER THREAT PLATFORM
              </span>
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Threat Intelligence & Operations
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setCurrentPage(item.id);
                  setIsOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center gap-3 truncate">
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-400'
                    }`}
                  />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge ? (
                  <span
                    className={`px-1.5 py-0.5 text-[9px] rounded font-mono font-bold shrink-0 ${
                      item.badge === 'Live'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 animate-pulse'
                        : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    }`}
                  >
                    {item.badge}
                  </span>
                ) : isActive ? (
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                ) : null}
              </button>
            );
          })}
        </nav>

        {/* User Card & Logout Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-cyber-950/60">
          <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
                <User className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <div className="truncate">
                <p className="text-xs font-semibold text-white truncate">
                  {user?.name || 'Security Analyst'}
                </p>
                <p className="text-[10px] text-slate-400 truncate font-mono">
                  {user?.email || 'analyst@local'}
                </p>
              </div>
            </div>
            <button
              onClick={logout}
              title="Logout session"
              className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
