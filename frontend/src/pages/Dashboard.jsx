import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Users,
  EyeOff,
  Radio,
  FileWarning,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import StatCard from '../components/StatCard';
import RiskBadge from '../components/RiskBadge';
import { dashboardService, threatIntelService } from '../services/api';

const Dashboard = ({ setCurrentPage, setSelectedReportId }) => {
  const [stats, setStats] = useState(null);
  const [threatStats, setThreatStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const [data, tData] = await Promise.all([
        dashboardService.getStats(),
        threatIntelService.getStatistics().catch(() => null)
      ]);
      setStats(data);
      setThreatStats(tData);
    } catch (err) {
      console.error('Failed to load dashboard statistics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const viewReport = (reportId) => {
    if (setSelectedReportId) setSelectedReportId(reportId);
    setCurrentPage('report');
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-mono text-slate-400">LOADING TELEMETRY DATA...</p>
      </div>
    );
  }

  const chartData = stats?.risk_distribution || [];

  const categoryBarData = [
    { name: 'PII Leaks', count: stats?.pii_leaks_count || 0, fill: '#10B981' },
    { name: 'Phishing', count: stats?.phishing_attempts_count || 0, fill: '#EF4444' },
    { name: 'Trackers', count: stats?.tracking_pixels_count || 0, fill: '#3B82F6' },
    { name: 'Critical', count: stats?.critical_findings_count || 0, fill: '#F59E0B' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Callout */}
      <div className="glass-panel p-6 border-cyan-500/20 bg-gradient-to-r from-cyber-900 via-cyber-850 to-cyber-900 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
            Cyber Threat Operations
          </span>
          <h2 className="text-xl font-bold text-white mt-2">
            Email Privacy & Threat Command Center
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Real-time heuristic evaluation of inbound communications, tracking pixels, credential leakage, and social engineering attempts.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            title="Refresh statistics"
            className="p-2.5 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:border-slate-600 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setCurrentPage('analyze')}
            className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20 font-mono"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>ANALYZE NEW EMAIL</span>
          </button>
        </div>
      </div>

      {/* Real-Time Cyber Threat Intelligence Quick Telemetry Bar */}
      {threatStats && (
        <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyber-900/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
            <div>
              <span className="text-xs font-bold text-white flex items-center gap-1.5 font-mono">
                LIVE CYBER THREAT FEED ACTIVE
              </span>
              <p className="text-[11px] text-slate-400 font-mono">
                {threatStats.total_incidents} verified global incidents &bull; {threatStats.total_exploited_vulnerabilities} CISA KEV zero-days &bull; {threatStats.total_threat_indicators} active phishing lures
              </p>
            </div>
          </div>

          <button
            onClick={() => setCurrentPage('live-threats')}
            className="px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 self-start md:self-auto transition-colors"
          >
            <span>LIVE THREAT PLATFORM</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Primary Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Analyzed"
          value={stats?.total_emails_analyzed || 0}
          subtitle="Processed emails"
          icon={FileWarning}
          color="cyan"
        />
        <StatCard
          title="High-Risk Emails"
          value={stats?.high_risk_emails || 0}
          subtitle="Score >= 60"
          icon={AlertTriangle}
          color="red"
          alert={(stats?.high_risk_emails || 0) > 0}
        />
        <StatCard
          title="Critical Findings"
          value={stats?.critical_findings_count || 0}
          subtitle="Immediate threats"
          icon={ShieldAlert}
          color="amber"
        />
        <StatCard
          title="PII Leaks"
          value={stats?.pii_leaks_count || 0}
          subtitle="Exposed data"
          icon={Users}
          color="emerald"
        />
        <StatCard
          title="Phishing Alerts"
          value={stats?.phishing_attempts_count || 0}
          subtitle="Deceptive links"
          icon={Radio}
          color="red"
        />
        <StatCard
          title="Tracking Pixels"
          value={stats?.tracking_pixels_count || 0}
          subtitle="Web beacons"
          icon={EyeOff}
          color="blue"
        />
      </div>

      {/* Charts & Visual Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Chart */}
        <div className="glass-panel p-5 lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Risk Distribution</h3>
              <p className="text-xs text-slate-400">Email classification breakdown</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              5-TIER
            </span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0B0F19" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-2 mt-2 pt-3 border-t border-slate-800">
            {chartData.map((item, idx) => (
              <div key={idx} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400 truncate">{item.name}</span>
                <span className="text-white font-mono font-semibold ml-auto">{item.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Indicators Bar Chart */}
        <div className="glass-panel p-5 lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Threat Indicators</h3>
              <p className="text-xs text-slate-400">Aggregated detection vectors</p>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              VECTORS
            </span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {categoryBarData.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-3 mt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between font-mono">
            <span>DETECTION RATIO</span>
            <span className="text-cyan-400 font-bold">
              {stats?.total_emails_analyzed ? `${((stats.high_risk_emails / stats.total_emails_analyzed) * 100).toFixed(0)}% HIGH RISK` : '0%'}
            </span>
          </div>
        </div>

        {/* Security Findings & Recent Alerts */}
        <div className="glass-panel p-5 lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">High Priority Threat Alerts</h3>
              <p className="text-xs text-slate-400">Critical incidents requiring user attention</p>
            </div>
            <span className="text-xs font-mono text-red-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
              LIVE MONITOR
            </span>
          </div>

          {stats?.security_alerts && stats.security_alerts.length > 0 ? (
            <div className="space-y-3 flex-1 overflow-y-auto max-h-72 pr-1">
              {stats.security_alerts.map((alert, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg border border-red-500/20 bg-red-500/5 hover:border-red-500/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="p-2 rounded bg-red-500/10 text-red-400 shrink-0 mt-0.5">
                        <AlertTriangle className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-white">{alert.title}</h4>
                        <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                          Sender: {alert.sender}
                        </p>
                        <ul className="mt-2 space-y-1">
                          {alert.reasons?.map((r, rIdx) => (
                            <li key={rIdx} className="text-[11px] text-red-300/90 flex items-center gap-1.5">
                              <span className="w-1 h-1 rounded-full bg-red-400" />
                              {r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-red-400 font-bold shrink-0">
                      SCORE {alert.score}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center py-10 text-center">
              <CheckCircle className="w-10 h-10 text-emerald-400/60 mb-2" />
              <p className="text-xs font-medium text-slate-300">No Critical Threat Alerts</p>
              <p className="text-[11px] text-slate-500 mt-1">
                All analyzed communications are within normal security parameters.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Analysis Activity Table */}
      <div className="glass-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Analysis Activity</h3>
            <p className="text-xs text-slate-400">Latest inspected emails and risk assessments</p>
          </div>
          <button
            onClick={() => setCurrentPage('history')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono transition-colors"
          >
            <span>VIEW ALL ARCHIVE</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {stats?.recent_activity && stats.recent_activity.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800 bg-cyber-950/40">
                <tr>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Risk Category</th>
                  <th className="py-2.5 px-3 font-mono">Score</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {stats.recent_activity.map((act) => (
                  <tr key={act.report_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-sans font-medium text-white max-w-xs truncate">
                      {act.subject}
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate">
                      {act.sender}
                    </td>
                    <td className="py-3 px-3">
                      <RiskBadge level={act.risk_category} size="sm" />
                    </td>
                    <td className="py-3 px-3 font-bold" style={{ color: act.category_color }}>
                      {act.score}/100
                    </td>
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {act.date ? new Date(act.date).toLocaleDateString() : 'Recent'}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => viewReport(act.report_id)}
                        className="px-2.5 py-1 rounded text-[11px] font-sans font-medium bg-slate-800 text-cyan-400 hover:bg-cyan-500/10 hover:border-cyan-500/30 border border-slate-700 transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-slate-500 text-xs">
            No emails analyzed yet. Upload an .eml file or test with sample emails.
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
