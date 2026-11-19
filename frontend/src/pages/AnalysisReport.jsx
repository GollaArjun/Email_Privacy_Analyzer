import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  FileText,
  Download,
  Printer,
  Radio,
  EyeOff,
  Paperclip,
  Key,
  ExternalLink,
  ChevronRight,
  Info,
  Sparkles,
  ArrowLeft,
  Copy,
  Check,
  Globe,
  ShieldCheck,
  Database,
} from 'lucide-react';
import ScoreGauge from '../components/ScoreGauge';
import RiskBadge from '../components/RiskBadge';
import { reportsService } from '../services/api';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

const AnalysisReport = ({ report: propReport, reportId, onBack }) => {
  const [report, setReport] = useState(propReport || null);
  const [loading, setLoading] = useState(!propReport && !!reportId);
  const [activeTab, setActiveTab] = useState('overview');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (propReport) {
      setReport(propReport);
    } else if (reportId) {
      const fetchReport = async () => {
        try {
          setLoading(true);
          const data = await reportsService.getById(reportId);
          setReport(data);
        } catch (err) {
          console.error('Failed to load report:', err);
        } finally {
          setLoading(false);
        }
      };
      fetchReport();
    }
  }, [propReport, reportId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-mono text-slate-400">LOADING CYBERSECURITY REPORT...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="glass-panel p-12 text-center max-w-lg mx-auto space-y-4">
        <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-white">Report Not Found</h3>
        <p className="text-xs text-slate-400">
          The requested email analysis report does not exist or has been removed.
        </p>
        <button
          onClick={onBack}
          className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white transition-colors"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const email_metadata = report.email_metadata || {};
  const findings = report.findings || {};
  const risk_assessment = report.risk_assessment || {
    overall_score: 0,
    risk_category: 'Low',
    score_explanation: 'Standard low-risk communication.',
    disclaimer: 'Heuristic calculation based on threat indicators.',
    recommended_actions: [],
    score_breakdown: {}
  };
  const ai_assessment = report.ai_assessment || {};
  const report_id = report.report_id || 'UNKNOWN';
  const created_at = report.created_at || '';

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrintPdf = async () => {
    try {
      const element = document.getElementById('epa-printable-report');
      if (element) {
        const canvas = await html2canvas(element, { scale: 1.5, backgroundColor: '#0a0e1a' });
        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        pdf.save(`EPA_Report_${report_id.slice(0, 8)}.pdf`);
        return;
      }
    } catch (err) {
      console.warn('PDF capture error, falling back to window.print():', err);
    }
    window.print();
  };

  const downloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `EPA_Report_${report_id.slice(0, 8)}.json`);
    dlAnchor.click();
  };

  return (
    <div id="epa-printable-report" className="space-y-6 print:bg-white print:text-black">
      {/* Top Header & Export Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          {onBack && (
            <button
              onClick={onBack}
              className="p-2 rounded-lg border border-slate-800 bg-cyber-900 text-slate-400 hover:text-white hover:border-slate-700 transition-colors"
              title="Go back"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
          )}
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                REPORT // {report_id.slice(0, 8)}
              </span>
              <RiskBadge level={risk_assessment.risk_category} size="sm" />
            </div>
            <h2 className="text-xl font-bold text-white mt-1 truncate max-w-xl">
              {email_metadata.subject || '(No Subject)'}
            </h2>
          </div>
        </div>

        {/* Export Buttons */}
        <div className="flex items-center gap-2 shrink-0 print:hidden">
          <button
            onClick={handleCopyJson}
            className="px-3 py-1.5 rounded-lg text-xs font-mono border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:border-slate-600 transition-all flex items-center gap-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy JSON'}</span>
          </button>
          <button
            onClick={downloadJson}
            className="px-3 py-1.5 rounded-lg text-xs font-mono border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:border-slate-600 transition-all flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrintPdf}
            className="px-3 py-1.5 rounded-lg text-xs font-mono border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-all flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / PDF</span>
          </button>
        </div>
      </div>

      {/* Main Score & Telemetry Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Gauge Card */}
        <div className="glass-panel p-6 flex flex-col items-center justify-center text-center">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
            Overall Privacy & Security Score
          </h3>
          <ScoreGauge score={risk_assessment.overall_score} category={risk_assessment.risk_category} size={210} />
          <p className="text-xs text-slate-300 mt-4 max-w-xs">{risk_assessment.score_explanation}</p>
          <p className="text-[10px] text-slate-500 italic mt-2">
            * {risk_assessment.disclaimer}
          </p>
        </div>

        {/* Score Breakdown Bars */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
              Risk Component Weights
            </h3>
            <div className="space-y-3 font-mono text-xs">
              {Object.entries(risk_assessment.score_breakdown).map(([key, val]) => {
                const label = key.replace(/_/g, ' ').toUpperCase();
                const pct = Math.min((val / 40) * 100, 100);
                return (
                  <div key={key}>
                    <div className="flex justify-between text-[11px] mb-1">
                      <span className="text-slate-400">{label}</span>
                      <span className="text-white font-bold">{val} pts</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-red-500 transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span>Deduplicated Findings</span>
            <span className="text-cyan-400 font-bold">
              {findings.pii_findings.length +
                findings.phishing_findings.length +
                findings.tracking_findings.length +
                findings.attachment_findings.length}{' '}
              Items
            </span>
          </div>
        </div>

        {/* Email Metadata Overview */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
              Email RFC822 Metadata
            </h3>
            <dl className="space-y-2 text-xs">
              <div>
                <dt className="text-slate-500 text-[10px] uppercase font-mono">From / Sender</dt>
                <dd className="text-white font-medium break-all">{email_metadata.sender}</dd>
              </div>
              {email_metadata.reply_to && (
                <div>
                  <dt className="text-slate-500 text-[10px] uppercase font-mono">Reply-To</dt>
                  <dd className="text-amber-400 font-medium break-all">{email_metadata.reply_to}</dd>
                </div>
              )}
              {email_metadata.return_path && (
                <div>
                  <dt className="text-slate-500 text-[10px] uppercase font-mono">Return-Path</dt>
                  <dd className="text-slate-300 font-mono break-all">{email_metadata.return_path}</dd>
                </div>
              )}
              <div>
                <dt className="text-slate-500 text-[10px] uppercase font-mono">Date</dt>
                <dd className="text-slate-300">{email_metadata.date || 'Unspecified'}</dd>
              </div>
              <div>
                <dt className="text-slate-500 text-[10px] uppercase font-mono">Message-ID</dt>
                <dd className="text-slate-400 font-mono text-[11px] break-all">
                  {email_metadata.message_id || 'None (Missing RFC 5322 ID)'}
                </dd>
              </div>
            </dl>
          </div>

          <div className="pt-3 border-t border-slate-800 mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Attachments: {email_metadata.attachments_count}</span>
            <span>HTML: {email_metadata.has_html ? 'Yes' : 'No'}</span>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-slate-800 overflow-x-auto print:hidden">
        {[
          { id: 'overview', label: 'AI Assessment & Actions', icon: Sparkles, count: risk_assessment.recommended_actions.length },
          { id: 'pii', label: 'Personal Information (PII)', icon: Key, count: findings.pii_findings.length },
          { id: 'phishing', label: 'Phishing & URLs', icon: Radio, count: findings.phishing_findings.length + findings.suspicious_urls.length },
          { id: 'tracking', label: 'Tracking & Telemetry', icon: EyeOff, count: findings.tracking_findings.length },
          { id: 'headers', label: 'Header Security', icon: FileText, count: findings.header_findings.length },
          { id: 'attachments', label: 'Attachments', icon: Paperclip, count: findings.attachment_findings.length },
          { id: 'threat_intel', label: 'Threat Intel Feeds', icon: Globe, count: (findings.threat_intel?.matches || []).length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 whitespace-nowrap transition-all ${
                isActive
                  ? 'border-cyan-400 text-cyan-400 font-semibold bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.count > 0 && (
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab 1: AI Threat Assessment & Action Plan */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="glass-panel p-6 border-cyan-500/30 bg-cyber-900/60 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Cybersecurity Intelligence & AI Verdict
                </h3>
              </div>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded border border-cyan-500/20">
                {ai_assessment.model_name}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-cyber-950/80 border border-slate-800 font-medium text-xs text-slate-200">
              <span className="text-cyan-400 font-mono font-bold uppercase mr-2">Verdict:</span>
              {ai_assessment.threat_verdict}
            </div>

            <div className="text-xs text-slate-300 leading-relaxed space-y-2">
              <p>{ai_assessment.contextual_analysis}</p>
            </div>

            {ai_assessment.key_observations && ai_assessment.key_observations.length > 0 && (
              <div>
                <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">Key Observations:</h4>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {ai_assessment.key_observations.map((obs, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                      <span>{obs}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Recommended Actions Checklist */}
          <div className="glass-panel p-6 border-slate-700/80 space-y-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>Prioritized Remediation Actions</span>
            </h3>

            <div className="space-y-2.5">
              {risk_assessment.recommended_actions.map((act, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg border border-slate-800 bg-cyber-950/40 flex items-start gap-3"
                >
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    STEP {idx + 1}
                  </span>
                  <p className="text-xs text-slate-200">{act}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: PII Detection */}
      {activeTab === 'pii' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white font-mono uppercase">
              Sensitive Personal Information & Credentials
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Sensitive values masked for safety
            </span>
          </div>

          {findings.pii_findings.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {findings.pii_findings.map((item, idx) => (
                <div key={idx} className="glass-panel p-4 border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/30">
                      {item.entity_type}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Confidence: {(item.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-cyber-950 border border-slate-800/80 font-mono text-xs text-white">
                    {item.text_masked}
                  </div>
                  <p className="text-xs text-slate-400">{item.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="glass-panel p-8 text-center text-slate-400 text-xs">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              No government identifiers, passwords, or personal credentials exposed.
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Phishing & Suspicious URLs */}
      {activeTab === 'phishing' && (
        <div className="space-y-6">
          {/* Phishing Findings */}
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase mb-3">
              Social Engineering & Deception Signals
            </h3>
            {findings.phishing_findings.length > 0 ? (
              <div className="space-y-3">
                {findings.phishing_findings.map((ph, idx) => (
                  <div
                    key={idx}
                    className="glass-panel p-4 border-amber-500/20 bg-amber-500/5 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white">{ph.title}</span>
                      <RiskBadge level={ph.severity} size="sm" />
                    </div>
                    <p className="text-xs text-slate-300">{ph.description}</p>
                    <div className="p-2 rounded bg-cyber-950 border border-slate-800 text-xs font-mono text-amber-300/90">
                      Evidence: {ph.evidence_masked}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="glass-panel p-6 text-center text-slate-400 text-xs">
                <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                No deceptive urgency lures or domain impersonation detected.
              </div>
            )}
          </div>

          {/* Suspicious URL Table */}
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase mb-3">
              Extracted Destination Links & Risk Vectors
            </h3>
            {findings.suspicious_urls.length > 0 ? (
              <div className="overflow-x-auto glass-panel">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-cyber-950/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Domain</th>
                      <th className="py-2.5 px-3">Risk Factors</th>
                      <th className="py-2.5 px-3">Indicators</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {findings.suspicious_urls.map((u, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="py-3 px-3 text-cyan-300 font-bold">{u.domain}</td>
                        <td className="py-3 px-3 text-slate-300 font-sans">{u.risk_factors.join('; ')}</td>
                        <td className="py-3 px-3">
                          <div className="flex flex-wrap gap-1">
                            {u.is_shortener && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                                Shortener
                              </span>
                            )}
                            {u.is_punycode && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-500/10 text-red-400 border border-red-500/20">
                                Punycode
                              </span>
                            )}
                            {u.is_ip_host && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-500/10 text-red-400 border border-red-500/20">
                                IP Host
                              </span>
                            )}
                            {u.has_redirect && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                Redirect
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="glass-panel p-6 text-center text-slate-400 text-xs">
                No high-risk URLs, IP hostnames, or punycode links found.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Tracking & Web Beacons */}
      {activeTab === 'tracking' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white font-mono uppercase">
              Covert Web Beacons & Read Receipts
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Identifies recipient telemetry
            </span>
          </div>

          {findings.tracking_findings.length > 0 ? (
            <div className="space-y-3">
              {findings.tracking_findings.map((tr, idx) => (
                <div key={idx} className="glass-panel p-4 border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                      {tr.tracker_name || 'Tracking Pixel'}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      Type: {tr.tracking_type}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-cyber-950 border border-slate-800 text-[11px] font-mono text-slate-300 break-all">
                    {tr.url}
                  </div>
                  <p className="text-xs text-slate-400">{tr.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="glass-panel p-8 text-center text-slate-400 text-xs">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              No 1x1 tracking pixels, hidden web beacons, or known ESP trackers detected.
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Email Header Analysis */}
      {activeTab === 'headers' && (
        <div className="space-y-4">
          <h3 className="text-sm font-bold text-white font-mono uppercase">
            Authentication Headers (SPF / DKIM / DMARC) & Routing
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {findings.header_findings.map((h, idx) => (
              <div key={idx} className="glass-panel p-4 border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white">{h.header_name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      h.status === 'PASS'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : h.status === 'FAIL'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                    }`}
                  >
                    {h.status}
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-300">
                  Value: {h.value_summary}
                </div>
                <p className="text-xs text-slate-400">{h.explanation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 6: Attachment Analysis */}
      {activeTab === 'attachments' && (
        <div className="space-y-4">
          <h3 className="text-sm font-bold text-white font-mono uppercase">
            Attachment Inspection & Hashes
          </h3>

          {findings.attachment_findings.length > 0 ? (
            <div className="space-y-3">
              {findings.attachment_findings.map((att, idx) => (
                <div key={idx} className="glass-panel p-4 border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Paperclip className="w-4 h-4 text-cyan-400" />
                      <span className="text-xs font-bold text-white">{att.filename}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {att.is_mime_mismatch && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                          MIME MISMATCH
                        </span>
                      )}
                      {att.is_double_extension && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          DOUBLE EXT
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          att.risk_level === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {att.risk_level}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300">{att.recommendation}</p>

                  <div className="p-3 rounded bg-cyber-950 border border-slate-800 font-mono text-[11px] space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Size: {(att.file_size_bytes / 1024).toFixed(1)} KB</span>
                      <span>MIME: {att.content_type}</span>
                    </div>
                    <div className="text-slate-400 truncate">SHA-256: {att.sha256_hash}</div>
                    <div className="text-slate-400 truncate">MD5: {att.md5_hash}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="glass-panel p-8 text-center text-slate-400 text-xs">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              No attached binary or document payloads found in message.
            </div>
          )}
        </div>
      )}

      {/* Tab 7: Threat Intelligence Feed Correlation */}
      {activeTab === 'threat_intel' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span>Live Threat Intelligence Feed Correlation</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time cross-referencing against OpenPhish, CISA KEV, and authoritative incident databases.
              </p>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="px-2.5 py-1 rounded bg-cyber-900 border border-slate-800 text-slate-300">
                Indicators Scanned: <span className="text-cyan-400 font-bold">{findings.threat_intel?.indicators_scanned_count || 0}</span>
              </span>
              <span className="px-2.5 py-1 rounded bg-cyber-900 border border-slate-800 text-slate-300">
                Matches: <span className={findings.threat_intel?.matches_count > 0 ? "text-red-400 font-bold" : "text-emerald-400 font-bold"}>
                  {findings.threat_intel?.matches_count || 0}
                </span>
              </span>
            </div>
          </div>

          {/* Verdict Status Banner */}
          {findings.threat_intel?.matches && findings.threat_intel.matches.length > 0 ? (
            <div className="p-4 rounded-xl border border-red-500/40 bg-red-500/10 flex items-start gap-3">
              <ShieldAlert className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-red-300">
                  CRITICAL: Verified Threat Feed Matches Detected ({findings.threat_intel.matches.length})
                </h4>
                <p className="text-xs text-red-200/90 leading-relaxed">
                  One or more indicators (URLs, hostnames, or attachment hashes) within this email are actively listed in authoritative threat intelligence feeds. The sender or payload appears intentionally deceptive.
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 flex items-start gap-3">
              <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-emerald-300">
                  No match found in checked sources
                </h4>
                <p className="text-xs text-emerald-200/90 leading-relaxed">
                  Extracted URLs, sender hostnames, and attachment cryptographic hashes did not trigger any active alerts in checked feeds (OpenPhish, CISA Known Exploited Vulnerabilities, Authoritative Outage & Incident Monitor).
                </p>
                <p className="text-[11px] text-emerald-400/80 italic font-mono pt-1">
                  Note: Consistent with threat intelligence standards, absence of prior reporting indicates an unflagged status rather than guaranteed benign origin.
                </p>
              </div>
            </div>
          )}

          {/* Privacy & Safe Execution Notice */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-cyber-900/60 flex items-start gap-3">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-300 space-y-1">
              <span className="font-semibold text-white font-mono text-[11px] uppercase tracking-wide">
                Privacy & Safe Evaluation Notice
              </span>
              <p className="text-slate-400 leading-relaxed">
                No private email text or recipient data was transmitted externally. Only normalized IOCs (domain hostnames and attachment SHA-256 hashes) were checked against threat repositories. Suspicious URLs are never visited automatically.
              </p>
            </div>
          </div>

          {/* Threat Matches Breakdown */}
          {findings.threat_intel?.matches && findings.threat_intel.matches.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                Correlated Threat Feed Matches
              </h4>
              <div className="space-y-3">
                {findings.threat_intel.matches.map((m, idx) => (
                  <div key={idx} className="glass-panel p-4 border-red-500/30 bg-red-950/10 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                          {m.indicator_type}
                        </span>
                        <span className="text-xs font-bold text-white break-all">{m.indicator_value}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          m.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                          m.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                          'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        }`}>
                          {m.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                          {m.confidence}
                        </span>
                      </div>
                    </div>

                    <div className="text-xs text-slate-300 space-y-1">
                      <p><span className="text-slate-400 font-medium">Verdict:</span> <strong className="text-white">{m.reputation_verdict}</strong></p>
                      <p className="text-slate-300 leading-relaxed">{m.explanation}</p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                      <div className="flex items-center gap-2">
                        <Database className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Source: <strong className="text-slate-300">{m.matched_source}</strong></span>
                        {m.source_url && (
                          <a
                            href={m.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-0.5 ml-1"
                          >
                            <span>Ref</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                      {m.last_seen && (
                        <span>Last Verified: {new Date(m.last_seen).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Checked Feeds Roster */}
          <div className="glass-panel p-5 border-slate-800 space-y-3">
            <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Threat Intelligence Sources Queried
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(findings.threat_intel?.sources_checked || [
                "OpenPhish Community Feed",
                "CISA Known Exploited Vulnerabilities Catalog",
                "Authoritative Cyber Incident & Outage Monitor"
              ]).map((src, idx) => (
                <div key={idx} className="p-3 rounded-lg border border-slate-800 bg-cyber-950/50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" />
                    <span className="text-xs font-medium text-slate-300 truncate">{src}</span>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">
                    QUERIED
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnalysisReport;
