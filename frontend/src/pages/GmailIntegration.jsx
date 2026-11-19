import React, { useState, useEffect } from 'react';
import {
  Mail,
  ShieldCheck,
  Lock,
  ExternalLink,
  RefreshCw,
  Trash2,
  CheckCircle,
  AlertCircle,
  FileSearch,
} from 'lucide-react';
import { gmailService } from '../services/api';

const GmailIntegration = ({ onAnalysisComplete }) => {
  const [status, setStatus] = useState(null);
  const [messages, setMessages] = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const checkStatus = async () => {
    try {
      setLoading(true);
      const s = await gmailService.getStatus();
      setStatus(s);
      if (s.connected) {
        const m = await gmailService.getMessages(15);
        setMessages(m.messages || []);
      }
    } catch (err) {
      console.warn('Could not fetch Gmail status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Check if redirect returned code & state in query param
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    if (code && state) {
      const finishOAuth = async () => {
        try {
          setLoading(true);
          await gmailService.callback(code, state);
          setSuccessMsg('Gmail connected successfully with read-only permissions.');
          // Remove query params from url
          window.history.replaceState({}, document.title, window.location.pathname);
          await checkStatus();
        } catch (e) {
          setError('Failed to complete Google OAuth authentication.');
        } finally {
          setLoading(false);
        }
      };
      finishOAuth();
    } else {
      checkStatus();
    }
  }, []);

  const handleConnect = async () => {
    setError('');
    try {
      const data = await gmailService.getAuthUrl();
      if (data.authorization_url) {
        window.location.href = data.authorization_url;
      }
    } catch (err) {
      setError('Could not initiate Google OAuth flow. Please check backend configuration.');
    }
  };

  const handleDisconnect = async () => {
    if (!window.confirm('Are you sure you want to revoke Gmail access and delete stored credentials?')) {
      return;
    }
    try {
      setLoading(true);
      await gmailService.disconnect();
      setStatus({ connected: false });
      setMessages([]);
      setSelectedIds([]);
      setSuccessMsg('Gmail authorization revoked and credentials deleted.');
    } catch (err) {
      setError('Failed to disconnect Gmail.');
    } finally {
      setLoading(false);
    }
  };

  const toggleSelect = (id) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const selectAll = () => {
    if (selectedIds.length === messages.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(messages.map((m) => m.id));
    }
  };

  const analyzeSelected = async () => {
    if (selectedIds.length === 0) {
      setError('Please select at least one email message to inspect.');
      return;
    }
    setError('');
    setScanning(true);
    try {
      const reports = await gmailService.analyzeSelected(selectedIds);
      if (reports && reports.length > 0 && onAnalysisComplete) {
        onAnalysisComplete(reports[0]); // Load first report
      }
    } catch (err) {
      setError('Failed to scan selected Gmail messages.');
    } finally {
      setScanning(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-mono text-slate-400">CHECKING GMAIL AUTHORIZATION...</p>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="glass-panel p-6 border-slate-700/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
            Minimum Privilege Read-Only OAuth
          </span>
          <h2 className="text-xl font-bold text-white mt-1">
            Gmail Privacy & Phishing Shield
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            EPA connects using Google OAuth 2.0 with strict read-only permissions (
            <code className="text-cyan-400 font-mono text-[11px]">gmail.readonly</code>). EPA never sends, deletes, or modifies your emails.
          </p>
        </div>

        <div>
          {status?.connected ? (
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <ShieldCheck className="w-4 h-4" />
                <span>LINKED {status.is_demo ? '(SIMULATION)' : '(LIVE)'}</span>
              </span>
              <button
                onClick={handleDisconnect}
                className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-700 rounded-lg transition-colors"
                title="Revoke access"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              onClick={handleConnect}
              className="px-5 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20"
            >
              <Mail className="w-4 h-4" />
              <span>CONNECT GMAIL</span>
            </button>
          )}
        </div>
      </div>

      {/* Notifications */}
      {successMsg && (
        <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}
      {error && (
        <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Connected Inbox Messages Table */}
      {status?.connected ? (
        <div className="glass-panel p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Select Inbox Messages to Inspect</h3>
              <p className="text-xs text-slate-400">
                Choose specific emails for non-intrusive security and privacy analysis
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={selectAll}
                className="px-3 py-1.5 rounded text-xs font-mono border border-slate-700 bg-slate-800 text-slate-300 hover:text-white"
              >
                {selectedIds.length === messages.length ? 'Deselect All' : 'Select All'}
              </button>
              <button
                onClick={analyzeSelected}
                disabled={scanning || selectedIds.length === 0}
                className={`px-4 py-1.5 rounded text-xs font-bold font-mono tracking-wider flex items-center gap-2 transition-all ${
                  selectedIds.length === 0 || scanning
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 shadow-sm shadow-cyan-500/20'
                }`}
              >
                {scanning ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-cyber-950 border-t-transparent rounded-full animate-spin" />
                    <span>ANALYZING...</span>
                  </>
                ) : (
                  <>
                    <FileSearch className="w-4 h-4" />
                    <span>SCAN SELECTED ({selectedIds.length})</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-cyber-950/80 text-[10px] uppercase font-mono tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3 w-10">Select</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Snippet</th>
                  <th className="py-2.5 px-3 text-right">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {messages.map((m) => {
                  const isChecked = selectedIds.includes(m.id);
                  return (
                    <tr
                      key={m.id}
                      onClick={() => toggleSelect(m.id)}
                      className={`cursor-pointer transition-colors ${
                        isChecked ? 'bg-cyan-500/10' : 'hover:bg-slate-800/30'
                      }`}
                    >
                      <td className="py-3 px-3">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => {}} // Controlled by tr onClick
                          className="rounded border-slate-700 bg-cyber-950 text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                        />
                      </td>
                      <td className="py-3 px-3 font-sans font-medium text-white max-w-[180px] truncate">
                        {m.sender}
                      </td>
                      <td className="py-3 px-3 text-cyan-300 font-sans max-w-[220px] truncate">
                        {m.subject}
                      </td>
                      <td className="py-3 px-3 text-slate-400 font-sans max-w-sm truncate text-[11px]">
                        {m.snippet}
                      </td>
                      <td className="py-3 px-3 text-right text-slate-400 text-[11px]">
                        {m.date}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Not Connected Explanatory Card */
        <div className="glass-panel p-8 text-center space-y-4">
          <div className="w-16 h-16 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-cyan-400">
            <Lock className="w-8 h-8" />
          </div>
          <h3 className="text-base font-bold text-white">Gmail Account Not Connected</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Authorize read-only access to scan your incoming inbox for covert tracking pixels, phishing attempts, and sensitive credential exposures.
          </p>
          <div className="pt-2">
            <button
              onClick={handleConnect}
              className="px-6 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 transition-all inline-flex items-center gap-2 shadow-lg shadow-cyan-500/20"
            >
              <Mail className="w-4 h-4" />
              <span>LINK GMAIL ACCOUNT</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default GmailIntegration;
