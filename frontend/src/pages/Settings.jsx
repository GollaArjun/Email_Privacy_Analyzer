import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Cpu,
  Trash2,
  Lock,
  Bell,
  Save,
  CheckCircle,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import { settingsService, systemService } from '../services/api';

const Settings = () => {
  const [settings, setSettings] = useState({
    ai_enabled: true,
    ollama_model: 'llama3',
    retention_period_days: 30,
    mask_pii_in_reports: true,
    notification_preferences: {
      high_risk_alerts: true,
      weekly_digest: false,
      phishing_alerts: true,
    },
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [health, setHealth] = useState(null);
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        setLoading(true);
        const data = await settingsService.get();
        setSettings(data);
        const h = await systemService.getHealth();
        setHealth(h);
      } catch (err) {
        console.warn('Could not load settings:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchSettings();
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSuccessMsg('');
    setErrorMsg('');
    try {
      const updated = await settingsService.update(settings);
      setSettings(updated);
      setSuccessMsg('Security and AI settings saved successfully.');
    } catch (err) {
      setErrorMsg('Failed to update settings.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm font-mono text-slate-400">LOADING CONFIGURATION...</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
          System Configuration
        </span>
        <h2 className="text-xl font-bold text-white mt-1">
          Security Engine & Privacy Preferences
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure local AI inference, automated data retention limits, and credential masking.
        </p>
      </div>

      {successMsg && (
        <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}
      {errorMsg && (
        <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: AI Engine Configuration */}
        <div className="glass-panel p-6 border-slate-700/80 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <div>
                <h3 className="text-sm font-bold text-white">Hybrid AI Security Engine (Ollama)</h3>
                <p className="text-xs text-slate-400">
                  Local on-device inference for contextual phishing analysis and remediation guidance
                </p>
              </div>
            </div>

            {/* Toggle Switch */}
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.ai_enabled}
                onChange={(e) => setSettings({ ...settings, ai_enabled: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Local Ollama Model Selection
              </label>
              <select
                value={settings.ollama_model}
                disabled={!settings.ai_enabled}
                onChange={(e) => setSettings({ ...settings, ollama_model: e.target.value })}
                className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-500 disabled:opacity-50"
              >
                <option value="llama3">llama3 (Recommended for deep threat reasoning)</option>
                <option value="mistral">mistral (Fast and lightweight)</option>
                <option value="gemma">gemma (Google DeepMind lightweight model)</option>
                <option value="llama2">llama2 (Legacy)</option>
              </select>
              <p className="text-[11px] text-slate-500 mt-1">
                Status: {health?.services?.ollama_llm || 'Local AI Engine active'}
              </p>
            </div>
          </div>
        </div>

        {/* Section 2: Data Retention & Privacy Hygiene */}
        <div className="glass-panel p-6 border-slate-700/80 space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Lock className="w-5 h-5 text-emerald-400" />
            <div>
              <h3 className="text-sm font-bold text-white">Data Retention & Masking Policies</h3>
              <p className="text-xs text-slate-400">
                Control automatic purging and credential redaction enforcement
              </p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-slate-300">Report Retention Period</span>
                <span className="font-mono text-cyan-400 font-bold">
                  {settings.retention_period_days === 0 ? 'Indefinite' : `${settings.retention_period_days} Days`}
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="90"
                step="15"
                value={settings.retention_period_days}
                onChange={(e) => setSettings({ ...settings, retention_period_days: parseInt(e.target.value, 10) })}
                className="w-full accent-cyan-500 bg-slate-800 h-1.5 rounded-lg cursor-pointer"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Reports older than this period are automatically sanitized to maintain user data hygiene.
              </p>
            </div>

            <div className="flex items-center justify-between pt-2">
              <div>
                <span className="text-xs font-semibold text-slate-300 block">
                  Enforce Sensitive PII Masking
                </span>
                <span className="text-[11px] text-slate-500">
                  Always redact Aadhaar, PAN, passwords, and tokens before storing in reports
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.mask_pii_in_reports}
                onChange={(e) => setSettings({ ...settings, mask_pii_in_reports: e.target.checked })}
                className="rounded border-slate-700 bg-cyber-950 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Section 3: Notification Preferences */}
        <div className="glass-panel p-6 border-slate-700/80 space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
            <Bell className="w-5 h-5 text-amber-400" />
            <div>
              <h3 className="text-sm font-bold text-white">Security Alerts & Notification Feeds</h3>
              <p className="text-xs text-slate-400">
                Receive proactive signals when critical threats or credential leaks are detected
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-slate-300 block">
                  High-Risk Threat Alerts
                </span>
                <span className="text-[11px] text-slate-500">
                  Broadcast immediate alerts when analysis score exceeds 60 (Very High / Critical)
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.notification_preferences?.high_risk_alerts ?? true}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    notification_preferences: {
                      ...settings.notification_preferences,
                      high_risk_alerts: e.target.checked,
                    },
                  })
                }
                className="rounded border-slate-700 bg-cyber-950 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
              <div>
                <span className="text-xs font-semibold text-slate-300 block">
                  Deceptive Phishing & Impersonation Warnings
                </span>
                <span className="text-[11px] text-slate-500">
                  Highlight suspicious Reply-To and typosquatting domains in notification banner
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.notification_preferences?.phishing_alerts ?? true}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    notification_preferences: {
                      ...settings.notification_preferences,
                      phishing_alerts: e.target.checked,
                    },
                  })
                }
                className="rounded border-slate-700 bg-cyber-950 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
              <div>
                <span className="text-xs font-semibold text-slate-300 block">
                  Periodic Security Digest
                </span>
                <span className="text-[11px] text-slate-500">
                  Compile weekly summary of privacy metrics and tracker block rates
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.notification_preferences?.weekly_digest ?? false}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    notification_preferences: {
                      ...settings.notification_preferences,
                      weekly_digest: e.target.checked,
                    },
                  })
                }
                className="rounded border-slate-700 bg-cyber-950 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 transition-all flex items-center gap-2 shadow-lg shadow-cyan-500/20"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'SAVING PREFERENCES...' : 'SAVE CONFIGURATION'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};

export default Settings;
