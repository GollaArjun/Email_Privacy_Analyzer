import React, { useState } from 'react';
import { User, ShieldCheck, Key, Lock, CheckCircle, AlertCircle, Edit3 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/api';

const Profile = () => {
  const { user } = useAuth();
  const [operatorName, setOperatorName] = useState(user?.name || '');
  const [nameSaving, setNameSaving] = useState(false);
  const [nameMsg, setNameMsg] = useState('');
  const [nameErr, setNameErr] = useState('');

  const [currPassword, setCurrPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const handleUpdateName = async (e) => {
    e.preventDefault();
    setNameMsg('');
    setNameErr('');
    if (!operatorName.trim()) {
      setNameErr('Name cannot be empty.');
      return;
    }
    try {
      setNameSaving(true);
      await authService.updateMe(operatorName.trim());
      setNameMsg('Operator display name updated successfully.');
    } catch (error) {
      setNameErr(error.response?.data?.detail || 'Failed to update operator name.');
    } finally {
      setNameSaving(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setMsg('');
    setErr('');

    if (newPassword !== confirmPassword) {
      setErr('New passwords do not match.');
      return;
    }
    if (newPassword.length < 6) {
      setErr('New password must be at least 6 characters.');
      return;
    }

    try {
      setSaving(true);
      await authService.changePassword(currPassword, newPassword);
      setMsg('Password updated successfully.');
      setCurrPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      setErr(error.response?.data?.detail || 'Failed to update password.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
          User Account
        </span>
        <h2 className="text-xl font-bold text-white mt-1">Operator Profile & Security</h2>
        <p className="text-xs text-slate-400 mt-1">
          Manage identity, session credentials, and security clearance.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Profile Card */}
        <div className="glass-panel p-6 border-slate-700/80 md:col-span-1 space-y-4 text-center">
          <div className="w-20 h-20 rounded-full bg-gradient-to-tr from-cyan-500 to-emerald-500 p-0.5 mx-auto">
            <div className="w-full h-full rounded-full bg-cyber-950 flex items-center justify-center">
              <User className="w-10 h-10 text-cyan-400" />
            </div>
          </div>

          <div>
            <h3 className="text-sm font-bold text-white">{user?.name || 'Security Analyst'}</h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{user?.email || 'analyst@demo.local'}</p>
          </div>

          <div className="pt-3 border-t border-slate-800 space-y-2 text-xs font-mono text-left">
            <div className="flex justify-between">
              <span className="text-slate-500">CLEARANCE:</span>
              <span className="text-emerald-400 font-bold">LEVEL 4 SEC</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ROLE:</span>
              <span className="text-cyan-300">INCIDENT RESPONDER</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ACCOUNT:</span>
              <span className="text-white">ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Edit Identity and Credentials Forms */}
        <div className="md:col-span-2 space-y-6">
          {/* Edit Identity */}
          <div className="glass-panel p-6 border-slate-700/80 space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
              <Edit3 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Operator Identity
              </h3>
            </div>

            {nameMsg && (
              <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-xs flex items-center gap-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{nameMsg}</span>
              </div>
            )}
            {nameErr && (
              <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{nameErr}</span>
              </div>
            )}

            <form onSubmit={handleUpdateName} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Operator Full Name
                </label>
                <input
                  type="text"
                  required
                  value={operatorName}
                  onChange={(e) => setOperatorName(e.target.value)}
                  placeholder="Security Specialist"
                  className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <button
                  type="submit"
                  disabled={nameSaving}
                  className="px-5 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 disabled:opacity-50"
                >
                  {nameSaving ? 'SAVING...' : 'SAVE DISPLAY NAME'}
                </button>
              </div>
            </form>
          </div>

          {/* Change Password Form */}
          <div className="glass-panel p-6 border-slate-700/80 space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
              <Lock className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Update Master Credentials
              </h3>
            </div>

            {msg && (
              <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-xs flex items-center gap-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{msg}</span>
              </div>
            )}
            {err && (
              <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{err}</span>
              </div>
            )}

            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Current Password
                </label>
                <input
                  type="password"
                  required
                  value={currPassword}
                  onChange={(e) => setCurrPassword(e.target.value)}
                  className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  New Password
                </label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Confirm New Password
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-cyber-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={saving}
                  className="px-5 py-2.5 rounded-lg text-xs font-bold font-mono tracking-wider bg-gradient-to-r from-cyan-500 to-emerald-500 text-cyber-950 hover:brightness-110 disabled:opacity-50"
                >
                  {saving ? 'UPDATING...' : 'UPDATE PASSWORD'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
