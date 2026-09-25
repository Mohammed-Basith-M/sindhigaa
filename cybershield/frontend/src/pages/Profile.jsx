import React, { useState } from 'react';
import { User, Mail, Shield, Award, Calendar, Save, Check } from 'lucide-react';

export default function Profile({ user, onUpdateUser }) {
  const [name, setName] = useState(user?.name || 'SOC Analyst');
  const [email, setEmail] = useState(user?.email || 'demo@cybershield.com');
  const [role, setRole] = useState(user?.role || 'SOC Incident Handler');
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    const updated = {
      ...user,
      name,
      email,
      role
    };
    localStorage.setItem('user', JSON.stringify(updated));
    if (onUpdateUser) onUpdateUser(updated);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div className="space-y-1">
        <h1 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
          Analyst Security Credentials
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          Operator profile, clearance level, and duty assignment details
        </p>
      </div>

      <div className="p-6 rounded-2xl bg-[#0a0f1d] border border-slate-800 space-y-6">
        <div className="flex items-center gap-4 pb-6 border-b border-slate-800">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-mono text-xl font-bold">
            {email.slice(0, 2).toUpperCase()}
          </div>
          <div className="space-y-1">
            <h2 className="text-base font-bold text-white font-mono">{name}</h2>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40">
                {role}
              </span>
              <span>·</span>
              <span className="text-slate-500">{user?.clearance || 'Level-3 Confidential'}</span>
            </div>
          </div>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-slate-500" /> Analyst Name / Callsign
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-slate-500" /> Duty Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-slate-500" /> Primary Operational Role
            </label>
            <input
              type="text"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="pt-2 flex items-center justify-between">
            <span className="text-[11px] font-mono text-slate-500">
              Account initialized: {new Date(user?.createdAt || Date.now()).toLocaleDateString()}
            </span>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] flex items-center gap-1.5"
            >
              {saved ? (
                <>
                  <Check className="w-4 h-4" />
                  <span>Profile Saved</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save Changes</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
