import React, { useState } from 'react';
import { Shield, Lock, Mail, User, ArrowRight } from 'lucide-react';

export default function Register({ onLoginSuccess, onNavigate }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('SOC Incident Handler');

  const handleSubmit = (e) => {
    e.preventDefault();
    const userObj = {
      name: name || email.split('@')[0],
      email,
      role,
      clearance: 'Level-2 Operator',
      createdAt: new Date().toISOString()
    };
    localStorage.setItem('user', JSON.stringify(userObj));
    localStorage.setItem('isLoggedIn', 'true');
    onLoginSuccess(userObj);
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0a0f1d] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h2 className="text-xl font-bold text-white tracking-wider">
            REGISTER SOC OPERATOR
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Provision analyst credentials for the PCAP intelligence platform
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-slate-500" /> Full Name / Callsign
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Alex Chen"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5 text-slate-500" /> Work Email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alex.chen@soc.corp"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-slate-500" /> Master Password
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300">Duty Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            >
              <option>SOC Incident Handler</option>
              <option>Network Forensic Investigator</option>
              <option>Malware Reverse Engineer</option>
              <option>Security Operations Manager</option>
            </select>
          </div>

          <button
            type="submit"
            className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2"
          >
            <span>Create Security Badge</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="text-center text-xs text-slate-500 font-mono">
          Already verified?{' '}
          <button
            onClick={() => onNavigate('login')}
            className="text-cyan-400 hover:underline font-medium"
          >
            Sign in
          </button>
        </div>
      </div>
    </div>
  );
}
