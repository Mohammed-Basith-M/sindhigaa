import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, KeyRound, Terminal } from 'lucide-react';

export default function Login({ onLoginSuccess, onNavigate }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please provide analyst credentials.');
      return;
    }
    
    // Simulate auth (demo credentials or any valid entry for prototype)
    const userObj = {
      name: email.split('@')[0].toUpperCase(),
      email: email,
      role: 'SOC Incident Handler',
      clearance: 'Level-3 Confidential',
      createdAt: new Date().toISOString()
    };
    
    localStorage.setItem('user', JSON.stringify(userObj));
    localStorage.setItem('isLoggedIn', 'true');
    onLoginSuccess(userObj);
  };

  const handleUseDemo = () => {
    setEmail('demo@cybershield.com');
    setPassword('demo123');
    setError('');
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0a0f1d] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6 relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.15)]">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h2 className="text-xl font-bold text-white tracking-wider">
            CYBER<span className="text-cyan-400">SHIELD</span> ACCESS
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Authenticate to access SOC telemetry and PCAP inspection suite
          </p>
        </div>

        {/* Quick Demo Credentials Box */}
        <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/20 space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono text-cyan-300">
            <span className="font-semibold flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5" /> Prototype Credentials:
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
            <div>Email: <span className="text-slate-200">demo@cybershield.com</span></div>
            <div>Password: <span className="text-slate-200">demo123</span></div>
          </div>
          <button
            type="button"
            onClick={() => {
              const userObj = {
                name: 'DEMO ANALYST',
                email: 'demo@cybershield.com',
                role: 'SOC Incident Handler',
                clearance: 'Level-3 Confidential',
                createdAt: new Date().toISOString()
              };
              localStorage.setItem('user', JSON.stringify(userObj));
              localStorage.setItem('isLoggedIn', 'true');
              onLoginSuccess(userObj);
            }}
            className="w-full py-2 px-3 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-semibold transition-all flex items-center justify-center gap-2"
          >
            <span>Instant Demo Sign In (1-Click)</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-xs text-rose-400 font-mono">
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5 text-slate-500" />
              Analyst Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@soc.corp"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-500" />
                Security Password
              </label>
              <button
                type="button"
                onClick={() => onNavigate('forgot-password')}
                className="text-[11px] text-cyan-400 hover:underline font-mono"
              >
                Forgot?
              </button>
            </div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          <button
            type="submit"
            className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2"
          >
            <span>Authenticate Session</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Footer */}
        <div className="text-center text-xs text-slate-500 font-mono">
          New analyst?{' '}
          <button
            onClick={() => onNavigate('register')}
            className="text-cyan-400 hover:underline font-medium"
          >
            Register SOC Badge
          </button>
        </div>
      </div>
    </div>
  );
}
