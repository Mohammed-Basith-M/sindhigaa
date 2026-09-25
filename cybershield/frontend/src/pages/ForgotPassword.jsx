import React, { useState } from 'react';
import { Shield, Mail, ArrowLeft, CheckCircle2 } from 'lucide-react';

export default function ForgotPassword({ onNavigate }) {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setSubmitted(true);
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#0a0f1d] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 mx-auto flex items-center justify-center">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <h2 className="text-xl font-bold text-white tracking-wider">
            RESET SECURITY CREDENTIALS
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Request temporary SOC emergency credential recovery
          </p>
        </div>

        {submitted ? (
          <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 space-y-3 text-center">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-semibold text-emerald-300 font-mono">
              Recovery Instructions Dispatched
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              If an analyst record exists for <span className="text-white">{email}</span>, tokenized reset coordinates have been relayed to internal SOC communications.
            </p>
            <button
              onClick={() => onNavigate('login')}
              className="mt-2 inline-flex items-center gap-2 text-xs text-cyan-400 hover:underline font-mono"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Sign In
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-slate-500" /> Registered Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.corp"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs tracking-wider uppercase transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2"
            >
              <span>Transmit Recovery Link</span>
            </button>

            <div className="text-center">
              <button
                type="button"
                onClick={() => onNavigate('login')}
                className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 font-mono"
              >
                <ArrowLeft className="w-3.5 h-3.5" /> Return to Login
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
