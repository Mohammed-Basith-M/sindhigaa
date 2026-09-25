import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import Results from './pages/Results';
import History from './pages/History';
import Threats from './pages/Threats';
import Profile from './pages/Profile';
import Settings from './pages/Settings';
import api from './services/api';

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [user, setUser] = useState({
    name: 'DEMO ANALYST',
    email: 'demo@cybershield.com',
    role: 'SOC Incident Handler',
    clearance: 'Level-3 Confidential',
    createdAt: new Date().toISOString()
  });
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg, type = 'error') => {
    setToastMessage({ text: msg, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Initialize auth from localStorage if present
  useEffect(() => {
    try {
      const storedAuth = localStorage.getItem('isLoggedIn');
      const storedUser = localStorage.getItem('user');
      if (storedAuth !== null) {
        setIsLoggedIn(storedAuth === 'true');
      }
      if (storedUser) {
        setUser(JSON.parse(storedUser));
      } else {
        localStorage.setItem('user', JSON.stringify(user));
        localStorage.setItem('isLoggedIn', 'true');
      }
    } catch (e) {
      console.error(e);
    }
  }, []);

  const handleLoginSuccess = (userObj) => {
    setUser(userObj);
    setIsLoggedIn(true);
    setCurrentPage('dashboard');
    showToast(`Welcome back, ${userObj.name}`, 'success');
  };

  const handleLogout = () => {
    localStorage.removeItem('isLoggedIn');
    localStorage.removeItem('user');
    setIsLoggedIn(false);
    setUser(null);
    setCurrentPage('login');
  };

  const handleSelectAnalysis = async (analysisId) => {
    setLoadingAnalysis(true);
    try {
      const data = await api.getAnalysis(analysisId);
      setCurrentAnalysis(data);
      setCurrentPage('results');
    } catch (err) {
      showToast(`Failed to load analysis: ${err.message}`, 'error');
    } finally {
      setLoadingAnalysis(false);
    }
  };

  const handleDemoTrigger = async () => {
    try {
      const demoData = await api.getDemoAnalysis();
      setCurrentAnalysis(demoData);
      setCurrentPage('results');
    } catch (err) {
      showToast(`Could not launch demo: ${err.message}`, 'error');
    }
  };

  const handleAnalysisComplete = (data) => {
    setCurrentAnalysis(data);
    setCurrentPage('results');
  };

  // If user is not logged in, render authentication routes
  if (!isLoggedIn) {
    if (currentPage === 'register') {
      return (
        <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
          <Navbar user={null} onLogout={handleLogout} onNavigate={setCurrentPage} />
          <Register onLoginSuccess={handleLoginSuccess} onNavigate={setCurrentPage} />
        </div>
      );
    }
    if (currentPage === 'forgot-password') {
      return (
        <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
          <Navbar user={null} onLogout={handleLogout} onNavigate={setCurrentPage} />
          <ForgotPassword onNavigate={setCurrentPage} />
        </div>
      );
    }
    return (
      <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
        <Navbar user={null} onLogout={handleLogout} onNavigate={setCurrentPage} />
        <Login onLoginSuccess={handleLoginSuccess} onNavigate={setCurrentPage} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar user={user} onLogout={handleLogout} onNavigate={setCurrentPage} />

      {/* Main Layout with Sidebar */}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentPage={currentPage}
          onNavigate={(page) => {
            setCurrentPage(page);
          }}
          onDemoTrigger={handleDemoTrigger}
        />

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto bg-[#090d16] relative">
          {loadingAnalysis && (
            <div className="absolute inset-0 bg-[#090d16]/80 backdrop-blur-sm z-50 flex items-center justify-center font-mono text-xs text-cyan-400">
              Retrieving PCAP Dossier...
            </div>
          )}

          {currentPage === 'dashboard' && (
            <Dashboard
              onNavigate={setCurrentPage}
              onSelectAnalysis={handleSelectAnalysis}
              onDemoTrigger={handleDemoTrigger}
            />
          )}

          {currentPage === 'analyze' && (
            <Analyze
              onAnalysisComplete={handleAnalysisComplete}
              onDemoTrigger={handleDemoTrigger}
            />
          )}

          {currentPage === 'results' && (
            <Results
              analysis={currentAnalysis}
              onNavigateBack={() => setCurrentPage('dashboard')}
            />
          )}

          {currentPage === 'history' && (
            <History onSelectAnalysis={handleSelectAnalysis} />
          )}

          {currentPage === 'threats' && (
            <Threats onSelectAnalysis={handleSelectAnalysis} />
          )}

          {currentPage === 'profile' && (
            <Profile user={user} onUpdateUser={setUser} />
          )}

          {currentPage === 'settings' && (
            <Settings />
          )}

          {/* Toast Notification Container */}
          {toastMessage && (
            <div className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-xl border text-xs font-mono shadow-2xl flex items-center gap-2 animate-bounce ${
              toastMessage.type === 'error'
                ? 'bg-rose-950/90 text-rose-200 border-rose-500/50 shadow-rose-950/50'
                : 'bg-emerald-950/90 text-emerald-200 border-emerald-500/50 shadow-emerald-950/50'
            }`}>
              <span className="w-2 h-2 rounded-full bg-current animate-ping" />
              <span>{toastMessage.text}</span>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
