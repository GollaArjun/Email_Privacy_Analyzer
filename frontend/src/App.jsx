import React, { useState } from 'react';
import { AuthProvider, AuthContext } from './context/AuthContext';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import AnalyzeEmail from './pages/AnalyzeEmail';
import AnalysisReport from './pages/AnalysisReport';
import GmailIntegration from './pages/GmailIntegration';
import AnalysisHistory from './pages/AnalysisHistory';
import ThreatIntelligence from './pages/ThreatIntelligence';
import LiveThreats from './pages/LiveThreats';
import BreachMonitor from './pages/BreachMonitor';
import PhishingIntel from './pages/PhishingIntel';
import VulnerabilityIntel from './pages/VulnerabilityIntel';
import CompanyIncidentTracker from './pages/CompanyIncidentTracker';
import ThreatSources from './pages/ThreatSources';
import Settings from './pages/Settings';
import Profile from './pages/Profile';
import About from './pages/About';
import Login from './pages/Login';
import Register from './pages/Register';

function AppContent() {
  const { isAuthenticated, loading } = React.useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [authView, setAuthView] = useState('login'); // 'login' | 'register'
  const [currentReport, setCurrentReport] = useState(null);
  const [selectedReportId, setSelectedReportId] = useState(null);

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-mono text-cyan-400 tracking-wider">INITIALIZING CYBER DEFENSE CONSOLE...</p>
      </div>
    );
  }

  // Not logged in -> show Login or Register
  if (!isAuthenticated) {
    if (authView === 'register') {
      return <Register onSwitchToLogin={() => setAuthView('login')} />;
    }
    return <Login onSwitchToRegister={() => setAuthView('register')} />;
  }

  const handleAnalysisComplete = (newReport) => {
    setCurrentReport(newReport);
    setSelectedReportId(newReport.report_id);
    setCurrentPage('report');
  };

  const handleSelectReport = (reportId) => {
    setCurrentReport(null);
    setSelectedReportId(reportId);
    setCurrentPage('report');
  };

  return (
    <MainLayout currentPage={currentPage} setCurrentPage={setCurrentPage}>
      {currentPage === 'dashboard' && (
        <Dashboard
          setCurrentPage={setCurrentPage}
          setSelectedReportId={setSelectedReportId}
        />
      )}

      {currentPage === 'analyze' && (
        <AnalyzeEmail onAnalysisComplete={handleAnalysisComplete} />
      )}

      {currentPage === 'report' && (
        <AnalysisReport
          report={currentReport}
          reportId={selectedReportId}
          onBack={() => setCurrentPage('dashboard')}
        />
      )}

      {currentPage === 'live-threats' && <LiveThreats />}

      {currentPage === 'breach-monitor' && <BreachMonitor />}

      {currentPage === 'phishing-intel' && <PhishingIntel />}

      {currentPage === 'vulnerability-intel' && <VulnerabilityIntel />}

      {currentPage === 'company-tracker' && <CompanyIncidentTracker />}

      {currentPage === 'threat-sources' && <ThreatSources />}

      {currentPage === 'gmail' && (
        <GmailIntegration onAnalysisComplete={handleAnalysisComplete} />
      )}

      {currentPage === 'history' && (
        <AnalysisHistory onSelectReport={handleSelectReport} />
      )}

      {currentPage === 'threat-intel' && <ThreatIntelligence />}

      {currentPage === 'settings' && <Settings />}

      {currentPage === 'profile' && <Profile />}

      {currentPage === 'about' && <About />}
    </MainLayout>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
