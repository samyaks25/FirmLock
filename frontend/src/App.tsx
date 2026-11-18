import { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './pages/Dashboard';
import { MyAssets } from './pages/MyAssets';
import { SecurityScans } from './pages/SecurityScans';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Onboarding } from './pages/Onboarding';
import { useAuth } from './auth/AuthContext';

function AppShell() {
  const { user, token, business, businessId, loading, logout } = useAuth();
  const [route, setRoute] = useState('/');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const handleNavigate = (path: string) => setRoute(path);

  const needsOnboarding = !loading && !!token && !businessId;

  const isAssets = route === '/assets';
  const isScans = route === '/scans';
  const isAlerts = route === '/alerts';
  const isReports = route === '/reports';
  const page = isAssets
    ? 'My Assets'
    : isScans
    ? 'Security Scans'
    : isAlerts
    ? 'Alerts & Notifications'
    : isReports
    ? 'Security Reports'
    : 'Dashboard';
  const desc = isAssets
    ? 'Manage and monitor your registered digital assets.'
    : isScans
    ? 'Monitor website security assessments and findings.'
    : isAlerts
    ? 'Monitor and manage security alerts across your assets.'
    : isReports
    ? 'Review and manage your website security assessment reports.'
    : 'Security posture overview and recent activity';

  if (loading) return null;

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <Sidebar
        onNavigate={handleNavigate}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((v) => !v)}
      />
      <div
        className={`min-h-screen transition-all duration-300 ${
          sidebarCollapsed ? 'md:ml-20' : 'md:ml-64'
        }`}
      >
        <Header
          title={page}
          description={desc}
          onMenuClick={() => {}}
          user={user}
          business={business}
          onSignOut={logout}
        />
        {needsOnboarding ? <Onboarding /> : isAssets ? <MyAssets /> : isScans ? <SecurityScans /> : isAlerts ? <Alerts /> : isReports ? <Reports /> : <Dashboard />}
      </div>
    </div>
  );
}

export default function App() {
  const { loading, token } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#101B2C]">
        <div className="flex flex-col items-center gap-3 text-white">
          <div className="w-10 h-10 rounded-full bg-[#36D6C4] flex items-center justify-center text-[#101B2C] font-bold">F</div>
          <p className="text-sm font-medium">Loading FirmLock...</p>
        </div>
      </div>
    );
  }

  if (!token) {
    return (
      window.location.pathname === '/register' ? <Register /> : <Login />
    );
  }

  return (
    <AppShell />
  );
}
