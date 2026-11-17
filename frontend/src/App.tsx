import { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './pages/Dashboard';
import { MyAssets } from './pages/MyAssets';
import { SecurityScans } from './pages/SecurityScans';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';

function App() {
  const [route, setRoute] = useState('/');

  const handleNavigate = (path: string) => setRoute(path);

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

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <Sidebar onNavigate={handleNavigate} />
      <Header title={page} description={desc} onMenuClick={() => {}} />
      {isAssets ? <MyAssets /> : isScans ? <SecurityScans /> : isAlerts ? <Alerts /> : isReports ? <Reports /> : <Dashboard />}
    </div>
  );
}

export default App;
