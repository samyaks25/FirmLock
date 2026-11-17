import { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './pages/Dashboard';
import { MyAssets } from './pages/MyAssets';
import { SecurityScans } from './pages/SecurityScans';
import { Alerts } from './pages/Alerts';

function App() {
  const [route, setRoute] = useState('/');

  const handleNavigate = (path: string) => setRoute(path);

  const isAssets = route === '/assets';
  const isScans = route === '/scans';
  const isAlerts = route === '/alerts';
  const page = isAssets
    ? 'My Assets'
    : isScans
    ? 'Security Scans'
    : isAlerts
    ? 'Alerts & Notifications'
    : 'Dashboard';
  const desc = isAssets
    ? 'Manage and monitor your registered digital assets.'
    : isScans
    ? 'Monitor website security assessments and findings.'
    : isAlerts
    ? 'Monitor and manage security alerts across your assets.'
    : 'Security posture overview and recent activity';

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <Sidebar onNavigate={handleNavigate} />
      <Header title={page} description={desc} onMenuClick={() => {}} />
      {isAssets ? <MyAssets /> : isScans ? <SecurityScans /> : isAlerts ? <Alerts /> : <Dashboard />}
    </div>
  );
}

export default App;
