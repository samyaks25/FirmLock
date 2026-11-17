import { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './pages/Dashboard';
import { MyAssets } from './pages/MyAssets';

function App() {
  const [route, setRoute] = useState('/');

  const handleNavigate = (path: string) => setRoute(path);

  const page = route === '/assets' ? 'My Assets' : 'Dashboard';
  const desc = route === '/assets' ? 'Manage and monitor your registered digital assets.' : 'Security posture overview and recent activity';

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <Sidebar onNavigate={handleNavigate} />
      <Header title={page} description={desc} onMenuClick={() => {}} />
      {route === '/assets' ? <MyAssets /> : <Dashboard />}
    </div>
  );
}

export default App;
