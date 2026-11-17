import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { Dashboard } from './pages/Dashboard';

function App() {
  const handleNavigate = (path: string) => {
    console.log('Navigate to:', path);
  };

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <Sidebar onNavigate={handleNavigate} />
      <Header
        title="Dashboard"
        description="Security posture overview and recent activity"
        onMenuClick={() => {}}
      />
      <Dashboard />
    </div>
  );
}

export default App;