import { useState } from 'react';
import {
  LayoutDashboard,
  Server,
  ShieldCheck,
  Bell,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { label: 'Dashboard', href: '/', icon: LayoutDashboard },
  { label: 'My Assets', href: '/assets', icon: Server },
  { label: 'Security Scans', href: '/scans', icon: ShieldCheck },
  { label: 'Alerts', href: '/alerts', icon: Bell },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar({ onNavigate }: { onNavigate: (path: string) => void }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-[#101B2C] text-white transition-all duration-300 z-50 ${
        collapsed ? 'w-32' : 'w-64'
      }`}
      aria-label="Main navigation"
    >
      <div className="flex flex-col h-full">
        <div className={`flex items-center justify-between h-16 ${collapsed ? 'px-3' : 'px-4'} border-b border-white/10`}>
          <div className={`flex items-center gap-2 ${collapsed ? 'flex-col' : 'flex-row'}`}>
            <img
              src="/firmlock-logo.png"
              alt="FirmLock"
              className="w-8 h-8 flex-shrink-0"
            />
            <span className={`font-semibold tracking-tight flex-shrink-0 ${collapsed ? 'text-xs leading-none hidden' : 'text-lg'}`}>
              FirmLock
            </span>
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-2 rounded-lg hover:bg-white/10 transition-colors text-white/70 hover:text-white"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
          >
            {collapsed ? (
              <ChevronRight className="w-5 h-5" aria-hidden="true" />
            ) : (
              <ChevronLeft className="w-5 h-5" aria-hidden="true" />
            )}
          </button>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Navigation">
          {navItems.map((item) => (
            <button
              key={item.href}
              onClick={() => onNavigate(item.href)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
                collapsed
                  ? 'justify-center'
                  : 'justify-start'
              }`}
              aria-label={item.label}
              title={collapsed ? item.label : undefined}
            >
              <item.icon
                className={`w-5 h-5 flex-shrink-0 ${
                  collapsed ? 'mx-auto' : ''
                }`}
                aria-hidden="true"
              />
              {!collapsed && <span>{item.label}</span>}
            </button>
          ))}
        </nav>

        <div className="p-3 border-t border-white/10">
          {!collapsed && (
            <div className="text-xs text-white/40 text-center">
              FirmLock v1.0.0
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}