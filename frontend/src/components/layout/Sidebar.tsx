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

interface SidebarProps {
  onNavigate: (path: string) => void;
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ onNavigate, collapsed, onToggle }: SidebarProps) {
  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-[#101B2C] text-white transition-all duration-300 z-50 overflow-hidden ${
        collapsed ? 'w-20' : 'w-64'
      }`}
      aria-label="Main navigation"
    >
      <div className="flex flex-col h-full">
        <div
          className={`relative border-b border-white/10 ${
            collapsed
              ? 'flex flex-col items-center justify-center px-2 pt-6 pb-2 min-h-[96px]'
              : 'flex items-center justify-between px-4 py-3 h-16'
          }`}
        >
          <div
            className={`flex items-center ${
              collapsed ? 'flex-col gap-1' : 'flex-row gap-2'
            }`}
          >
            <img
              src="/firmlock-logo.png"
              alt="FirmLock"
              className={`flex-shrink-0 ${collapsed ? 'w-7 h-7' : 'w-8 h-8'}`}
            />
            <span
              className={`font-semibold tracking-tight ${
                collapsed ? 'text-[10px] leading-tight text-center' : 'text-lg'
              }`}
            >
              FirmLock
            </span>
          </div>
          <button
            onClick={onToggle}
            className={`rounded-lg hover:bg-white/10 transition-colors text-white/70 hover:text-white ${
              collapsed ? 'absolute right-1 top-1 p-1' : 'p-2'
            }`}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!collapsed}
          >
            {collapsed ? (
              <ChevronRight className="w-4 h-4" aria-hidden="true" />
            ) : (
              <ChevronLeft className="w-5 h-5" aria-hidden="true" />
            )}
          </button>
        </div>

        <nav
          className="flex-1 px-2 py-4 space-y-1 overflow-y-auto"
          aria-label="Navigation"
        >
          {navItems.map((item) => (
            <button
              key={item.href}
              onClick={() => onNavigate(item.href)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
                collapsed ? 'justify-center px-0' : 'justify-start'
              }`}
              aria-label={item.label}
              title={collapsed ? item.label : undefined}
            >
              <item.icon
                className="w-5 h-5 flex-shrink-0"
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