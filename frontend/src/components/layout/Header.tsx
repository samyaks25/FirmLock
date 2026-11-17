import { Bell, User, Menu, LogOut, ChevronDown, Settings } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';

interface HeaderProps {
  title: string;
  description?: string;
  onMenuClick?: () => void;
}

export function Header({ title, description, onMenuClick }: HeaderProps) {
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const notificationsRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notificationsRef.current && !notificationsRef.current.contains(event.target as Node)) {
        setNotificationsOpen(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const notificationItems = [
    { id: 1, message: 'SSL certificate expiring for api.firmlock.io', time: '5 min ago', type: 'warning' },
    { id: 2, message: 'Security scan completed for www.example.com', time: '1 hour ago', type: 'success' },
    { id: 3, message: 'New vulnerability detected in dependency', time: '3 hours ago', type: 'critical' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-white border-b border-[#E2E8F0]">
      <div className="flex items-center justify-between h-16 px-4 md:px-6">
        <div className="flex items-center gap-4">
          <button
            onClick={onMenuClick}
            className="md:hidden p-2 rounded-lg hover:bg-[#F4F7FA] transition-colors text-[#172536]"
            aria-label="Open menu"
          >
            <Menu className="w-5 h-5" aria-hidden="true" />
          </button>
          <div>
            <h1 className="text-xl font-semibold text-[#101B2C]">{title}</h1>
            {description && (
              <p className="text-sm text-[#718096]">{description}</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative" ref={notificationsRef}>
            <button
              onClick={() => {
                setNotificationsOpen(!notificationsOpen);
                setUserMenuOpen(false);
              }}
              className="relative p-2 rounded-lg hover:bg-[#F4F7FA] transition-colors text-[#718096] hover:text-[#101B2C]"
              aria-label="Notifications"
              aria-expanded={notificationsOpen}
            >
              <Bell className="w-5 h-5" aria-hidden="true" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-[#F2B84B] rounded-full" aria-hidden="true" />
            </button>

            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-80 bg-white rounded-xl shadow-lg border border-[#E2E8F0] py-2 z-50 animate-in fade-in-0 zoom-in-95">
                <div className="px-4 py-3 border-b border-[#E2E8F0] flex items-center justify-between">
                  <h3 className="font-medium text-[#101B2C]">Notifications</h3>
                  <button className="text-sm text-[#36D6C4] hover:underline">Mark all read</button>
                </div>
                <div className="max-h-96 overflow-y-auto">
                  {notificationItems.map((item) => (
                    <button
                      key={item.id}
                      className="w-full px-4 py-3 hover:bg-[#F4F7FA] text-left transition-colors border-b border-[#E2E8F0]/50 last:border-0"
                    >
                      <p className="text-sm text-[#172536]">{item.message}</p>
                      <p className="text-xs text-[#718096] mt-1">{item.time}</p>
                      <span
                        className={`inline-block mt-2 px-2 py-0.5 text-xs rounded-full ${
                          item.type === 'warning'
                            ? 'bg-[#F2B84B]/10 text-[#F2B84B]'
                            : item.type === 'success'
                            ? 'bg-[#36D6C4]/10 text-[#36D6C4]'
                            : 'bg-[#EF4444]/10 text-[#EF4444]'
                        }`}
                      >
                        {item.type}
                      </span>
                    </button>
                  ))}
                </div>
                <div className="px-4 py-3 border-t border-[#E2E8F0]">
                  <button className="w-full text-center text-sm text-[#36D6C4] hover:underline">
                    View all notifications
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="relative" ref={userMenuRef}>
            <button
              onClick={() => {
                setUserMenuOpen(!userMenuOpen);
                setNotificationsOpen(false);
              }}
              className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-[#F4F7FA] transition-colors"
              aria-label="User menu"
              aria-expanded={userMenuOpen}
            >
              <div className="w-8 h-8 rounded-full bg-[#36D6C4] flex items-center justify-center">
                <User className="w-4 h-4 text-[#101B2C]" aria-hidden="true" />
              </div>
              <span className="hidden md:block text-sm font-medium text-[#172536]">John Doe</span>
              <ChevronDown className="w-4 h-4 text-[#718096] hidden md:block" aria-hidden="true" />
            </button>

            {userMenuOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-xl shadow-lg border border-[#E2E8F0] py-2 z-50 animate-in fade-in-0 zoom-in-95">
                <div className="px-4 py-3 border-b border-[#E2E8F0]">
                  <p className="font-medium text-[#101B2C]">John Doe</p>
                  <p className="text-sm text-[#718096]">john@company.com</p>
                  <p className="text-xs text-[#36D6C4] mt-1">Admin</p>
                </div>
                <button className="w-full flex items-center gap-2 px-4 py-2 text-sm text-[#172536] hover:bg-[#F4F7FA] transition-colors">
                  <User className="w-4 h-4" aria-hidden="true" />
                  Profile
                </button>
                <button className="w-full flex items-center gap-2 px-4 py-2 text-sm text-[#172536] hover:bg-[#F4F7FA] transition-colors">
                  <Settings className="w-4 h-4" aria-hidden="true" />
                  Settings
                </button>
                <div className="border-t border-[#E2E8F0] my-2" />
                <button className="w-full flex items-center gap-2 px-4 py-2 text-sm text-[#EF4444] hover:bg-[#F4F7FA] transition-colors">
                  <LogOut className="w-4 h-4" aria-hidden="true" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}