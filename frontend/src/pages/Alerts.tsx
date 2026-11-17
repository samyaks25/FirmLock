import { useState } from 'react';
import { Bell, AlertTriangle, ShieldCheck, XCircle } from 'lucide-react';
import { AlertSummaryCard } from '../components/alerts/AlertSummaryCard';
import { AlertList, AlertFilterBar, type Alert } from '../components/alerts/AlertList';
import { AlertDetails } from '../components/alerts/AlertDetails';

const initialAlerts: Alert[] = [
  {
    id: 'ALT-001',
    title: 'SSL Certificate Expiring Soon',
    website: 'API Gateway',
    domain: 'api.company.com',
    category: 'SSL Certificate Expiration',
    severity: 'Critical',
    date: '2026-11-16',
    time: '09:30 AM',
    read: false,
    description:
      'The SSL certificate for api.company.com is set to expire in 7 days (on 2026-11-23). This will cause browser warnings and potential service disruption for API consumers.',
    impact:
      'Users and API clients will see certificate warnings. Services relying on this certificate may fail to establish secure connections, leading to downtime and loss of trust.',
    remediation:
      'Renew the SSL certificate immediately through your certificate authority. Update the certificate on all load balancers and servers. Verify the new certificate chain is valid.',
  },
  {
    id: 'ALT-002',
    title: 'Missing Content-Security-Policy Header',
    website: 'Primary Website',
    domain: 'www.company.com',
    category: 'Missing Security Headers',
    severity: 'High',
    date: '2026-11-15',
    time: '02:15 PM',
    read: false,
    description:
      'The website is missing the Content-Security-Policy (CSP) header, which helps prevent XSS attacks and data injection by controlling resource loading.',
    impact:
      'Without CSP, the site is more vulnerable to cross-site scripting (XSS) attacks, clickjacking, and other code injection attacks that could compromise user data.',
    remediation:
      'Implement a Content-Security-Policy header with appropriate directives for your application. Start with report-only mode to test, then enforce. Include directives for scripts, styles, images, and fonts.',
  },
  {
    id: 'ALT-003',
    title: 'SQL Injection Vulnerability Detected',
    website: 'Customer Portal',
    domain: 'portal.company.com',
    category: 'Security Vulnerabilities',
    severity: 'Critical',
    date: '2026-11-15',
    time: '11:45 AM',
    read: true,
    description:
      'A potential SQL injection vulnerability was detected in the login form parameter handling. Input validation appears insufficient.',
    impact:
      'Attackers could potentially execute arbitrary SQL commands, leading to data theft, data manipulation, or complete database compromise.',
    remediation:
      'Implement parameterized queries/prepared statements for all database interactions. Add input validation and sanitization. Deploy a Web Application Firewall (WAF) rule to block injection attempts.',
  },
  {
    id: 'ALT-004',
    title: 'Domain Registration Expiring',
    website: 'Documentation Site',
    domain: 'docs.company.com',
    category: 'Domain Expiration',
    severity: 'Medium',
    date: '2026-11-14',
    time: '04:20 PM',
    read: true,
    description:
      'The domain docs.company.com is set to expire in 30 days (on 2026-12-16). Failure to renew will result in loss of domain ownership.',
    impact:
      'If the domain expires, the documentation site will become inaccessible. There is also a risk of domain hijacking if a malicious actor registers it.',
    remediation:
      'Renew the domain registration immediately through your domain registrar. Enable auto-renewal to prevent future issues. Verify DNS records are correctly configured.',
  },
  {
    id: 'ALT-005',
    title: 'Insecure Cookie Configuration',
    website: 'Customer Portal',
    domain: 'portal.company.com',
    category: 'Website Security Configuration',
    severity: 'High',
    date: '2026-11-14',
    time: '10:10 AM',
    read: false,
    description:
      'Session cookies are missing the Secure and HttpOnly flags, making them accessible to client-side scripts and transmittable over non-HTTPS connections.',
    impact:
      'Session cookies could be stolen via XSS attacks or intercepted over unencrypted connections, leading to account takeover.',
    remediation:
      'Set the Secure flag to ensure cookies are only sent over HTTPS. Set HttpOnly flag to prevent JavaScript access. Consider adding SameSite attribute for CSRF protection.',
  },
  {
    id: 'ALT-006',
    title: 'Outdated TLS Version Supported',
    website: 'API Gateway',
    domain: 'api.company.com',
    category: 'Security Vulnerabilities',
    severity: 'Medium',
    date: '2026-11-13',
    time: '03:30 PM',
    read: true,
    description:
      'The server supports TLS 1.0 and TLS 1.1, which are deprecated and have known vulnerabilities. Modern clients should use TLS 1.2 or 1.3.',
    impact:
      'Connections using deprecated TLS versions are vulnerable to downgrade attacks and cryptographic weaknesses.',
    remediation:
      'Disable TLS 1.0 and TLS 1.1 on the server. Configure the server to only support TLS 1.2 and TLS 1.3. Test compatibility with all client applications.',
  },
  {
    id: 'ALT-007',
    title: 'Missing HSTS Header',
    website: 'Primary Website',
    domain: 'www.company.com',
    category: 'Missing Security Headers',
    severity: 'Low',
    date: '2026-11-12',
    time: '09:00 AM',
    read: true,
    description:
      'The HTTP Strict Transport Security (HSTS) header is not present, which means browsers may allow HTTP connections to the site.',
    impact:
      'Without HSTS, users could be vulnerable to SSL stripping attacks where HTTPS connections are downgraded to HTTP.',
    remediation:
      'Add the Strict-Transport-Security header with an appropriate max-age. Start with a short duration and include subdomains. Consider preloading.',
  },
  {
    id: 'ALT-008',
    title: 'Weak Cipher Suite Enabled',
    website: 'API Gateway',
    domain: 'api.company.com',
    category: 'Website Security Configuration',
    severity: 'Medium',
    date: '2026-11-11',
    time: '01:45 PM',
    read: true,
    description:
      'The server supports weak cipher suites including RC4 and 3DES, which have known cryptographic vulnerabilities.',
    impact:
      'Weak ciphers can be exploited to decrypt traffic or perform man-in-the-middle attacks on encrypted connections.',
    remediation:
      'Update the server SSL/TLS configuration to disable weak cipher suites. Enable only strong ciphers (AES-GCM, ChaCha20-Poly1305). Test with SSL Labs.',
  },
];

export function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>(initialAlerts);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [readFilter, setReadFilter] = useState('All');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const handleMarkRead = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
  };

  const handleMarkUnread = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: false } : a)));
  };

  const handleDismiss = (id: string) => {
    if (window.confirm('Dismiss this alert? This action cannot be undone.')) {
      setAlerts((prev) => prev.filter((a) => a.id !== id));
    }
  };

  const handleMarkAllRead = () => {
    setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
  };

  const handleView = (alert: Alert) => {
    setSelectedAlert(alert);
  };

  const total = alerts.length;
  const unread = alerts.filter((a) => !a.read).length;
  const critical = alerts.filter((a) => a.severity === 'Critical').length;
  const resolved = initialAlerts.length - alerts.length;

  return (
    <div className="min-h-screen bg-[#F4F7FA]">
      <div className="md:ml-64">
        <div className="p-4 md:p-6 md:ml-20 transition-all duration-300">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-semibold text-[#101B2C]">Alerts & Notifications</h1>
              <p className="text-sm text-[#718096]">Monitor and manage security alerts across your assets.</p>
            </div>
          </div>

          <p className="text-xs text-[#718096] mb-4">
            All alerts shown are demonstration data. No actual security findings generated.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6">
            <AlertSummaryCard
              label="Total Alerts"
              value={total}
              icon={Bell}
              iconBgColor="bg-[#36D6C4]/10"
              iconColor="text-[#36D6C4]"
            />
            <AlertSummaryCard
              label="Unread Alerts"
              value={unread}
              icon={AlertTriangle}
              iconBgColor="bg-[#F2B84B]/10"
              iconColor="text-[#F2B84B]"
            />
            <AlertSummaryCard
              label="Critical Alerts"
              value={critical}
              icon={XCircle}
              iconBgColor="bg-[#EF4444]/10"
              iconColor="text-[#EF4444]"
            />
            <AlertSummaryCard
              label="Resolved Alerts"
              value={resolved}
              icon={ShieldCheck}
              iconBgColor="bg-[#22C55E]/10"
              iconColor="text-[#22C55E]"
            />
          </div>

          <AlertFilterBar
            search={search}
            setSearch={setSearch}
            severityFilter={severityFilter}
            setSeverityFilter={setSeverityFilter}
            readFilter={readFilter}
            setReadFilter={setReadFilter}
          />

          <AlertList
            alerts={alerts}
            search={search}
            setSearch={setSearch}
            severityFilter={severityFilter}
            setSeverityFilter={setSeverityFilter}
            readFilter={readFilter}
            setReadFilter={setReadFilter}
            onView={handleView}
            onMarkRead={handleMarkRead}
            onMarkUnread={handleMarkUnread}
            onDismiss={handleDismiss}
            onMarkAllRead={handleMarkAllRead}
          />

          <p className="text-center text-sm text-[#718096] mt-8 pb-8">
            All data shown is demonstration/mock data for preview purposes.
          </p>
        </div>
      </div>

      {selectedAlert && (
        <AlertDetails alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}
    </div>
  );
}