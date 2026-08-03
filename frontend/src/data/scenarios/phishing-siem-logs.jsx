// data/scenarios/phishing-siem-logs.js
// Searchable SIEM log entries analysts cross-reference against alerts in the queue.
// Each log correlates to a specific alert via sender/domain/IP so the analyst can
// confirm or refute the alert instead of guessing blind.

export default [
  // ── Correlates to Alert 8815 / id 1000 — "Inheritance Alert" phishing (TRUE POSITIVE) ──
  {
    id: 'log-1',
    source: 'Email Gateway',
    timestamp: 'Aug 1st 2026 at 10:41',
    level: 'WARN',
    message: 'Message from eileen@trendymillineryco.me flagged: sender domain registered 6 days ago.',
    tags: ['email', 'domain-age']
  },
  {
    id: 'log-2',
    source: 'DNS Proxy',
    timestamp: 'Aug 1st 2026 at 10:43',
    level: 'INFO',
    message: 'DNS query for trendymillineryco.me resolved to 185.220.101.47 (known low-reputation hosting range).',
    tags: ['dns', 'reputation']
  },
  {
    id: 'log-3',
    source: 'Threat Intel Feed',
    timestamp: 'Aug 1st 2026 at 10:44',
    level: 'ALERT',
    message: '185.220.101.47 matches IOC list — associated with prior mass-phishing campaigns.',
    tags: ['threat-intel', 'ioc']
  },

  // ── Correlates to Alert 8814 / id 1001 — "Invoice #88213" phishing (TRUE POSITIVE) ──
  {
    id: 'log-4',
    source: 'Email Gateway',
    timestamp: 'Jul 28th 2026 at 17:50',
    level: 'WARN',
    message: 'Password-protected attachment from billing@accounts-verify-secure.com — content scan skipped (cannot decrypt).',
    tags: ['email', 'attachment']
  },
  {
    id: 'log-5',
    source: 'DNS Proxy',
    timestamp: 'Jul 28th 2026 at 17:51',
    level: 'INFO',
    message: 'Domain accounts-verify-secure.com is NOT on the corporate vendor allow-list.',
    tags: ['dns', 'allow-list']
  },
  {
    id: 'log-6',
    source: 'Threat Intel Feed',
    timestamp: 'Jul 28th 2026 at 17:52',
    level: 'ALERT',
    message: 'accounts-verify-secure.com registered 3 days ago — typosquat pattern matches known invoice-fraud campaigns.',
    tags: ['threat-intel', 'typosquat']
  },

  // ── Correlates to newsletter alert / id 1002 — FALSE POSITIVE ──
  {
    id: 'log-7',
    source: 'Email Gateway',
    timestamp: 'Jul 05th 2026 at 16:29',
    level: 'INFO',
    message: 'Message from newsletter@krebsonsecurity.com — SPF, DKIM, and DMARC all passed.',
    tags: ['email', 'auth-pass']
  },
  {
    id: 'log-8',
    source: 'Threat Intel Feed',
    timestamp: 'Jul 05th 2026 at 16:29',
    level: 'INFO',
    message: 'krebsonsecurity.com — no matches on any IOC or reputation list. Domain age: 15+ years.',
    tags: ['threat-intel', 'reputation']
  },
  {
    id: 'log-9',
    source: 'Mail Analytics',
    timestamp: 'Jul 05th 2026 at 16:30',
    level: 'INFO',
    message: 'analyst-team@tryhatme.com has received 47 prior emails from this sender over the last 6 months, none flagged.',
    tags: ['history']
  },

  // ── Unrelated noise (id 1003 sysmon) — red herring, not phishing-related ──
  {
    id: 'log-10',
    source: 'Sysmon',
    timestamp: 'Jul 05th 2026 at 16:32',
    level: 'INFO',
    message: 'taskhostw.exe spawned by svchost.exe on win-3451 — standard Windows scheduled task behavior, no C2 indicators.',
    tags: ['endpoint', 'process']
  }
]