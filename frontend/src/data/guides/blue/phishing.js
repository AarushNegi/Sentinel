// data/guides/blue/phishing.js
export default {
  title: 'Phishing',
  headline: 'Every alert is a clue. Catch it before the click.',
  overview: 'Phishing succeeds by exploiting trust, not systems — which means your best defenses are awareness, filtering, and fast detection rather than patching a vulnerability. Your job is to spot the signals at every stage before the attacker reaches their objective.',
  targets: [
    'Employee inboxes and email gateways',
    'Login pages and authentication systems',
    'Endpoint activity following a suspicious click'
  ],
  stages: [
    { name: 'Reconnaissance', tactic: 'Watch for unusual scraping of employee info on LinkedIn, company directories, or public breach dumps — this often precedes a targeted lure.' },
    { name: 'Weaponization', tactic: 'Monitor threat intel feeds for newly registered lookalike domains or phishing kits mimicking your company\'s login page.' },
    { name: 'Delivery', tactic: 'Use email filtering and attachment sandboxing to catch the message before it reaches an inbox; train users to report suspicious emails.' },
    { name: 'Exploitation', tactic: 'Detect credential entry on a non-corporate domain via browser isolation or DNS filtering — this is often the last chance to stop it.' },
    { name: 'Installation', tactic: 'If a payload executed, use EDR and application whitelisting to catch unauthorized processes or persistence attempts.' },
    { name: 'Command and Control', tactic: 'Monitor outbound traffic for beaconing patterns or connections to newly registered domains.' },
    { name: 'Actions on Objectives', tactic: 'Use DLP and anomaly detection to catch unusual data access or export before real damage is done.' }
  ],
  tips: [
    'The best detection is often a suspicious employee — make reporting easy and blameless.',
    'A single reported phishing email is a chance to block it organization-wide before others click.',
    'Correlate multiple weak signals (unusual login + odd time + new device) rather than waiting for one strong one.'
  ]
}