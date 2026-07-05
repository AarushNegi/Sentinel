// data/guides/red/phishing.js
export default {
  title: 'Phishing',
  headline: 'Get one click. That\'s all it takes.',
  overview: 'Phishing exploits trust, not systems. Your job is to craft a lure believable enough that a target hands over credentials or executes a payload without a second thought.',
  targets: [
    'Employee email accounts',
    'Login credentials for internal tools',
    'Any user with access to sensitive systems'
  ],
  stages: [
    { name: 'Reconnaissance', tactic: 'Identify a target employee and learn their role, tools, and habits.' },
    { name: 'Weaponization', tactic: 'Build a convincing fake login page or malicious attachment.' },
    { name: 'Delivery', tactic: 'Send the email through a channel the target trusts.' },
    { name: 'Exploitation', tactic: 'Get the target to click, enter credentials, or open the file.' },
    { name: 'Installation', tactic: 'Drop a persistence mechanism if a payload was executed.' },
    { name: 'Command and Control', tactic: 'Establish a channel back to your infrastructure.' },
    { name: 'Actions on Objectives', tactic: 'Use the captured access to move toward your real goal.' }
  ],
  tips: [
    'Urgency and authority work better than technical sophistication.',
    'Match the sender domain as closely as possible.',
    'Never reuse the same lure twice in one engagement.'
  ]
}