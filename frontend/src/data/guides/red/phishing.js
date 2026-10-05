// data/guides/red/phishing.js
// Only the Weaponization and Exploitation stages have `preview` data added —
// used by EmailBuilderStage.jsx and CampaignMonitorStage.jsx for the visual redesign.
// All other stages are unchanged from the previous version.

export default {
  title: 'Phishing',
  headline: 'Get one click. That\'s all it takes.',
  overview: 'Phishing exploits trust, not systems. Your job is to craft a lure believable enough that a target hands over credentials or executes a payload without a second thought.',
  targets: [
    'Employee email accounts',
    'Login credentials for internal tools',
    'Any user with access to sensitive systems'
  ],
  tips: [
    'Urgency and authority work better than technical sophistication.',
    'Match the sender domain as closely as possible.',
    'Never reuse the same lure twice in one engagement.'
  ],
  stages: [
    {
      name: 'Reconnaissance',
      narrative: null,
      mitre: 'T1589',
      challenge: {
        prompt: 'Pick your recon method to identify a target.',
        options: [
          { id: 'a', text: 'Check LinkedIn for employee names, roles, and org structure', outcome: 'best', feedback: 'Passive, low-risk, and gives you exactly what you need to write a believable pretext.' },
          { id: 'b', text: 'Call the company help desk pretending to be an employee', outcome: 'fail', feedback: 'The help desk logs the call and flags it internally. Your engagement is burned before you send a single email.', hint: 'Direct contact this early creates a paper trail. Stay passive during recon.' },
          { id: 'c', text: 'Guess emails using firstname.lastname@company.com pattern', outcome: 'risky', feedback: 'It often works, but you have no confirmation you\'ve got the right person or that the account is even active.' }
        ]
      },
      log: 'INFO  Recon started — target identified via passive OSINT'
    },
    {
      name: 'Weaponization',
      narrative: 'Lure',
      mitre: 'T1587',
      challenge: {
        prompt: 'Choose your lure format. This is the email you\'ll send.',
        options: [
          {
            id: 'a',
            text: 'Fake IT password-reset email using the company\'s real branding',
            outcome: 'best',
            feedback: 'Familiar branding lowers suspicion instantly — this is the highest-converting lure format.',
            preview: {
              sender: 'IT Support',
              senderEmail: 'it-support@yourcompany.com',
              subject: 'Action Required: Your Password Expires Today',
              body: 'Hi there,\n\nOur records show your network password will expire in 1 hour. To avoid being locked out of your account, please reset it immediately using the secure link below.\n\nThis is an automated message from IT Services.',
              brandColor: '#2563eb',
              badge: 'Looks official'
            }
          },
          {
            id: 'b',
            text: '"You\'ve won a prize!" email',
            outcome: 'fail',
            feedback: 'Obvious spam. Most mail clients flag it before it even reaches the inbox, and no employee trusts it.',
            hint: 'Your lure needs to look like something the target expects to receive.',
            preview: {
              sender: 'Prize Team',
              senderEmail: 'winner@luckydraw-rewards.com',
              subject: '🎉 YOU HAVE WON $1,000,000!!! CLAIM NOW',
              body: 'CONGRATULATIONS!!!\n\nYou have been randomly selected as our GRAND PRIZE WINNER! Click below within 24 hours to claim your reward before it expires!!!',
              brandColor: '#eab308',
              badge: 'Obvious spam'
            }
          },
          {
            id: 'c',
            text: 'PDF invoice with an embedded macro',
            outcome: 'risky',
            feedback: 'Can work, but modern attachment scanners catch macro-enabled documents more often than not.',
            preview: {
              sender: 'Billing Dept',
              senderEmail: 'billing@vendor-invoices.net',
              subject: 'Invoice_2847.pdf — Payment Due',
              body: 'Please find attached the invoice for last month\'s services. Kindly review and process payment at your earliest convenience.',
              brandColor: '#6b7280',
              badge: 'May get scanned',
              attachment: 'Invoice_2847.docm'
            }
          }
        ]
      },
      log: 'INFO  Phishing template generated — impersonating IT support'
    },
    {
      name: 'Delivery',
      narrative: 'Bait',
      mitre: 'T1566.001',
      challenge: {
        prompt: 'Which sender domain do you use to deliver the email?',
        options: [
          { id: 'a', text: 'it-support@companyname-secure.com (typosquatted domain)', outcome: 'best', feedback: 'Close enough to the real domain that most targets won\'t look twice.' },
          { id: 'b', text: 'randomguy123@gmail.com', outcome: 'fail', feedback: 'A free personal email address claiming to be "IT Support" is an instant red flag. Deleted on sight.', hint: 'Your domain needs to look like it belongs to the organization, not a stranger.' },
          { id: 'c', text: 'A domain already flagged by threat intel from a past campaign', outcome: 'risky', feedback: 'Many mail filters already block it — it might land in spam before the target ever sees it.' }
        ]
      },
      log: 'SUCCESS  Email delivered — urgent password reset request, spam filter bypassed'
    },
    {
      name: 'Exploitation',
      narrative: 'Trap',
      mitre: 'T1204.001',
      challenge: {
        prompt: 'The target opened the email. What\'s your call-to-action?',
        options: [
          {
            id: 'a',
            text: '"Your password expires in 1 hour — reset now" with urgency',
            outcome: 'best',
            feedback: 'Urgency short-circuits careful thinking. This is the highest click-through pattern in real phishing data.',
            preview: { ctaText: 'Reset Password Now', urgency: true, clicks: true }
          },
          {
            id: 'b',
            text: '"Click here to unsubscribe"',
            outcome: 'fail',
            feedback: 'No urgency, no incentive — almost nobody clicks, and you get no credentials.',
            hint: 'Give the target a reason to act immediately, not eventually.',
            preview: { ctaText: 'Unsubscribe', urgency: false, clicks: false }
          },
          {
            id: 'c',
            text: '"Important document attached, open immediately" (macro-enabled)',
            outcome: 'risky',
            feedback: 'Only works if the target has macros enabled — many orgs disable them by default now.',
            preview: { ctaText: 'Open Document', urgency: true, clicks: true, requiresMacro: true }
          }
        ]
      },
      log: 'ALERT  Victim clicked link — credentials submitted on fake login page'
    },
    {
      name: 'Installation',
      narrative: 'Harvest',
      mitre: 'T1098',
      challenge: {
        prompt: 'You have credentials. How do you keep access?',
        options: [
          { id: 'a', text: 'Register a mail-forwarding rule / OAuth app using the stolen credentials', outcome: 'best', feedback: 'No malware, no file dropped — just abuses legitimate account features. Very hard to detect.' },
          { id: 'b', text: 'Drop a custom backdoor executable on their machine', outcome: 'risky', feedback: 'It can work, but AV/EDR tools have a real chance of flagging a new unsigned binary.' },
          { id: 'c', text: 'Log in once, take what you can immediately, and don\'t come back', outcome: 'fail', feedback: 'The session times out and password gets rotated after the incident is noticed — you lose access fast.', hint: 'Think about what lets you come back later without re-phishing.' }
        ]
      },
      log: 'CRITICAL  Backdoor installed using captured credentials'
    },
    {
      name: 'Command and Control',
      narrative: 'Harvest',
      mitre: 'T1071',
      challenge: {
        prompt: 'How do you maintain a channel back to your infrastructure?',
        options: [
          { id: 'a', text: 'Blend C2 traffic over HTTPS with low-frequency beacons', outcome: 'best', feedback: 'Looks like normal web traffic. Low beacon frequency avoids traffic-pattern-based detection.' },
          { id: 'b', text: 'Beacon every second over a raw unencrypted socket', outcome: 'fail', feedback: 'Immediately flagged — unencrypted, high-frequency traffic to an unknown IP is a textbook SOC alert.', hint: 'Your traffic needs to blend in with what the network normally sees.' },
          { id: 'c', text: 'Use a popular C2 framework\'s default, unmodified traffic profile', outcome: 'risky', feedback: 'Signature-based detection tools often have this exact default profile in their ruleset.' }
        ]
      },
      log: 'CRITICAL  Outbound C2 connection established'
    },
    {
      name: 'Actions on Objectives',
      narrative: 'Harvest',
      mitre: 'T1041',
      challenge: {
        prompt: 'You have persistent access. What\'s the payoff?',
        options: [
          { id: 'a', text: 'Quietly exfiltrate a small set of high-value files over time', outcome: 'best', feedback: 'Slow and targeted — stays under most Data Loss Prevention (DLP) thresholds.' },
          { id: 'b', text: 'Immediately dump the entire file server', outcome: 'fail', feedback: 'A massive spike in outbound traffic trips DLP and network monitoring alarms almost instantly.', hint: 'A sudden, huge data transfer is one of the easiest things for defenders to catch.' },
          { id: 'c', text: 'Deploy ransomware across the network', outcome: 'risky', feedback: 'Guarantees detection immediately — only makes sense if disruption, not stealth, was the actual goal.' }
        ]
      },
      log: 'CRITICAL  Sensitive data exfiltrated to external server'
    }
  ]
}