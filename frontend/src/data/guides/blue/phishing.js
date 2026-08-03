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
  tips: [
    'The best detection is often a suspicious employee — make reporting easy and blameless.',
    'A single reported phishing email is a chance to block it organization-wide before others click.',
    'Correlate multiple weak signals (unusual login + odd time + new device) rather than waiting for one strong one.'
  ],
  stages: [
    {
      name: 'Reconnaissance',
      narrative: null,
      mitre: 'T1589',
      challenge: {
        prompt: 'You get a tip that someone may be researching your employees online. What\'s your move?',
        options: [
          { id: 'a', text: 'Review what\'s publicly exposed about staff (LinkedIn, org charts, bios) and flag oversharing', outcome: 'best', feedback: 'You can\'t stop recon, but reducing exposed attack-surface information makes future lures harder to craft.' },
          { id: 'b', text: 'Ignore it — recon isn\'t an attack, so there\'s nothing to act on', outcome: 'fail', feedback: 'Recon is the earliest possible warning sign. Ignoring it means losing your best chance to prepare before delivery.', hint: 'Recon activity, even passive, is worth logging and reviewing — it often precedes a targeted campaign.' },
          { id: 'c', text: 'Send a company-wide warning email about "possible phishing"', outcome: 'risky', feedback: 'Too vague to be actionable, and constant unspecific warnings train employees to tune out real alerts later.' }
        ]
      },
      log: 'INFO  Passive OSINT activity noted — no direct organizational contact detected'
    },
    {
      name: 'Weaponization',
      narrative: 'Lure',
      mitre: 'T1587',
      challenge: {
        prompt: 'Threat intel flags a new phishing kit mimicking your company\'s login page. What do you do?',
        options: [
          { id: 'a', text: 'Add the fake login domain to your blocklist and alert the SOC to watch for related traffic', outcome: 'best', feedback: 'Proactive blocking before delivery even happens is the cheapest possible win — no employee ever sees the lure.' },
          { id: 'b', text: 'Wait until an employee actually reports receiving it', outcome: 'fail', feedback: 'By the time someone reports it, others may have already clicked. You had the chance to block it network-wide first.', hint: 'Threat intel exists so you can act before the first click, not after.' },
          { id: 'c', text: 'Forward the intel to IT with no specific action requested', outcome: 'risky', feedback: 'Without a clear next step, this kind of alert often sits unread until it\'s too late to matter.' }
        ]
      },
      log: 'INFO  Threat intel received — lookalike domain identified in the wild'
    },
    {
      name: 'Delivery',
      narrative: 'Bait',
      mitre: 'T1566.001',
      challenge: {
        prompt: 'An email claiming to be "IT Support" lands in an employee\'s inbox from an external domain. How do you handle it?',
        options: [
          { id: 'a', text: 'Check the sender domain against your allow-list and quarantine anything that doesn\'t match', outcome: 'best', feedback: 'Domain verification at the gateway catches typosquatted senders before a human ever has to make a judgment call.' },
          { id: 'b', text: 'Let it through — employees are trained to spot phishing themselves', outcome: 'fail', feedback: 'Training helps, but relying on it alone means your weakest link is your only line of defense. One tired employee is all it takes.', hint: 'Technical filtering should catch what training might miss on a busy day.' },
          { id: 'c', text: 'Manually review every external email before delivery', outcome: 'risky', feedback: 'This doesn\'t scale — email volume will overwhelm manual review, and delays frustrate legitimate business communication.' }
        ]
      },
      log: 'ALERT  Suspicious sender domain flagged by email gateway rule'
    },
    {
      name: 'Exploitation',
      narrative: 'Trap',
      mitre: 'T1204.001',
      challenge: {
        prompt: 'An employee clicks the link and lands on a fake login page. What\'s the best detection layer here?',
        options: [
          { id: 'a', text: 'Browser isolation or DNS filtering blocks the non-corporate domain before credentials are entered', outcome: 'best', feedback: 'This is your last automated line of defense — stopping the page load before the credential form is even seen.' },
          { id: 'b', text: 'Nothing — if the email got through, there\'s no way to stop it now', outcome: 'fail', feedback: 'Giving up here means the attacker gets the credentials by default. Detection layers exist precisely for this moment.', hint: 'Even after delivery, there are still technical controls that can intercept the click itself.' },
          { id: 'c', text: 'Rely on the employee to notice the fake page looks slightly different', outcome: 'risky', feedback: 'Modern phishing pages are often pixel-perfect clones — human visual inspection catches this only some of the time.' }
        ]
      },
      log: 'ALERT  Outbound connection to known-bad domain attempted'
    },
    {
      name: 'Installation',
      narrative: 'Harvest',
      mitre: 'T1098',
      challenge: {
        prompt: 'You see a new mail-forwarding rule and an unfamiliar OAuth app grant on a compromised account. What now?',
        options: [
          { id: 'a', text: 'Revoke the OAuth grant, remove the forwarding rule, and force a password reset immediately', outcome: 'best', feedback: 'This directly removes the attacker\'s persistence mechanisms — the exact things letting them stay in without malware.' },
          { id: 'b', text: 'Just reset the password and consider it resolved', outcome: 'fail', feedback: 'The forwarding rule and OAuth grant survive a password reset. The attacker keeps reading mail even after "fixing" the account.', hint: 'Password resets don\'t undo every persistence mechanism an attacker may have set up.' },
          { id: 'c', text: 'Monitor the account for a few more days before acting', outcome: 'risky', feedback: 'Every extra day gives the attacker more time to read sensitive mail or escalate further inside the account.' }
        ]
      },
      log: 'CRITICAL  Unauthorized OAuth app and mail-forwarding rule detected on user account'
    },
    {
      name: 'Command and Control',
      narrative: 'Harvest',
      mitre: 'T1071',
      challenge: {
        prompt: 'Network monitoring shows an endpoint making regular, low-volume HTTPS calls to an unfamiliar domain. What\'s your next step?',
        options: [
          { id: 'a', text: 'Correlate the beacon pattern with threat intel and isolate the host if it matches known C2 behavior', outcome: 'best', feedback: 'Beaconing patterns are subtle by design — cross-referencing with intel is how you tell normal traffic from disguised C2.' },
          { id: 'b', text: 'Ignore it — it\'s just HTTPS traffic, which is normal and encrypted', outcome: 'fail', feedback: 'Attackers deliberately blend C2 into normal-looking HTTPS traffic. Dismissing it because it\'s "just HTTPS" is exactly the blind spot they\'re counting on.', hint: 'Encrypted doesn\'t mean safe — the pattern of the traffic matters more than the protocol.' },
          { id: 'c', text: 'Block the domain immediately without further investigation', outcome: 'risky', feedback: 'Blocking without confirmation risks disrupting legitimate services and losing the chance to trace what the attacker already accessed.' }
        ]
      },
      log: 'ALERT  Low-frequency beaconing pattern detected from internal host'
    },
    {
      name: 'Actions on Objectives',
      narrative: 'Harvest',
      mitre: 'T1041',
      challenge: {
        prompt: 'DLP flags a slow trickle of files being uploaded to an external file-sharing site from one account. How do you respond?',
        options: [
          { id: 'a', text: 'Investigate what was accessed, contain the account, and determine scope of exposure', outcome: 'best', feedback: 'Slow exfiltration is designed to fly under simple volume-based alarms — full investigation is the only way to know the real damage.' },
          { id: 'b', text: 'Dismiss it since the volume is too small to be a real incident', outcome: 'fail', feedback: 'That\'s exactly why the attacker chose a slow trickle — to stay under naive volume thresholds while still getting the data out.', hint: 'Attackers deliberately keep exfiltration small and slow specifically to avoid triggering size-based alerts.' },
          { id: 'c', text: 'Immediately disable the account without checking what was already taken', outcome: 'risky', feedback: 'Stops future exfiltration, but you lose the chance to determine exactly what was already exposed for a proper incident report.' }
        ]
      },
      log: 'ALERT  DLP flagged unusual low-volume file uploads to external destination'
    }
  ]
}