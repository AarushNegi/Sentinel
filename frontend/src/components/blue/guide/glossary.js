// components/blue/guide/glossary.js
// Plain-English explanations shown by the "What is this?" pop-ups. These are
// generic teaching text: they never describe the active scenario's answer.

export const GLOSSARY = {
  phishing: {
    title: 'Phishing',
    what: 'A fake message that tries to trick someone into clicking a link, opening a file or giving away a password.',
    why: 'Most account break-ins start with a message like this, so analysts check every report carefully.',
    look: 'Look for a sender that does not match the company it claims to be, links that go somewhere unexpected, and pressure to act quickly.',
    example: 'An email that looks like it comes from your bank but links to a look-alike website.',
  },
  soc: {
    title: 'SOC analyst',
    what: 'A Security Operations Centre (SOC) analyst watches security alerts, investigates them and decides how to respond.',
    why: 'You are playing this role: you decide which alerts matter, gather proof and stop attacks.',
    look: 'Work in order: understand the alert, collect evidence, decide, then act.',
    example: 'Reading an alert, checking the email behind it and deciding whether to block a website.',
  },
  severity: {
    title: 'Incident severity',
    what: 'How serious a security incident is likely to be, from Low to Critical.',
    why: 'It decides how quickly a team reacts and who needs to be told.',
    look: 'Severity can change as you learn more. Judge it from the evidence, not just the label on the alert.',
    example: 'Low: unusual but limited. Critical: possible severe damage that needs urgent action.',
  },
  headers: {
    title: 'Email headers',
    what: 'Hidden technical details attached to every email: who really sent it, which servers handled it and whether it passed security checks.',
    why: 'The part of an email you see (the display name) is easy to fake. Headers are much harder to fake.',
    look: 'Compare the real sender address with the name shown, and check where replies would go.',
    example: 'A display name of "IT Support" with a sender address on an unrelated website.',
  },
  sender_domain: {
    title: 'Sender domain',
    what: 'The part of an email address after the @ sign. It shows which organisation controls the mailbox.',
    why: 'Attackers often use a domain that looks similar to a real company.',
    look: 'Read the domain letter by letter and compare it with the real company domain.',
    example: 'acme-payments.test is not the same as acme.test.',
  },
  reply_to: {
    title: 'Reply-To address',
    what: 'The address that receives your reply. It can be different from the address the email was sent from.',
    why: 'Attackers use a different Reply-To so answers go to them.',
    look: 'If Reply-To differs from the sender, ask whether there is a good reason.',
    example: 'An email from a colleague whose replies go to an unrelated outside address.',
  },
  auth: {
    title: 'SPF, DKIM and DMARC',
    what: 'Three checks that help receivers decide whether an email really came from the domain it claims. SPF checks the sending server is allowed. DKIM checks a digital signature. DMARC says what to do when those checks fail.',
    why: 'They help spot forged senders.',
    look: 'Note which checks passed or failed, but never decide from one result alone. A pass does not prove an email is safe, and a fail does not prove it is malicious.',
    example: 'SPF fail plus a mismatched Reply-To is a stronger warning than either alone.',
  },
  url_domain: {
    title: 'URL and domain',
    what: 'A URL is a full web address. The domain is the main name inside it, for example the "example.test" in https://login.example.test/page.',
    why: 'The text of a link can say one thing while the real address goes somewhere else.',
    look: 'Compare the text shown with the real destination, and read the domain closely.',
    example: 'A link reading "company.test" that really points to "company-login.test".',
  },
  ioc: {
    title: 'IOC (Indicator of Compromise)',
    what: 'A clue that may suggest a system or account has been involved in malicious activity, such as a domain, IP address or file fingerprint.',
    why: 'Analysts collect IOCs so they can look for them elsewhere and block them.',
    look: 'Investigate an indicator and gather supporting evidence before deciding to block it.',
    example: 'A domain linked to a suspicious email.',
  },
  hash: {
    title: 'File hash',
    what: 'A short fingerprint calculated from a file. The same file always gives the same hash and any change gives a different one.',
    why: 'Analysts look up a hash in threat databases without having to open the file.',
    look: 'Check whether the hash is already known as malicious.',
    example: 'A hash that matches a known malware family.',
  },
  siem: {
    title: 'SIEM and security event logs',
    what: 'A SIEM is a tool that collects logs (records of events) from many systems so analysts can search them in one place.',
    why: 'Logs show what really happened: who signed in, what was visited and what changed.',
    look: 'Search for the user, the time and the suspicious address from the email.',
    example: 'Searching web proxy logs to see whether anyone visited a suspicious domain.',
  },
  authlogs: {
    title: 'Authentication logs',
    what: 'Records of every sign-in attempt, successful or not, with the time, place and device.',
    why: 'They show whether an attacker used a stolen password.',
    look: 'Look for sign-ins from unfamiliar places or devices, especially soon after a suspicious click.',
    example: 'A sign-in from another country minutes after the employee clicked a link.',
  },
  failed_signin: {
    title: 'Failed sign-in',
    what: 'An attempt to access an account that did not succeed.',
    why: 'Many failures can mean someone is guessing passwords.',
    look: 'Check whether a run of failures was followed by a success.',
    example: 'Several failed attempts and then one success from the same address.',
  },
  unusual_signin: {
    title: 'Unusual sign-in',
    what: 'A login that does not match the usual pattern for that person.',
    why: 'It may mean someone else is using the account.',
    look: 'Compare the location, device and time with the person\'s normal activity.',
    example: 'An employee who works in one city signing in from another country.',
  },
  session: {
    title: 'Session',
    what: 'The period during which a signed-in account stays logged in. Attackers can keep a session open even after a password changes unless it is revoked.',
    why: 'Ending suspicious sessions removes the attacker\'s current access.',
    look: 'Look for sessions from unfamiliar locations or devices.',
    example: 'A web session opened from an address the employee has never used.',
  },
  mailbox_rule: {
    title: 'Mailbox rule',
    what: 'A rule that automatically moves, deletes or forwards email.',
    why: 'Attackers create hidden rules to quietly forward copies of mail to themselves.',
    look: 'Look for rules the user did not create, especially forwarding to outside addresses.',
    example: 'A rule that forwards every message containing "invoice" to an outside mailbox.',
  },
  endpoint: {
    title: 'Endpoint',
    what: 'A computer or device used by a person, such as a laptop.',
    why: 'If someone opened a malicious file, the device itself may be infected.',
    look: 'Look for unexpected programs, scripts or connections on the device.',
    example: 'A laptop running a hidden script after an attachment was opened.',
  },
  session_revocation: {
    title: 'Session revocation',
    what: 'Forcing an account to sign out everywhere so every existing session stops working.',
    why: 'It cuts off an attacker who is already signed in.',
    look: 'Use it when the evidence shows a suspicious session. The real user will need to sign in again.',
    example: 'Revoking sessions after a login from an attacker\'s address.',
  },
  quarantine: {
    title: 'Quarantine',
    what: 'Moving a message into a restricted holding area so people can no longer open it normally.',
    why: 'It stops others from interacting with a dangerous message while you investigate.',
    look: 'Quarantine the message in every affected mailbox, not just one.',
    example: 'Moving a phishing email out of an inbox into a locked folder.',
  },
  containment: {
    title: 'Containment',
    what: 'Actions that stop an attack from spreading or continuing, for example blocking a website or isolating a device.',
    why: 'It limits the damage while you work out the full picture.',
    look: 'Choose actions that match the evidence. Unneeded actions disrupt people.',
    example: 'Blocking a malicious domain for everyone in the company.',
  },
  remediation: {
    title: 'Remediation',
    what: 'Fixing what the attack changed so that systems and accounts are safe and trusted again.',
    why: 'Stopping an attack does not undo its effects. Stolen passwords still work and hidden rules still forward mail until you fix them.',
    look: 'Remove what the attacker left behind, then verify it is really gone.',
    example: 'Resetting a password and deleting a forwarding rule.',
  },
  preservation: {
    title: 'Evidence preservation',
    what: 'Saving a protected copy of evidence before you change or delete anything.',
    why: 'Fixing a system can destroy the proof of what happened.',
    look: 'Preserve forensic artifacts before removing rules or cleaning devices.',
    example: 'Saving a copy of a malicious mailbox rule before deleting it.',
  },
  verification: {
    title: 'Verification and recovery',
    what: 'Checking that your actions really worked and nothing dangerous remains.',
    why: 'An action can fail or miss something, and a case should not be closed on an assumption.',
    look: 'Read the verification results. Every gap is something still to fix.',
    example: 'Confirming no suspicious session or mailbox rule is left.',
  },
  mfa: {
    title: 'MFA (multi-factor authentication)',
    what: 'A second proof of identity, such as a code on a phone, required in addition to a password.',
    why: 'Even if a password is stolen, an attacker cannot sign in without the second factor.',
    look: 'Enforce it on accounts whose password may have been exposed.',
    example: 'A sign-in that asks for a one-time code after the password.',
  },
}

// Short severity descriptions shown on badges. These teach the labels; they are
// not conclusions about the active incident.
export const SEVERITY_TEACH = {
  low: 'Unusual activity with limited immediate concern.',
  medium: 'Worth investigating; the risk is not yet fully known.',
  high: 'Potentially serious activity requiring prompt attention.',
  critical: 'A potentially severe incident requiring urgent response.',
}

export const SEVERITY_MEANING = {
  LOW: 'This incident looks limited. It still needs a quick check so nothing is missed.',
  MEDIUM: 'This incident needs investigation, but there is no confirmed evidence of a widespread compromise yet.',
  HIGH: 'This incident may be serious and needs prompt attention.',
  CRITICAL: 'This incident may be severe and needs urgent response.',
}
