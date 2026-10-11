// data/scenarios/ir-ransomware.js
// Incident Response scenario: suspected ransomware at Acme Finance.
// Based on the worked example in the Incident Response Guide (NIST SP 800-61 lifecycle).
// All activity is simulated. Times are minutes since midnight.

const t = (h, m) => h * 60 + m

export default {
  id: 'ir-ransomware',
  caseId: 'INC-2026-0042',
  title: 'Suspected ransomware at Acme Finance',
  incidentStart: t(8, 41),
  detectAt: t(8, 45),

  assets: [
    { id: 'MAIL-GW', role: 'Mail gateway', owner: 'IT Operations', os: 'Appliance', criticality: 'Medium' },
    { id: 'WS-014', role: 'Employee workstation', owner: 'J. Carter (Accounts)', os: 'Windows 11', criticality: 'Medium' },
    { id: 'WS-022', role: 'Employee workstation', owner: 'M. Hill (Finance)', os: 'Windows 11', criticality: 'Medium' },
    { id: 'FS-01', role: 'File server (Finance share)', owner: 'IT Operations', os: 'Windows Server 2022', criticality: 'High' },
    { id: 'DC-01', role: 'Domain controller', owner: 'IT Operations', os: 'Windows Server 2022', criticality: 'Critical' },
    { id: 'DB-01', role: 'Database server', owner: 'Finance Systems', os: 'Windows Server 2022', criticality: 'High' },
    { id: 'C2', role: 'External server (unknown)', owner: 'Unknown', os: 'Unknown', criticality: 'n/a', external: true }
  ],

  nodes: [
    { id: 'C2', x: 70, y: 55 },
    { id: 'MAIL-GW', x: 70, y: 175 },
    { id: 'WS-014', x: 235, y: 115 },
    { id: 'WS-022', x: 410, y: 55 },
    { id: 'FS-01', x: 410, y: 175 },
    { id: 'DC-01', x: 235, y: 255 },
    { id: 'DB-01', x: 545, y: 175 }
  ],

  edges: [
    { a: 'MAIL-GW', b: 'WS-014', activeWhen: ['e3', 'e4'] },
    { a: 'WS-014', b: 'C2', activeWhen: ['e7'] },
    { a: 'WS-014', b: 'FS-01', activeWhen: ['e12'] },
    { a: 'WS-014', b: 'WS-022', activeWhen: ['e13'] },
    { a: 'WS-014', b: 'DC-01', activeWhen: [] },
    { a: 'FS-01', b: 'DB-01', activeWhen: [] },
    { a: 'WS-022', b: 'FS-01', activeWhen: [] }
  ],

  events: [
    { id: 'e0', at: t(8, 12), source: 'Windows Security', host: 'WS-022', user: 'mhill', severity: 'info', message: 'Successful interactive logon.', stage: 'Baseline', noise: true },
    { id: 'e1', at: t(8, 20), source: 'DNS', host: 'WS-031', user: 'asingh', severity: 'info', message: 'DNS query for teams.microsoft.com.', stage: 'Baseline', noise: true },
    { id: 'e2', at: t(8, 30), source: 'Firewall', host: 'WS-031', user: 'asingh', severity: 'info', message: 'Outbound HTTPS allowed to Microsoft 365 endpoints.', stage: 'Baseline', noise: true },

    { id: 'e3', at: t(8, 41), source: 'Email Gateway', host: 'MAIL-GW', user: 'jcarter', severity: 'medium', message: 'Inbound email from billing@acme-invoices.co delivered to jcarter@acme.local with attachment Invoice_Q3.docm.', mitre: 'T1566.001', stage: 'Delivery', key: true, ioc: 'Invoice_Q3.docm', iocType: 'file' },
    { id: 'e4', at: t(8, 43), source: 'Sysmon', host: 'WS-014', user: 'jcarter', severity: 'high', message: 'WINWORD.EXE spawned powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...', mitre: 'T1059.001', stage: 'Execution', state: 'compromised', key: true },
    { id: 'e5', at: t(8, 44), source: 'DNS', host: 'WS-014', user: 'jcarter', severity: 'medium', message: 'DNS query for update-cdn-sync.com. Domain first seen on this network 2 days ago.', mitre: 'T1071.004', stage: 'Command and control', state: 'suspicious', key: true, ioc: 'update-cdn-sync.com', iocType: 'domain' },
    { id: 'e6', at: t(8, 45), source: 'EDR', host: 'WS-014', user: 'jcarter', severity: 'high', message: 'ALERT: Office application spawned PowerShell with an encoded command.', mitre: 'T1059.001', stage: 'Execution', alert: true, key: true },
    { id: 'e7', at: t(8, 46), source: 'Firewall', host: 'WS-014', user: 'jcarter', severity: 'medium', message: 'Outbound HTTPS to 185.220.101.47:443 (update-cdn-sync.com), repeating every 60 seconds.', mitre: 'T1071.001', stage: 'Command and control', c2: true, key: true, ioc: '185.220.101.47', iocType: 'ip' },

    { id: 'e8', at: t(8, 50), source: 'Windows Security', host: 'DB-01', user: 'svc-backup', severity: 'info', message: 'Service logon: scheduled backup agent.', stage: 'Baseline', noise: true },
    { id: 'e9', at: t(8, 52), source: 'Sysmon', host: 'WS-014', user: 'jcarter', severity: 'high', message: 'powershell.exe opened a handle to lsass.exe (PROCESS_VM_READ).', mitre: 'T1003.001', stage: 'Credential access', needs: ['e4'], state: 'compromised', key: true },
    { id: 'e10', at: t(8, 58), source: 'Windows Security', host: 'WS-014', user: 'jcarter', severity: 'high', message: "Scheduled task 'OneDriveSyncHelper' created. Runs C:\\Users\\jcarter\\AppData\\Roaming\\svc.ps1 at logon.", mitre: 'T1053.005', stage: 'Persistence', needs: ['e4'], key: true, ioc: 'svc.ps1', iocType: 'file' },
    { id: 'e11', at: t(9, 3), source: 'Windows Security', host: 'DC-01', user: 'jcarter', severity: 'low', message: 'Kerberos TGT requested (normal working-hours pattern).', stage: 'Baseline', noise: true },

    { id: 'e12', at: t(9, 7), source: 'Windows Security', host: 'FS-01', user: 'jcarter', severity: 'high', message: 'Network logon (SMB) from WS-014. jcarter has never authenticated to FS-01 before.', mitre: 'T1021.002', stage: 'Lateral movement', via: 'WS-014', needs: ['e9'], usesCreds: true, c2: true, state: 'suspicious', key: true },
    { id: 'e19', at: t(9, 10), source: 'EDR', host: 'WS-040', user: 'itadmin', severity: 'low', message: 'Unsigned installer executed (approved IT deployment tool).', stage: 'Baseline', noise: true },
    { id: 'e20', at: t(9, 12), source: 'DNS', host: 'WS-031', user: 'asingh', severity: 'info', message: 'DNS query for outlook.office365.com.', stage: 'Baseline', noise: true },
    { id: 'e13', at: t(9, 14), source: 'Windows Security', host: 'WS-022', user: 'jcarter', severity: 'high', message: 'RDP logon from WS-014 using jcarter.', mitre: 'T1021.001', stage: 'Lateral movement', via: 'WS-014', needs: ['e9'], usesCreds: true, c2: true, state: 'compromised', key: true },
    { id: 'e14', at: t(9, 18), source: 'File Server Audit', host: 'FS-01', user: 'jcarter', severity: 'medium', message: 'Directory enumeration of \\\\FS-01\\Finance (12,480 files).', mitre: 'T1083', stage: 'Discovery', needs: ['e12'], usesCreds: true, state: 'compromised' },
    { id: 'e15', at: t(9, 20), source: 'Sysmon', host: 'FS-01', user: 'jcarter', severity: 'critical', message: 'vssadmin.exe delete shadows /all /quiet', mitre: 'T1490', stage: 'Impact', needs: ['e12'], hostBlocked: true, state: 'compromised', key: true },
    { id: 'e16', at: t(9, 24), source: 'File Server Audit', host: 'FS-01', user: 'jcarter', severity: 'critical', message: 'Mass rename: 2,300 files changed to *.locked in 60 seconds.', mitre: 'T1486', stage: 'Impact', needs: ['e15'], hostBlocked: true, state: 'encrypted', key: true },
    { id: 'e17', at: t(9, 31), source: 'EDR', host: 'WS-022', user: 'jcarter', severity: 'critical', message: 'Mass file modification with .locked extension.', mitre: 'T1486', stage: 'Impact', needs: ['e13'], hostBlocked: true, state: 'encrypted', key: true },
    { id: 'e18', at: t(9, 35), source: 'File Server Audit', host: 'FS-01', user: 'jcarter', severity: 'critical', message: 'README_RESTORE.txt created in 41 directories.', mitre: 'T1486', stage: 'Impact', needs: ['e16'], hostBlocked: true, state: 'encrypted', key: true }
  ],

  actions: [
    // Containment
    { id: 'isolate-ws014', phase: 'containment', label: 'Isolate WS-014 with EDR network containment', detail: 'Cuts the host off the network but keeps disk and memory intact for forensics.', cost: 3, rating: 'best', core: true, effect: { type: 'isolate', host: 'WS-014' }, feedback: 'Stops the beacon and lateral movement while preserving evidence. Isolation does not remove persistence, so eradication is still needed.' },
    { id: 'disable-jcarter', phase: 'containment', label: "Disable jcarter's account and revoke active sessions", detail: 'Stops the stolen credentials from being used anywhere else.', cost: 2, rating: 'best', core: true, effect: { type: 'disable', user: 'jcarter' }, feedback: 'Good. Credentials were dumped from LSASS, so assume the account is compromised. Disabling it blocks any further logons that use it.' },
    { id: 'block-c2', phase: 'containment', label: 'Block update-cdn-sync.com and 185.220.101.47 at the firewall', detail: 'Cuts the attacker command channel for every host.', cost: 3, rating: 'best', core: true, effect: { type: 'c2' }, feedback: 'Good. Blocking the IOCs breaks operator control, so hands-on-keyboard steps like lateral movement stop.' },
    { id: 'isolate-fs01', phase: 'containment', label: 'Isolate FS-01 (Finance file server)', detail: 'Disruptive: the Finance team loses its share until it is restored.', cost: 3, rating: 'best', affectedHost: 'FS-01', effect: { type: 'isolate', host: 'FS-01' }, feedback: 'Right call. FS-01 shows attacker activity, and isolating it stops encryption from progressing.', unaffectedFeedback: 'Premature. FS-01 shows no attacker activity yet, so isolating it disrupts Finance without evidence. Scope first.' },
    { id: 'isolate-ws022', phase: 'containment', label: 'Isolate WS-022 (Finance workstation)', detail: 'Stops spread from a second infected workstation.', cost: 3, rating: 'best', affectedHost: 'WS-022', effect: { type: 'isolate', host: 'WS-022' }, feedback: 'Right call. WS-022 shows attacker activity and should be contained.', unaffectedFeedback: 'Premature. WS-022 shows no attacker activity yet, so this is disruption without evidence.' },
    { id: 'power-off-ws014', phase: 'containment', label: 'Power off WS-014 immediately', detail: 'Fast, but destroys volatile memory evidence.', cost: 1, rating: 'risky', effect: { type: 'isolate', host: 'WS-014' }, feedback: 'It stops the host, but you lose memory evidence (the injected PowerShell, credentials in RAM). Network isolation preserves evidence.' },
    { id: 'reset-all', phase: 'containment', label: 'Force a password reset for every employee', detail: 'Broad and disruptive, and not scoped to the compromised account.', cost: 6, rating: 'risky', feedback: 'Heavy-handed. It takes time, disrupts everyone, and does not stop the active session on WS-014. Target the affected account first.' },
    { id: 'wait-monitor', phase: 'containment', label: 'Keep monitoring for 5 minutes before acting', detail: 'Gather more evidence before touching anything.', cost: 5, rating: 'wrong', feedback: 'The evidence is already sufficient: encoded PowerShell from Word, a rare domain, and a beacon. Waiting gives the attacker time to dump credentials and move laterally.' },

    // Eradication
    { id: 'remove-persistence', phase: 'eradication', label: "Remove the 'OneDriveSyncHelper' task and svc.ps1", detail: 'Deletes the persistence mechanism found in the logs.', cost: 4, rating: 'best', core: true, unlock: { anyOf: ['isolate-ws014', 'power-off-ws014', 'disable-jcarter', 'block-c2'] }, lockedReason: 'Contain the incident first.', feedback: 'Correct. The scheduled task would restart the attacker script after any reconnect or reboot.' },
    { id: 'rotate-creds', phase: 'eradication', label: 'Rotate jcarter credentials and secrets cached on WS-014', detail: 'Credentials were read from LSASS, so treat them as exposed.', cost: 4, rating: 'best', core: true, unlock: { anyOf: ['isolate-ws014', 'power-off-ws014', 'disable-jcarter', 'block-c2'] }, lockedReason: 'Contain the incident first.', feedback: 'Correct. Rotate exposed secrets, not just the password the user typed.' },
    { id: 'block-macros', phase: 'eradication', label: 'Block Office macros from internet-sourced files by policy', detail: 'Fixes the weakness that let the attachment run.', cost: 3, rating: 'best', core: true, unlock: { anyOf: ['isolate-ws014', 'power-off-ws014', 'disable-jcarter', 'block-c2'] }, lockedReason: 'Contain the incident first.', feedback: 'Correct. Closing the entry point is part of eradication, not only cleaning the host.' },
    { id: 'av-only', phase: 'eradication', label: 'Run a quick antivirus scan and call it clean', detail: 'Fast, but only looks for known file signatures.', cost: 5, rating: 'risky', unlock: { anyOf: ['isolate-ws014', 'power-off-ws014', 'disable-jcarter', 'block-c2'] }, lockedReason: 'Contain the incident first.', feedback: 'An AV scan will not reliably find a scheduled task, stolen credentials, or fileless PowerShell. Clean means verified, not scanned.' },
    { id: 'delete-note', phase: 'eradication', label: 'Delete the README_RESTORE.txt ransom notes', detail: 'Tidies up the file server.', cost: 2, rating: 'wrong', unlock: { anyOf: ['isolate-ws014', 'power-off-ws014', 'disable-jcarter', 'block-c2'] }, lockedReason: 'Contain the incident first.', feedback: 'That removes evidence and fixes nothing. Preserve the notes: they are artifacts for scope and for any legal or law-enforcement reporting.' },

    // Recovery
    { id: 'rebuild-ws014', phase: 'recovery', label: 'Rebuild WS-014 from a trusted image', detail: 'Do not trust a host that ran attacker code.', cost: 8, rating: 'best', core: true, unlock: { allOf: ['remove-persistence', 'rotate-creds'] }, lockedReason: 'Finish eradication first.', feedback: 'Correct. Rebuilding from a known-good state is safer than cleaning a compromised host.' },
    { id: 'rebuild-ws022', phase: 'recovery', label: 'Rebuild WS-022 from a trusted image', detail: 'WS-022 ran attacker activity.', cost: 8, rating: 'best', coreIfAffected: true, affectedHost: 'WS-022', unlock: { allOf: ['remove-persistence', 'rotate-creds'] }, lockedReason: 'Finish eradication first.', feedback: 'Correct. WS-022 was compromised, so rebuild it.', unaffectedFeedback: 'Unnecessary. WS-022 shows no attacker activity, so rebuilding it wastes time.' },
    { id: 'restore-fs01', phase: 'recovery', label: 'Restore FS-01 from the last known-good offline backup', detail: 'Restores the Finance share from before the attack.', cost: 10, rating: 'best', coreIfAffected: true, affectedHost: 'FS-01', unlock: { allOf: ['remove-persistence', 'rotate-creds'] }, lockedReason: 'Finish eradication first.', feedback: 'Correct. Restore from a trusted offline backup taken before the attack.', unaffectedFeedback: 'Unnecessary. FS-01 was never touched in this run, so there is nothing to restore.' },
    { id: 'verify-monitor', phase: 'recovery', label: 'Reconnect systems and monitor for renewed activity (5 min)', detail: 'Reconnect carefully and watch for the same indicators.', cost: 5, rating: 'best', core: true, unlock: { allOf: ['rebuild-ws014'] }, lockedReason: 'Rebuild WS-014 first.', feedback: 'Correct. Recovery is not done until you confirm the attacker is not coming back.' },
    { id: 'pay-ransom', phase: 'recovery', label: 'Pay the ransom to get a decryptor', detail: 'Ends the incident quickly, supposedly.', cost: 1, rating: 'wrong', unlock: { allOf: ['remove-persistence', 'rotate-creds'] }, lockedReason: 'Finish eradication first.', feedback: 'Paying gives no guarantee of recovery, funds the attacker, and does not close the entry point. Restore from backups instead.' }
  ]
}