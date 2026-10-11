// components/blue/guide/guidance.js
// What the simulation says after an action. All text is generic teaching
// content combined with facts the student can already see in the public view,
// so it cannot leak the answer and works for AI-generated and built-in scenarios.

// Explanations shown after an action. `res` is the server's answer.
const ACTION_RESULTS = {
  select_alert: ['Alert opened', 'You can now read the details. Decide whether it needs investigation.'],
  triage_alert: ['Decision recorded', 'Your decision is saved. Triage the remaining alerts or continue the investigation.'],
  open_email: ['Email opened', 'Now check the sender, the links and any attachment. Look for anything that does not match what a genuine business email would contain.'],
  view_raw_headers: ['Raw headers loaded', 'These are the technical details behind the email. Use them together with the sender and authentication results.'],
  inspect_header_field: ['Header inspected', 'Compare this value with what the email claims to be. One odd field is a clue, not proof.'],
  analyze_headers: ['Email authentication checked', 'You reviewed the sender checks (SPF, DKIM, DMARC). Use them together with the email content and the links. No single result decides the case.'],
  reveal_link: ['Link destination revealed', 'The link was not opened. You can now compare the text shown with the real destination.'],
  inspect_url: ['Destination analyzed safely', 'The simulator checked the destination without visiting it. Review what it found.'],
  inspect_attachment: ['Attachment analyzed safely', 'The file was not run. Review the findings before drawing a conclusion.'],
  ioc_lookup: ['Indicator analyzed', 'Read what was checked and what it means. Confirm with more than one source before you block anything.'],
  search_siem: ['Event logs searched', 'Compare these results with the email and the user\'s activity.'],
  collect_log: ['Record saved as evidence', 'The record is now in your clues.'],
  analyze_auth_logs: ['Sign-in activity reviewed', 'Look for sign-ins from unfamiliar places or devices, especially soon after the email arrived.'],
  investigate_user: ['Email activity reviewed', 'Check for mailbox rules or unusual mail activity.'],
  investigate_endpoint: ['Endpoint activity reviewed', 'Look for signs of a malicious program or unusual connections.'],
  preserve_evidence: ['Evidence preserved', 'A protected copy has been saved. You can now remove or change the original safely.'],
  quarantine_email: ['Email quarantined', 'The message is restricted in this mailbox. Other risks, such as accounts or devices, are not affected by this action.'],
  block_indicator: ['Indicator blocked', 'The indicator is now blocked. Make sure you blocked it because the evidence supports it.'],
  revoke_sessions: ['Sessions revoked', 'The user is signed out of every session. Check whether any other suspicious activity remains.'],
  isolate_endpoint: ['Endpoint isolated', 'The device is cut off from the network. Preserve its evidence before it is cleaned.'],
  reset_account: ['Account reset', 'The password was reset. Make sure no suspicious sessions or rules remain.'],
  enforce_mfa: ['MFA enforced', 'A second factor is now required for this account.'],
  remove_mailbox_rule: ['Mailbox rule action completed', 'Check that no other suspicious rules or sessions remain.'],
  endpoint_cleanup: ['Endpoint cleaned', 'Cleaning removes malware, but you still need to verify recovery.'],
  set_assessment: ['Assessment recorded', 'Your working assessment is saved. You can update it as new evidence arrives.'],
}

export const CONSEQUENTIAL = new Set([
  'quarantine_email', 'block_indicator', 'revoke_sessions', 'isolate_endpoint',
  'reset_account', 'enforce_mfa', 'remove_mailbox_rule', 'endpoint_cleanup',
])

// Open risk visible in the public view. Only states the student has already
// discovered are used ("unknown" means not yet investigated).
export function remainingRisk(view) {
  const out = []
  view.users.forEach((u) => {
    if (u.session === 'suspicious') out.push(`${u.name} still has a suspicious session.`)
    if (u.mailbox_rule === 'present') out.push(`${u.name} still has a malicious mailbox rule.`)
  })
  return out
}

// Builds the card shown after an action. `res` is the successful server result.
export function explainResult(action, res, view) {
  const [title, body] = ACTION_RESULTS[action] || ['Action completed', res.message || 'The simulation state was updated.']
  const result = { kind: 'ok', title, body, detail: res.message || '', next: '', risks: [] }

  if (res.verification) {
    const v = res.verification
    const recovery = v.kind === 'remediation'
    if (v.complete) {
      result.title = recovery ? 'Recovery verified' : 'Containment verified'
      result.body = recovery
        ? 'Every recovery check passed in the simulation.'
        : 'Every containment check passed in the simulation.'
      result.next = recovery ? 'Continue to Complete the Case.' : 'Continue to Fix and Recover.'
    } else {
      result.kind = 'warn'
      result.title = recovery ? 'Recovery check incomplete' : 'Containment check found gaps'
      result.body = 'Some required conditions have not been met. Review the outstanding findings before closing the case.'
      result.next = 'Fix the gaps listed below, then verify again.'
    }
    result.lines = v.lines
    return result
  }

  if (CONSEQUENTIAL.has(action)) {
    result.risks = remainingRisk(view)
    result.next = result.risks.length
      ? 'Keep going: some risk is still open (see below).'
      : 'Check whether anything else needs action, then verify.'
  }
  if (res.new_evidence?.length) {
    result.next = result.next || `${res.new_evidence.length} new evidence item${res.new_evidence.length === 1 ? '' : 's'} added to your clues.`
  }
  return result
}

// Turns a server refusal into guidance. The server's own reason is kept.
export function explainError(data, status) {
  const reason = data?.error || ''
  if (status === 409) {
    return { kind: 'error', title: 'This session can no longer be changed',
      body: reason || 'Another window or an older version changed this investigation. Reload the page to continue.' }
  }
  return {
    kind: 'error',
    title: 'You cannot complete this step yet',
    body: reason || 'Complete the required investigation action first.',
    detail: 'Review the current objective to see what remains.',
  }
}

export const NETWORK_ERROR = {
  kind: 'error',
  title: 'Sentinel could not reach the server',
  body: 'Your last action was not recorded. Check that the backend is running, then try again.',
}

// Teaching text for the three response actions that need more than a label.
export const CONFIRM_COPY = {
  quarantine_email: { title: 'Quarantine this email?', verb: 'Quarantine',
    body: 'Quarantine restricts access to the selected email in this simulation. This can help prevent further interaction while you investigate the incident.',
    consideration: 'It only affects the message. It does not remove other risks such as a stolen password or an infected device.' },
  block_indicator: { title: 'Block this indicator?', verb: 'Block',
    body: 'Blocking stops everyone in the organisation from reaching this address or file.',
    consideration: 'Only block what you have verified as malicious. Blocking a legitimate service disrupts business.' },
  revoke_sessions: { title: 'Revoke these sessions?', verb: 'Revoke',
    body: 'This signs the user out everywhere and ends any session an attacker may be using.',
    consideration: 'The real user will have to sign in again. It does not change the password.' },
  isolate_endpoint: { title: 'Isolate this device?', verb: 'Isolate',
    body: 'Isolation cuts the device off from the network so malware cannot spread or call home.',
    consideration: 'The user cannot work on this device until it is released. Preserve evidence before cleaning.' },
  reset_account: { title: 'Reset this account?', verb: 'Reset',
    body: 'This forces a new password and invalidates the old one, so stolen credentials stop working.',
    consideration: 'The user is locked out until they set a new password. Only reset accounts with evidence of exposure.' },
  enforce_mfa: { title: 'Require multi-factor authentication?', verb: 'Enforce MFA',
    body: 'The account will need a second proof of identity in addition to its password.',
    consideration: 'It protects against future password theft but does not remove an existing attacker session.' },
  remove_mailbox_rule: { title: 'Remove the malicious mailbox rules?', verb: 'Remove',
    body: 'This deletes forwarding rules the attacker created so mail stops leaving the mailbox.',
    consideration: 'Removing a rule also removes evidence of it. Preserve the evidence first.' },
  endpoint_cleanup: { title: 'Clean this device?', verb: 'Clean',
    body: 'Cleaning removes malware and its persistence from the isolated device.',
    consideration: 'Some evidence on the device is lost. Preserve it first, then verify recovery.' },
  close_incident: { title: 'Close this case?', verb: 'Close case',
    body: 'Closing submits your classification, root cause, affected scope and supporting evidence for scoring.',
    consideration: 'You cannot reopen the case. Closing with exposure still unresolved is scored as a gap.' },
}
