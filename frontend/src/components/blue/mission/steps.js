// components/blue/mission/steps.js
// The mission as a list of short, single-task steps. The list is built from the
// analyst-visible view, so steps that do not apply to this incident (for
// example "Check the attachment" when there is none) never appear. Whether a
// step is complete always comes from recorded server state.

export const CLASS_CHOICES = [
  ['false_positive', 'Harmless', 'The message looks suspicious but turned out to be safe.'],
  ['phishing_no_compromise', 'Phishing, nobody fell for it', 'A phishing email arrived but no account or device was affected.'],
  ['credential_compromise', 'An account was taken over', 'Someone gave away a password and an attacker used it.'],
  ['malware_infection', 'A device was infected', 'A file was opened and malware ran.'],
  ['widespread_campaign', 'An attack on many people', 'Several employees were targeted or affected.'],
]
export const SEVERITY_CHOICES = [['low', 'Low'], ['medium', 'Medium'], ['high', 'High'], ['critical', 'Critical']]
export const CAUSE_CHOICES = [
  ['no_user_interaction', 'Nobody interacted with it', 'The message only arrived.'],
  ['phishing_link_credential_theft', 'A phishing link stole a password', 'Someone clicked and typed their password.'],
  ['malicious_attachment_malware', 'An attachment installed malware', 'Someone opened the file.'],
  ['spoofed_sender_social_engineering', 'A forged sender tricked someone', 'The sender pretended to be someone trusted.'],
  ['multiple_vectors', 'More than one method', 'Several tricks were combined.'],
]
export const RISK_CHOICES = [
  ['none', 'None', 'Everything is contained and recovered.'],
  ['low', 'Low', 'A small, understood risk remains.'],
  ['medium', 'Medium', 'Some fixes are still missing.'],
  ['high', 'High', 'The attacker or malware may still be active.'],
]

const has = (view, id) => view.evidence.some((e) => e.id === id)
const hasPrefix = (view, prefix) => view.evidence.some((e) => e.id.startsWith(prefix))
const objective = (view, id) => view.objectives.find((o) => o.id === id)?.done || false
const action = (view, name) => view.available_actions.find((a) => a.action === name)

export const RESPONSE_GROUPS = {
  contain: ['quarantine_email', 'block_indicator', 'revoke_sessions', 'isolate_endpoint'],
  fix: ['remove_mailbox_rule', 'reset_account', 'enforce_mfa', 'endpoint_cleanup'],
}
const anyDone = (view, names) => names.some((n) => action(view, n)?.targets?.some((t) => t.done))

const STEP_DEFS = [
  { id: 'alerts', title: 'An alert arrives', objective: 'Look at each alert and decide how urgent it is.',
    gate: 'Make a decision for every alert to continue.',
    ready: (v) => v.alerts.every((a) => a.triage) },
  { id: 'email', title: 'Inspect the email', objective: 'Click the sender to see who really sent this message.',
    gate: 'Click the sender and check it against the real organisation.',
    ready: (v) => has(v, 'EV-FIELD-from') },
  { id: 'link', title: 'Check the link', objective: 'Pick a link and find out where it really goes.',
    gate: 'Reveal where at least one link really goes.',
    ready: (v) => hasPrefix(v, 'EV-LINKTARGET-') },
  { id: 'attachment', title: 'Check the attachment', objective: 'Open the file in a safe sandbox. It is never run for real.',
    gate: 'Open the attachment in the sandbox.', include: (v) => v.email.has_attachment,
    ready: (v) => has(v, 'EV-ATTACH') },
  { id: 'security', title: 'Review email security', objective: 'See whether the email passed the checks that catch forged senders.',
    gate: 'Run the email security checks.',
    ready: (v) => has(v, 'EV-HEADERS') },
  { id: 'indicator', title: 'Investigate the indicator', objective: 'Look into the suspicious address or file you found.',
    gate: 'Investigate at least one indicator.',
    ready: (v) => v.indicators.length === 0 || objective(v, 'ioc') },
  { id: 'activity', title: "Check the employee's activity", objective: 'Look for sign-ins and mailbox changes after the email arrived.',
    gate: 'Check at least one kind of activity.',
    ready: (v) => objective(v, 'users') },
  { id: 'decide', title: 'Decide what happened', objective: 'Using your clues, say what kind of incident this is.',
    gate: 'Record your decision to continue.',
    ready: (v) => Boolean(v.assessment) },
  { id: 'contain', title: 'Stop the threat', objective: 'Choose actions that stop the attack. Only act on what you can prove.',
    gate: '', ready: () => true,
    soft: (v) => anyDone(v, RESPONSE_GROUPS.contain) },
  { id: 'fix', title: 'Fix the damage', objective: 'Undo what the attacker changed. Skip anything that was never affected.',
    gate: '', ready: () => true,
    soft: (v) => anyDone(v, RESPONSE_GROUPS.fix) || objective(v, 'remediate') },
  { id: 'verify', title: 'Verify recovery', objective: 'Check that the threat is really gone before you close the case.',
    gate: 'Run both checks to continue.',
    ready: (v) => Boolean(action(v, 'verify_containment')?.done && action(v, 'verify_remediation')?.done) },
  { id: 'affected', title: 'Who was affected?', objective: 'Tick everyone and every device the attack really reached.',
    gate: '', ready: () => true },
  { id: 'cause', title: 'How did it happen?', objective: 'Pick the root cause and the risk that remains.',
    gate: 'Choose a root cause and a remaining risk.', ready: (v, form) => Boolean(form.root_cause && form.residual_risk && form.evidence_preserved !== null) },
  { id: 'close', title: 'Prove it and close the case', objective: 'Choose the clues that prove your conclusion, then close the case.',
    gate: '', ready: () => true },
]

export function buildSteps(view) {
  if (view.status === 'completed') return [{ id: 'debrief', title: 'Mission debrief', objective: 'See how your decisions played out.' }]
  return STEP_DEFS.filter((s) => !s.include || s.include(view))
}

export const isReady = (step, view, form) => (step.ready ? step.ready(view, form) : true)

// Where to resume: the first step whose work is not recorded yet.
export function resumeIndex(steps, view, form) {
  for (let i = 0; i < steps.length; i += 1) {
    const s = steps[i]
    if (!isReady(s, view, form)) return i
    if (s.soft && !s.soft(view)) return i
  }
  return steps.length - 1
}

/* --------------------------------- hints -------------------------------- */

// Three graduated hints per step. They use only visible facts and never state
// the verdict. The server may replace them with a model-written hint.
export function staticHints(stepId, view) {
  const email = view.email?.opened
  const hints = {
    alerts: ['Read the title and the source of the alert.', 'Compare how sure the tool is (confidence) with how serious it says the alert is.', 'An alert you ignore cannot be investigated later, so only dismiss one when the details show it is harmless.'],
    email: ['Look at the line that says who sent the message, then click it.', 'Compare the organisation the sender claims to be with the web address after the @ sign.', 'A mismatch can mean impersonation, but one clue is not proof. Collect more before deciding.'],
    link: ['Find the links in the email and pick one.', 'Compare the words you can read with the address it really goes to.', 'Attackers hide a dangerous address behind friendly words, so the real address is what counts.'],
    attachment: ['The file sits at the bottom of the email.', 'Look at the file type and what the sandbox did with it.', 'Files that ask to run code when opened are a classic way to infect a computer.'],
    security: ['Start with the security checks button.', 'Look at whether each check passed, failed or was missing.', 'These checks help show whether the sender was forged, but no single result decides it.'],
    indicator: ['Pick one of the indicators found so far.', 'Check how new it is and whether anything reports it as harmful.', 'If several sources agree that something is bad, you can be more confident before blocking it.'],
    activity: ['Choose a check, then look at the events that appear.', 'Look for activity from places or devices you do not recognise, after the email arrived.', 'The order of events links the email to what happened on the account.'],
    decide: ['Think about what your clues showed about the sender, link and activity.', 'Ask whether anyone interacted with the email and whether an account or device was affected.', 'Pick the description that matches your evidence, not the one that sounds the most dramatic.'],
    contain: ['Think about what is still dangerous right now.', 'Match each risk you proved with one action. Skip actions you have no proof for.', 'Unneeded actions interrupt real people, so every action should be backed by a clue.'],
    fix: ['Think about what the attacker may have changed.', 'Fix only what your clues show was affected. Save evidence before removing it.', 'Removing something destroys proof of it, so keep a copy first.'],
    verify: ['Run both checks.', 'Read each line: a missing tick is a job still to do.', 'If something fails, go back, fix it and check again.'],
    affected: ['Think about who interacted with the email.', 'Only tick people and devices your evidence shows were affected.', 'Ticking people who were never affected costs points.'],
    cause: ['Think about how the attacker got in.', 'Match the cause to the clues you found, not to a guess.', 'If the remaining risk is not none, say what is still open.'],
    close: ['Pick the clues that best prove your story.', 'Choose only the clues that support your conclusion.', 'Unrelated clues count against you, so be selective.'],
  }
  const list = hints[stepId] || ['Look at the main item on the screen.', 'Look for anything that does not fit.', 'Decide, then check what happened.']
  if (stepId === 'email' && !email) return ['Open the email first.', list[1], list[2]]
  return list
}

export const STEP_TIPS = {
  alerts: { title: 'Your mission.', body: 'Work out whether the reported email is dangerous and what to do about it. Each screen has one job.', button: "Got it, let's start" },
  email: { title: "Let's inspect the email.", body: 'Click the parts of the message to look behind them. The sender is a good place to start.', button: "Got it, let's inspect" },
  activity: { title: 'Look at the timeline.', body: 'Events are listed in order. See what happened after the email arrived.', button: 'Got it' },
  contain: { title: 'Looking is not stopping.', body: 'These actions change the simulated environment. Each one asks you to confirm first.', button: 'Got it' },
  fix: { title: 'Stopping is not fixing.', body: 'Fix what the attacker changed, and keep a copy of any evidence before removing it.', button: 'Got it' },
}

// Plain-language feedback after a verdict. It never says whether the student is right.
export const VERDICT_FEEDBACK = {
  suspicious: 'Noted as suspicious. Keep collecting clues to back it up.',
  legitimate: 'Noted as legitimate. Check the next clues to see if they agree.',
  unsure: 'Noted as unsure. That is fine. More clues will help you decide.',
}
