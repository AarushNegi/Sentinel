// components/blue/mission/DecisionScreens.jsx
// The decision steps: classify, stop the threat, fix the damage, verify, then
// a short three-screen closure. Every action goes through `ask`, which shows a
// confirmation first, and every result comes from the server.
import { useMemo } from 'react'
import { Term } from '../guide/HelpUI'
import { prettify } from '../blueApi'
import { CAUSE_CHOICES, CLASS_CHOICES, RESPONSE_GROUPS, RISK_CHOICES, SEVERITY_CHOICES } from './steps'

function Choice({ name, value, current, onChange, title, text }) {
  return (
    <label className={`bg-choice${current === value ? ' on' : ''}`}>
      <input type="radio" name={name} checked={current === value} onChange={() => onChange(value)} />
      <span><strong>{title}</strong>{text && <small>{text}</small>}</span>
    </label>
  )
}

/* ------------------------------- decide -------------------------------- */

export function DecideScreen({ view, busy, completed, run, form, setForm }) {
  const recorded = view.assessment
  const ok = form.classification && form.severity
  return (
    <section className="bg-inspector" aria-label="Your decision">
      <fieldset className="bg-choices">
        <legend>What kind of incident is this?</legend>
        {CLASS_CHOICES.map(([v, t, d]) => (
          <Choice key={v} name="classification" value={v} current={form.classification} title={t} text={d}
            onChange={(x) => setForm({ ...form, classification: x })} />
        ))}
      </fieldset>
      <div className="bg-row" role="group" aria-label="How serious is it?">
        <span><Term id="severity">How serious?</Term></span>
        {SEVERITY_CHOICES.map(([v, l]) => (
          <button key={v} type="button" className={form.severity === v ? 'bg-btn bg-chosen' : 'bg-btn'} aria-pressed={form.severity === v}
            onClick={() => setForm({ ...form, severity: v })}>{l}</button>
        ))}
      </div>
      <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !ok}
        onClick={() => run('set_assessment', null, { classification: form.classification, severity: form.severity })}>
        Record my decision
      </button>
      {recorded && (
        <p className="bg-small" role="status">Recorded: {prettify(recorded.classification)}, {recorded.severity} severity. You can change it until you close the case.</p>
      )}
    </section>
  )
}

/* ------------------------- contain and fix steps ------------------------- */

const COPY = {
  quarantine_email: { title: 'Quarantine the email', text: 'Locks the message so nobody can open it.', verb: 'Quarantine', label: (t) => `Quarantine for ${t.label}` },
  block_indicator: { title: 'Block an address', text: 'Stops everyone reaching it. Only for confirmed bad ones.', verb: 'Block', label: (t) => `Block ${t.label}` },
  revoke_sessions: { title: 'Sign the user out everywhere', text: 'Ends any session an attacker is using.', verb: 'Revoke', label: (t) => `Revoke sessions: ${t.label}` },
  isolate_endpoint: { title: 'Isolate a device', text: 'Cuts the device off the network.', verb: 'Isolate', label: (t) => `Isolate endpoint of ${t.label}` },
  remove_mailbox_rule: { title: 'Remove malicious mailbox rules', text: 'Stops mail being secretly forwarded.', verb: 'Remove', label: (t) => `Remove forwarding rules: ${t.label}` },
  reset_account: { title: 'Reset the password', text: 'Makes a stolen password useless.', verb: 'Reset', label: (t) => `Reset credentials: ${t.label}` },
  enforce_mfa: { title: 'Require a second sign-in step', text: 'Adds a code on top of the password.', verb: 'Require', label: (t) => `Enforce MFA: ${t.label}` },
  endpoint_cleanup: { title: 'Clean a device', text: 'Removes malware from an isolated device.', verb: 'Clean', label: (t) => `Clean endpoint of ${t.label}` },
}

function ActionCard({ view, action, busy, completed, ask }) {
  const a = view.available_actions.find((x) => x.action === action)
  const c = COPY[action]
  if (!a || !a.targets || !c) return null
  return (
    <article className="bg-action-card">
      <h2>{c.title}</h2>
      <p>{c.text}</p>
      {a.targets.length === 0 ? <p className="bg-small">{a.reason || 'Nothing to act on yet.'}</p> : (
        <ul className="bg-targets">
          {a.targets.map((t) => (
            <li key={t.id}>
              <span>{t.label}</span>
              <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !t.enabled} aria-label={c.label(t)}
                title={t.reason || ''} onClick={() => ask(action, t.id, t.label)}>{t.done ? 'Done ✓' : c.verb}</button>
              {!t.enabled && !t.done && t.reason && <small>{t.reason}</small>}
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}

export function RespondScreen({ mode, view, busy, completed, ask, run, evidenceCard }) {
  const list = RESPONSE_GROUPS[mode].filter((a) => view.available_actions.some((x) => x.action === a && x.targets))
  const preservable = view.evidence.filter((e) => e.preservable)
  const siem = view.available_actions.find((a) => a.action === 'search_siem')?.targets?.find((t) => t.id === 'mail_delivery')
  return (
    <section className="bg-inspector" aria-label={mode === 'contain' ? 'Stop the threat' : 'Fix the damage'}>
      <p className="bg-small">
        {mode === 'contain'
          ? <><Term id="containment">Containment</Term> stops the attack right now. It does not repair anything yet.</>
          : <><Term id="remediation">Remediation</Term> repairs what the attacker changed. Skip anything your clues show was never affected.</>}
      </p>
      <div className="bg-action-grid">
        {mode === 'contain' && siem && (
          <article className="bg-action-card">
            <h2>Search for related messages</h2>
            <p>Find out who else received the email.</p>
            <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !siem.enabled} onClick={() => run('search_siem', 'mail_delivery')}>
              {siem.done ? 'Search done ✓' : 'Search mailboxes'}
            </button>
          </article>
        )}
        {list.map((a) => <ActionCard key={a} view={view} action={a} busy={busy} completed={completed} ask={ask} />)}
        {preservable.length > 0 && (
          <article className="bg-action-card">
            <h2>Save evidence copies</h2>
            <p><Term id="preservation">Keep a copy</Term> before anything is removed.</p>
            {preservable.map((e) => evidenceCard(e))}
          </article>
        )}
      </div>
      {list.length === 0 && <p className="bg-small">No actions of this kind apply to this incident.</p>}
    </section>
  )
}

/* -------------------------------- verify --------------------------------- */

export function VerifyScreen({ view, busy, completed, run, verification, onFix }) {
  const checks = [
    ['verify_containment', 'containment', 'Is the threat contained?', 'Check the message, the addresses and the sessions.'],
    ['verify_remediation', 'remediation', 'Is the damage fixed?', 'Check for forwarding rules, passwords and devices.'],
  ]
  const gaps = Object.values(verification).some((v) => !v.complete)
  return (
    <section className="bg-inspector" aria-label="Verify recovery">
      <div className="bg-cards2">
        {checks.map(([action, kind, q, text]) => {
          const a = view.available_actions.find((x) => x.action === action)
          const v = verification[kind]
          return (
            <article key={kind} className="bg-action-card">
              <h2>{q}</h2>
              <p>{text}</p>
              <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !a?.enabled} title={a?.reason || ''} onClick={() => run(action)}>
                {a?.done ? 'Check again' : 'Run this check'}
              </button>
              {!a?.enabled && a?.reason && <small>{a.reason}</small>}
              {v && (
                <div className={`bg-verify ${v.complete ? 'ok' : 'gap'}`}>
                  <strong>{v.complete ? 'All clear' : 'Something is missing'}</strong>
                  <ul>{v.lines.map((l) => <li key={l}>{l}</li>)}</ul>
                </div>
              )}
            </article>
          )
        })}
      </div>
      {gaps && <button type="button" className="bg-btn" onClick={onFix}>Go back and fix it</button>}
    </section>
  )
}

/* ------------------------------ closure wizard --------------------------- */

const toggle = (list, id) => (list.includes(id) ? list.filter((x) => x !== id) : [...list, id])

export function AffectedScreen({ view, form, setForm }) {
  return (
    <section className="bg-inspector" aria-label="Who was affected">
      <fieldset className="bg-fieldset">
        <legend>People who interacted with the attack</legend>
        {view.users.map((u) => (
          <label key={u.id} className="bg-check">
            <input type="checkbox" checked={form.users.includes(u.id)} onChange={() => setForm({ ...form, users: toggle(form.users, u.id) })} />
            {u.name} <small>{u.email}</small>
          </label>
        ))}
        <p className="bg-small">Leave everyone unticked if nobody interacted with it.</p>
      </fieldset>
      <fieldset className="bg-fieldset">
        <legend>Devices that were compromised</legend>
        {view.users.map((u) => (
          <label key={u.endpoint} className="bg-check">
            <input type="checkbox" checked={form.assets.includes(u.endpoint)} onChange={() => setForm({ ...form, assets: toggle(form.assets, u.endpoint) })} />
            {u.endpoint} <small>{u.name}</small>
          </label>
        ))}
      </fieldset>
    </section>
  )
}

export function CauseScreen({ view, form, setForm }) {
  const preserved = view.evidence.filter((e) => e.preserved).length
  const preservable = view.evidence.filter((e) => e.preservable).length
  return (
    <section className="bg-inspector" aria-label="Root cause">
      <fieldset className="bg-choices">
        <legend>How did the attacker get in?</legend>
        {CAUSE_CHOICES.map(([v, t, d]) => <Choice key={v} name="cause" value={v} current={form.root_cause} title={t} text={d} onChange={(x) => setForm({ ...form, root_cause: x })} />)}
      </fieldset>
      <fieldset className="bg-choices">
        <legend>How much risk is left?</legend>
        {RISK_CHOICES.map(([v, t, d]) => <Choice key={v} name="risk" value={v} current={form.residual_risk} title={t} text={d} onChange={(x) => setForm({ ...form, residual_risk: x })} />)}
      </fieldset>
      <fieldset className="bg-fieldset">
        <legend><Term id="preservation">Evidence copies</Term></legend>
        <p className="bg-small">You saved {preserved} of {preservable} items that can be saved. Say yes only if the evidence this incident needs was really saved.</p>
        {[[true, 'Yes, the evidence was saved'], [false, 'No, some was not saved']].map(([v, l]) => (
          <label key={String(v)} className="bg-check"><input type="radio" name="preserved" checked={form.evidence_preserved === v} onChange={() => setForm({ ...form, evidence_preserved: v })} />{l}</label>
        ))}
      </fieldset>
    </section>
  )
}

export function CloseScreen({ view, busy, form, setForm, pinned, setPinned, onClose }) {
  const proof = useMemo(() => pinned.filter((id) => view.evidence.some((e) => e.id === id)), [pinned, view.evidence])
  const ready = form.summary.trim().length >= 20 && Boolean(form.classification && form.severity)
  const closeInfo = view.available_actions.find((a) => a.action === 'close_incident')
  return (
    <section className="bg-inspector" aria-label="Close the case">
      <fieldset className="bg-fieldset">
        <legend>Which clues prove your story? ({proof.length} chosen)</legend>
        <p className="bg-small">Choose only clues that support your conclusion. Unrelated ones count against you.</p>
        {view.evidence.map((e) => (
          <label key={e.id} className="bg-check">
            <input type="checkbox" checked={proof.includes(e.id)} onChange={() => setPinned(toggle(pinned, e.id))} />
            {e.title} <small>{prettify(e.category)}</small>
          </label>
        ))}
      </fieldset>
      <label className="bg-field">In your own words, what happened?
        <textarea rows={4} maxLength={1500} value={form.summary} placeholder="What happened, what you did, and what is left."
          onChange={(e) => setForm({ ...form, summary: e.target.value })} />
      </label>
      {closeInfo && !closeInfo.enabled && closeInfo.reason && <p className="bg-small" role="status">{closeInfo.reason}</p>}
      <button type="button" className="bg-btn bg-primary bg-big" disabled={busy || !ready || !closeInfo?.enabled}
        title={ready ? '' : 'Write at least 20 characters.'} onClick={onClose}>Close the case</button>
      {!ready && <p className="bg-small">{form.classification && form.severity ? 'Write a sentence or two to enable closing.' : 'Go back to "Decide what happened" and record your decision first.'}</p>}
    </section>
  )
}
