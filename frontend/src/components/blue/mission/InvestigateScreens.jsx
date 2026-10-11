// components/blue/mission/InvestigateScreens.jsx
// The investigation steps. Each one is a single task built around something
// the student clicks. Every reveal is a real server action: nothing is shown
// until the student asks for it, and nothing is ever opened, run or visited.
import { useState } from 'react'
import { SEVERITY_TEACH } from '../guide/glossary'
import { Fold, Term } from '../guide/HelpUI'
import { DISPOSITIONS, prettify } from '../blueApi'
import { VERDICT_FEEDBACK } from './steps'

const find = (view, id) => view.evidence.find((e) => e.id === id)
const state = (view, name, id) => view.available_actions.find((a) => a.action === name)?.targets?.find((t) => t.id === id)

// A quick opinion, with a short reply. It never says whether the student is right.
export function Verdict({ id, question, options, verdicts, setVerdict }) {
  const current = verdicts[id]
  const list = options || [['suspicious', 'Looks suspicious'], ['legitimate', 'Looks legitimate'], ['unsure', 'Not sure yet']]
  return (
    <div className="bg-verdict" role="group" aria-label={question}>
      <p><strong>{question}</strong></p>
      <div className="bg-row">
        {list.map(([v, l]) => (
          <button key={v} type="button" className={current === v ? 'bg-btn bg-chosen' : 'bg-btn'} aria-pressed={current === v}
            onClick={() => setVerdict(id, v)}>{l}</button>
        ))}
      </div>
      {current && <p className="bg-small" role="status">{VERDICT_FEEDBACK[current] || 'Noted.'}</p>}
    </div>
  )
}

function Analysis({ evidence, evidenceCard }) {
  if (!evidence) return null
  return (
    <div className="bg-analysis">
      <p className="bg-finding">{evidence.content.verdict || evidence.content.summary}</p>
      <Fold title="See the details">{evidenceCard(evidence)}</Fold>
    </div>
  )
}

/* ------------------------------ 1. alerts ------------------------------ */

export function AlertsScreen({ view, busy, completed, run }) {
  const alerts = [...view.alerts].sort((a, b) => a.detected_at.localeCompare(b.detected_at))
  const firstOpen = alerts.findIndex((a) => !a.triage)
  const [pos, setPos] = useState(firstOpen === -1 ? 0 : firstOpen)
  const alert = alerts[Math.min(pos, alerts.length - 1)]
  const left = alerts.filter((a) => !a.triage).length

  const decide = async (value) => {
    const ok = await run('triage_alert', alert.id, { disposition: value })
    if (ok) {
      const next = alerts.findIndex((a, i) => i !== pos && !a.triage)
      if (next !== -1) setPos(next)
    }
  }

  if (left === 0 && alerts.every((a) => a.triage)) {
    return (
      <div className="bg-done-card">
        <p className="bg-big-text">All {alerts.length} alerts reviewed.</p>
        <p>You triaged each one. Ready to look at the suspicious email?</p>
        <div className="bg-row">
          {alerts.map((a, i) => (
            <button key={a.id} type="button" className="bg-chip" onClick={() => { setPos(i) }} aria-label={`Review again: ${a.title}`}>{a.title}</button>
          ))}
        </div>
      </div>
    )
  }

  return (
    <article className="bg-notification" key={alert.id}>
      <p className="bg-small">Alert {pos + 1} of {alerts.length}</p>
      <div className="bg-alert-head">
        <h2>{alert.title}</h2>
        <span className={`bg-badge bg-sev-${alert.severity}`} title={SEVERITY_TEACH[alert.severity]}>{prettify(alert.severity)}</span>
      </div>
      <p>{alert.description}</p>
      <p className="bg-meta"><span>From <strong>{alert.source}</strong></span><span>About <strong>{alert.entity}</strong></span><span>Tool confidence <strong>{alert.confidence}%</strong></span></p>
      {!alert.selected ? (
        <button type="button" className="bg-btn bg-primary bg-big" disabled={busy || completed} onClick={() => run('select_alert', alert.id)}>
          Investigate alert
        </button>
      ) : (
        <>
          <p className="bg-detail"><strong>What the details say:</strong> {alert.detail}</p>
          {alert.incident_alert && <p className="bg-callout-line">This alert is about the suspicious email you were sent to look into.</p>}
          <p><strong>How urgent is this?</strong></p>
          <div className="bg-row">
            {DISPOSITIONS.map(([value, label]) => (
              <button key={value} type="button" className={alert.triage === value ? 'bg-btn bg-chosen' : 'bg-btn'}
                aria-pressed={alert.triage === value} disabled={busy || completed} onClick={() => decide(value)}>{label}</button>
            ))}
          </div>
        </>
      )}
    </article>
  )
}

/* ------------------------------- 2. email ------------------------------- */

export function EmailScreen({ view, busy, completed, run, evidenceCard, verdicts, setVerdict }) {
  const email = view.email
  const [peek, setPeek] = useState('')
  const [senderOpen, setSenderOpen] = useState(false)
  if (!email.opened) {
    return (
      <article className="bg-notification">
        <h2>{email.subject}</h2>
        <p className="bg-meta"><span>To <strong>{email.recipient}</strong></span><span>Security gateway: <strong>{email.gateway.verdict}</strong></span></p>
        <p>The message is held safely. Nothing in it can run.</p>
        <button type="button" className="bg-btn bg-primary bg-big" disabled={busy || completed} onClick={() => run('open_email')}>Open the email</button>
      </article>
    )
  }
  const from = find(view, 'EV-FIELD-from')
  const t = state(view, 'inspect_header_field', 'from')
  const domain = email.sender_email.split('@')[1] || ''

  return (
    <>
      <article className="bg-mail" aria-label="Email message">
        <dl className="bg-mail-meta">
          <div><dt>From</dt><dd>
            <button type="button" className={`bg-click${senderOpen ? ' active' : ''}`} aria-expanded={senderOpen}
              onClick={() => { setSenderOpen(true); setPeek('') }}>
              {email.sender_name} &lt;{email.sender_email}&gt;
            </button></dd></div>
          <div><dt>To</dt><dd>{email.recipient}</dd></div>
          <div><dt>Subject</dt><dd><strong>{email.subject}</strong></dd></div>
          <div><dt>Sent</dt><dd>{email.sent_at}</dd></div>
        </dl>
        <div className="bg-mail-body">
          <p>{email.greeting}</p>
          {email.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
          <p className="bg-mail-links">
            {email.links.map((l) => (
              <button key={l.id} type="button" className="bg-mail-link" onClick={() => setPeek('Links are checked in a moment. First, who sent this?')}>{l.label}</button>
            ))}
          </p>
          <p>{email.signature}</p>
          {email.attachment && (
            <button type="button" className="bg-attach" onClick={() => setPeek('The attachment is checked in a later step. First, who sent this?')}>
              <span aria-hidden="true">📎</span><span><strong>{email.attachment.filename}</strong><small>{email.attachment.kind.toUpperCase()} · {email.attachment.size_kb} KB</small></span>
            </button>
          )}
        </div>
      </article>

      {!senderOpen && <p className="bg-nudge" role="status">{peek || 'Tip: click the sender line at the top of the email.'}</p>}

      {senderOpen && (
        <section className="bg-inspector" aria-label="Sender inspector">
          <h2>Who really sent this?</h2>
          <div className="bg-compare">
            <div><span>Name you see</span><strong>{email.sender_name}</strong></div>
            <div><span>Actual address</span><strong>{email.sender_email}</strong></div>
            <div><span><Term id="sender_domain">Domain</Term></span><strong>{domain}</strong></div>
          </div>
          {!from ? (
            <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !t?.enabled} onClick={() => run('inspect_header_field', 'from')}>
              Compare with the real organisation
            </button>
          ) : (
            <>
              <Analysis evidence={from} evidenceCard={evidenceCard} />
              <Verdict id="sender" question="Does this sender look right?" verdicts={verdicts} setVerdict={setVerdict} />
            </>
          )}
        </section>
      )}
    </>
  )
}

/* ------------------------------- 3. link -------------------------------- */

export function LinkScreen({ view, busy, completed, run, evidenceCard, verdicts, setVerdict }) {
  const links = view.email.links || []
  const [sel, setSel] = useState(links[0]?.id || null)
  if (!view.email.opened) return <p>Open the email in the previous step first.</p>
  const link = links.find((l) => l.id === sel) || links[0]
  if (!link) return <p>This email has no links.</p>
  const target = find(view, `EV-LINKTARGET-${link.id}`)
  const sandbox = find(view, `EV-URL-${link.id}`)
  const fieldOf = (e, name) => (e?.content.fields || []).find(([k]) => k.toLowerCase().includes(name))?.[1]

  return (
    <>
      {links.length > 1 && (
        <div className="bg-row" role="group" aria-label="Choose a link">
          {links.map((l) => (
            <button key={l.id} type="button" className={l.id === link.id ? 'bg-btn bg-chosen' : 'bg-btn'} aria-pressed={l.id === link.id} onClick={() => setSel(l.id)}>{l.label}</button>
          ))}
        </div>
      )}
      <section className="bg-inspector" aria-label="Link inspector">
        <div className="bg-compare bg-compare-2">
          <div><span>Words in the email</span><strong>{link.label}</strong><small>shown as {link.display_url}</small></div>
          <div className={target ? 'reveal' : ''}><span>Where it really goes</span>
            <strong>{target ? (fieldOf(target, 'actual target') || fieldOf(target, 'actual') || 'See details below') : 'Hidden until you look'}</strong>
            {target && fieldOf(target, 'domain') && <small>domain: {fieldOf(target, 'domain')}</small>}
          </div>
        </div>
        <div className="bg-row">
          <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !state(view, 'reveal_link', link.id)?.enabled}
            onClick={() => run('reveal_link', link.id)}>
            {target ? 'Destination revealed ✓' : 'Reveal where it really goes'}
          </button>
          {target && (
            <button type="button" className="bg-btn" disabled={busy || completed || !state(view, 'inspect_url', link.id)?.enabled}
              onClick={() => run('inspect_url', link.id)}>
              {sandbox ? 'Sandbox check done ✓' : 'Check it in the sandbox'}
            </button>
          )}
        </div>
        <p className="bg-small">The link is never opened. Sentinel only reads where it points. <Term id="url_domain">What is a domain?</Term></p>
        <Analysis evidence={target} evidenceCard={evidenceCard} />
        <Analysis evidence={sandbox} evidenceCard={evidenceCard} />
        {target && <Verdict id={`link-${link.id}`} question="Does this link look safe?" verdicts={verdicts} setVerdict={setVerdict} />}
      </section>
    </>
  )
}

/* ---------------------------- 4. attachment ----------------------------- */

export function AttachmentScreen({ view, busy, completed, run, evidenceCard, verdicts, setVerdict }) {
  const att = view.email.attachment
  if (!att) return <p>This email has no attachment.</p>
  const result = find(view, 'EV-ATTACH')
  return (
    <section className="bg-inspector" aria-label="Attachment inspector">
      <div className="bg-attach bg-attach-static">
        <span aria-hidden="true">📎</span>
        <span><strong>{att.filename}</strong><small>{att.kind.toUpperCase()} · {att.size_kb} KB</small></span>
      </div>
      {!result ? (
        <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !state(view, 'inspect_attachment', att.id)?.enabled}
          onClick={() => run('inspect_attachment', att.id)}>Open in the sandbox</button>
      ) : (
        <>
          <Analysis evidence={result} evidenceCard={evidenceCard} />
          <Verdict id="attachment" question="Does this file look safe?" verdicts={verdicts} setVerdict={setVerdict} />
        </>
      )}
      <p className="bg-small">The file is never downloaded or run. The sandbox is simulated. <Term id="hash">What is a hash?</Term></p>
    </section>
  )
}

/* --------------------------- 5. email security --------------------------- */

const ROUTE_CHECKS = [
  ['reply_to', 'Where do replies go?'],
  ['return_path', 'Check the return address'],
  ['received', 'Trace the route'],
]

export function SecurityScreen({ view, busy, completed, run, evidenceCard }) {
  const auth = find(view, 'EV-HEADERS')
  const raw = find(view, 'EV-RAWHEADERS')
  return (
    <section className="bg-inspector" aria-label="Email security">
      <p>Mail servers check whether an email really came from the domain it claims (<Term id="auth">SPF, DKIM and DMARC</Term>).</p>
      {!auth ? (
        <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !view.available_actions.find((a) => a.action === 'analyze_headers')?.enabled}
          onClick={() => run('analyze_headers')}>Run the security checks</button>
      ) : (
        <div className="bg-analysis">{evidenceCard(auth)}<p className="bg-small">No single result proves an email is safe or malicious. Use it together with your other clues.</p></div>
      )}
      <div className="bg-row" role="group" aria-label="More checks">
        {ROUTE_CHECKS.map(([id, label]) => {
          const t = state(view, 'inspect_header_field', id)
          return <button key={id} type="button" className="bg-btn" disabled={busy || completed || !t?.enabled} onClick={() => run('inspect_header_field', id)}>{t?.done ? `${label} ✓` : label}</button>
        })}
      </div>
      {ROUTE_CHECKS.map(([id]) => find(view, `EV-FIELD-${id}`) && <Analysis key={id} evidence={find(view, `EV-FIELD-${id}`)} evidenceCard={evidenceCard} />)}
      <Fold title="Advanced: raw email headers">
        {raw ? evidenceCard(raw) : (
          <button type="button" className="bg-btn" disabled={busy || completed} onClick={() => run('view_raw_headers')}>Show the raw headers</button>
        )}
      </Fold>
    </section>
  )
}

/* ----------------------------- 6. indicator ------------------------------ */

const TOOL_ORDER = ['domain_reputation', 'url_reputation', 'ip_reputation', 'hash_lookup', 'dns_analysis', 'related_search']
const TOOL_NAMES = {
  domain_reputation: 'Check reputation', url_reputation: 'Check link reputation', ip_reputation: 'Check IP reputation',
  dns_analysis: 'Check when it was registered', hash_lookup: 'Look up the file fingerprint', related_search: 'Find related indicators',
}
const TYPE_NAMES = { domain: 'Domain', url: 'Link', ip: 'IP address', hash: 'File fingerprint' }

export function IndicatorScreen({ view, busy, completed, run, evidenceCard, verdicts, setVerdict, titleOf, onOpenTray }) {
  const [sel, setSel] = useState(null)
  if (view.indicators.length === 0) return <p>No indicators found yet. They appear when you check links and attachments.</p>
  const current = view.indicators.find((i) => i.id === sel) || view.indicators[0]
  const tools = (view.available_actions.find((a) => a.action === 'ioc_lookup')?.targets || [])
    .filter((t) => t.id.startsWith(`${current.id}:`))
    .sort((a, b) => TOOL_ORDER.indexOf(a.id.split(':')[1]) - TOOL_ORDER.indexOf(b.id.split(':')[1]))
  const next = tools.find((t) => t.enabled && !t.done)
  const results = view.evidence.filter((e) => e.entity === current.id && e.category === 'ioc')

  return (
    <section className="bg-inspector" aria-label="Indicator investigation">
      <p className="bg-small">An <Term id="ioc">indicator</Term> is a clue such as a domain, address or file fingerprint.</p>
      <div className="bg-row" role="group" aria-label="Choose an indicator">
        {view.indicators.map((i) => (
          <button key={i.id} type="button" className={i.id === current.id ? 'bg-btn bg-chosen' : 'bg-btn'} aria-pressed={i.id === current.id} onClick={() => setSel(i.id)}>
            <span className="bg-small">{TYPE_NAMES[i.type] || prettify(i.type)}</span> <code>{i.value}</code>{i.blocked ? ' (blocked)' : ''}
          </button>
        ))}
      </div>
      <div className="bg-row">
        <button type="button" className="bg-btn bg-primary" disabled={busy || completed || !next} onClick={() => run('ioc_lookup', next.id)}>
          {next ? `Investigate: ${TOOL_NAMES[next.id.split(':')[1]]}` : 'Everything checked ✓'}
        </button>
      </div>
      {results.map((e) => (
        <div key={e.id} className="bg-found" data-evidence-id={e.id}>
          <strong>{e.title}</strong>
          <p className="bg-finding">{e.content.verdict || e.content.summary}</p>
          {e.related?.length > 0 && (
            <p className="bg-small">Connected clues: {e.related.map((r) => (
              <button type="button" key={r} className="bg-link" onClick={onOpenTray}>{titleOf(r)}</button>
            ))}</p>
          )}
          <Fold title="See the details">{evidenceCard(e)}</Fold>
        </div>
      ))}
      {results.length > 0 && (
        <Verdict id={`ioc-${current.id}`} question="Do you think this is malicious?" verdicts={verdicts} setVerdict={setVerdict}
          options={[['suspicious', 'Looks malicious'], ['legitimate', 'Looks harmless'], ['unsure', 'Not sure yet']]} />
      )}
    </section>
  )
}
