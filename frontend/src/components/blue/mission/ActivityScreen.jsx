// components/blue/mission/ActivityScreen.jsx
// Step: check the employee's activity. A timeline of simulated security
// events, queried from the server. Checks run real investigation actions;
// the student decides whether the account looks affected. Some events are
// ordinary and harmless on purpose: unusual is not the same as malicious.
import { useCallback, useEffect, useState } from 'react'
import { Fold, Term } from '../guide/HelpUI'
import { callApi, prettify } from '../blueApi'
import { Verdict } from './InvestigateScreens'

const ICON = { auth: '🔑', mailbox: '✉️', session: '🔗', endpoint: '💻', proxy: '🌐' }
const SOURCES = [['', 'Everything'], ['auth', 'Sign-ins'], ['mailbox', 'Email'], ['session', 'Sessions'], ['endpoint', 'Device'], ['proxy', 'Web']]
const CHECKS = [
  { id: 'signins', label: 'Check recent sign-ins', source: 'auth', action: 'analyze_auth_logs' },
  { id: 'mail', label: 'Check mailbox changes', source: 'mailbox', action: 'investigate_user' },
  { id: 'sessions', label: 'Check sessions', source: 'session', action: null },
  { id: 'device', label: 'Check the device', source: 'endpoint', action: 'investigate_endpoint' },
]

export default function ActivityScreen({ view, busy, completed, run, evidenceCard, verdicts, setVerdict }) {
  const [source, setSource] = useState('')
  const [userId, setUserId] = useState('')
  const [search, setSearch] = useState('')
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  const user = view.users.find((u) => u.id === userId) || view.users[0] || null
  const info = (name) => view.available_actions.find((a) => a.action === name)

  const query = useCallback(async (src = source, uid = userId, text = search) => {
    setError('')
    const filters = {}
    if (uid) filters.user = uid
    if (text.trim()) filters.search = text.trim()
    try {
      const { ok, data } = await callApi(`/api/blue-phishing/${view.session_id}/query`, { body: { source: src || undefined, filters } })
      if (!ok) throw new Error(data.error || 'The search failed.')
      setRows(data.rows)
      setTotal(data.total)
    } catch (e) {
      setError(e.message)
    }
  }, [view.session_id, source, userId, search])

  const collected = view.evidence.filter((e) => e.category === 'log').length
  useEffect(() => {
    query()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view.users.length, collected, source, userId])

  const runCheck = async (c) => {
    setSource(c.source)
    if (c.action && user) {
      const t = info(c.action)?.targets?.find((x) => x.id === user.id)
      if (t && t.enabled && !t.done) await run(c.action, user.id)
    }
  }
  const checkState = (c) => (c.action && user ? info(c.action)?.targets?.find((x) => x.id === user.id) : null)
  const available = CHECKS.filter((c) => !c.action || info(c.action)?.targets?.some((t) => t.id === user?.id))

  // The email's arrival is the anchor that connects the events to the incident.
  const sentAt = view.email.opened ? view.email.sent_at : null
  const timeline = [...rows.map((r) => ({ kind: 'event', at: r.ts, row: r })),
    ...(sentAt && !source ? [{ kind: 'email', at: sentAt }] : [])].sort((a, b) => a.at.localeCompare(b.at))
  const found = user ? view.evidence.filter((e) => ['identity', 'user', 'endpoint'].includes(e.category) && e.entity === user.id) : []

  return (
    <section className="bg-inspector" aria-label="Employee activity">
      {view.users.length > 1 && (
        <div className="bg-row" role="group" aria-label="Choose an employee">
          {view.users.map((u) => (
            <button key={u.id} type="button" className={user?.id === u.id ? 'bg-btn bg-chosen' : 'bg-btn'} aria-pressed={user?.id === u.id}
              onClick={() => setUserId(u.id)}>{u.name}</button>
          ))}
        </div>
      )}
      {user && <p><strong>{user.name}</strong> · {user.role}, {user.department}{user.is_primary ? ' · received the reported email' : ''}</p>}

      <div className="bg-row" role="group" aria-label="Activity checks">
        {available.map((c) => {
          const t = checkState(c)
          return (
            <button key={c.id} type="button" className={source === c.source ? 'bg-btn bg-chosen' : 'bg-btn'} disabled={busy || completed || !user || (t && !t.enabled && !t.done)}
              title={t && !t.enabled && !t.done ? t.reason || '' : ''} onClick={() => runCheck(c)}>
              {t?.done ? `${c.label} ✓` : c.label}
            </button>
          )
        })}
      </div>
      <p className="bg-small">Words you may see: <Term id="unusual_signin">unusual sign-in</Term>, <Term id="session">session</Term>, <Term id="mailbox_rule">mailbox rule</Term>.</p>

      {error && <p role="alert" className="bg-error-text">{error}</p>}
      <p className="bg-small" aria-live="polite">{total} event{total === 1 ? '' : 's'} shown.</p>
      {rows.length === 0 && (
        <p className="bg-small">No matching events were found in the simulated records. That does not prove the account is safe: try another check.</p>
      )}
      {timeline.length === 0 ? (
        null
      ) : (
        <ol className="bg-events">
          {timeline.map((item, i) => item.kind === 'email' ? (
            <li key={`mail-${i}`} className="bg-event bg-event-email"><span aria-hidden="true">📧</span><div><strong>The suspicious email arrived</strong><small>{item.at}</small></div></li>
          ) : (
            <li key={item.row.id} className={`bg-event${item.row.collected ? ' saved' : ''}`}>
              <span aria-hidden="true">{ICON[item.row.source] || '•'}</span>
              <div>
                <button type="button" className="bg-rowbtn" aria-expanded={open === item.row.id} onClick={() => setOpen(open === item.row.id ? null : item.row.id)}>
                  {prettify(item.row.event_type)} <em>({item.row.outcome})</em>
                </button>
                <small>{item.at} · {item.row.device}{item.row.src_ip ? ` · ${item.row.src_ip}` : ''}</small>
                {open === item.row.id && (
                  <div className="bg-event-detail" aria-label="Event details">
                    <p>{item.row.detail}</p>
                    <button type="button" className="bg-btn" disabled={busy || completed || item.row.collected} onClick={() => run('collect_log', item.row.id)}>
                      {item.row.collected ? 'Saved as a clue ✓' : 'Save as a clue'}
                    </button>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}

      <Fold title="Filter the events">
        <form className="bg-row" onSubmit={(e) => { e.preventDefault(); query() }}>
          <label className="bg-field">Type of event
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {SOURCES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="bg-field">Search the events
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="for example: forward" />
          </label>
          <button type="submit" className="bg-btn">Apply filter</button>
        </form>
      </Fold>

      {found.length > 0 && (
        <div className="bg-analysis">
          {found.map((e) => <div key={e.id}><strong>{e.title}</strong><p className="bg-finding">{e.content.verdict || e.content.summary}</p><Fold title="See the details">{evidenceCard(e)}</Fold></div>)}
        </div>
      )}
      {found.length > 0 && user && (
        <Verdict id={`activity-${user.id}`} question="Does this account look affected?" verdicts={verdicts} setVerdict={setVerdict}
          options={[['suspicious', 'Looks affected'], ['legitimate', 'Looks fine'], ['unsure', 'Not sure yet']]} />
      )}
    </section>
  )
}
