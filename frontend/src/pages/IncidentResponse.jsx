// pages/IncidentResponse.jsx
// Blue Team: Incident Response in a SIEM-style environment.
// Search, timeline, asset graph, case management, response playbook, and IR metrics.
// All activity is simulated. The clock only moves when the analyst searches or acts.

import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import { saveSimulationReport } from '../services/api'
import scenario from '../data/scenarios/ir-ransomware'
import {
  fmt, LEVEL_NAME, PTS, deriveState, computeEvents, hostLevels, searchEvents,
  isUnlocked, resolveAction, containedAtOf, scoreRun
} from '../utils/irEngine'
import './IncidentResponse.css'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'search', label: 'Search' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'graph', label: 'Asset graph' },
  { id: 'case', label: 'Case' },
  { id: 'response', label: 'Response' }
]

const PHASE_LABEL = { containment: 'Containment', eradication: 'Eradication', recovery: 'Recovery' }
const LIFECYCLE = ['Preparation', 'Detection and analysis', 'Containment', 'Eradication', 'Recovery', 'Lessons learned']
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
const NODE_COLORS = ['#64748b', '#eab308', '#ef4444', '#b91c1c']

function AssetGraph({ levels, state, visibleIds, selected, onSelect }) {
  const pos = Object.fromEntries(scenario.nodes.map((n) => [n.id, n]))
  return (
    <svg viewBox="0 0 620 310" className="ir-graph" role="img" aria-label="Asset graph showing host status">
      {scenario.edges.map((e) => {
        const a = pos[e.a]
        const b = pos[e.b]
        const active = e.activeWhen.some((id) => visibleIds.has(id))
        const cut = state.isolated[e.a] != null || state.isolated[e.b] != null
        return (
          <line
            key={e.a + e.b}
            x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            className={`ir-edge ${active ? 'active' : ''} ${cut ? 'cut' : ''}`}
          />
        )
      })}
      {scenario.nodes.map((n) => {
        const lvl = levels[n.id] || 0
        const isolated = state.isolated[n.id] != null
        return (
          <g
            key={n.id}
            className="ir-node"
            role="button"
            tabIndex={0}
            aria-label={`${n.id}, ${isolated ? 'isolated' : LEVEL_NAME[lvl]}`}
            onClick={() => onSelect(n.id)}
            onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') onSelect(n.id) }}
          >
            <circle
              cx={n.x} cy={n.y} r="28"
              fill={lvl === 3 ? '#7f1d1d' : '#111827'}
              stroke={NODE_COLORS[lvl]}
              strokeWidth={selected === n.id ? 4 : 2}
              strokeDasharray={isolated ? '4 3' : undefined}
            />
            <text x={n.x} y={n.y + 4} textAnchor="middle" className="ir-node-label">{n.id}</text>
            <text x={n.x} y={n.y + 46} textAnchor="middle" className="ir-node-sub">
              {isolated ? 'isolated' : LEVEL_NAME[lvl]}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

export default function IncidentResponse() {
  const navigate = useNavigate()

  const [started, setStarted] = useState(false)
  const [tab, setTab] = useState('overview')
  const [clock, setClock] = useState(scenario.detectAt)
  const [actionsDone, setActionsDone] = useState([])
  const [pinned, setPinned] = useState([])
  const [flagged, setFlagged] = useState([])
  const [severity, setSeverity] = useState('')
  const [ackAt, setAckAt] = useState(null)
  const [notes, setNotes] = useState('')
  const [lessons, setLessons] = useState('')
  const [queryInput, setQueryInput] = useState('')
  const [applied, setApplied] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [selectedHost, setSelectedHost] = useState(null)
  const [hintsUsed, setHintsUsed] = useState(0)
  const [hintText, setHintText] = useState('')
  const [lastFeedback, setLastFeedback] = useState(null)
  const [saving, setSaving] = useState(false)
  const [startTime] = useState(() => Date.now())

  const state = useMemo(() => deriveState(actionsDone), [actionsDone])
  const visible = useMemo(() => computeEvents(scenario.events, clock, state), [clock, state])
  const levels = useMemo(() => hostLevels(visible), [visible])
  const visibleIds = useMemo(() => new Set(visible.map((e) => e.id)), [visible])
  const results = useMemo(() => searchEvents(visible, applied), [visible, applied])
  const doneIds = actionsDone.map((a) => a.id)

  const timelineItems = useMemo(() => {
    const ev = visible.map((e) => ({ kind: 'event', at: e.at, e }))
    const ac = actionsDone.map((a) => ({ kind: 'action', at: a.at, a }))
    return [...ev, ...ac].sort((x, y) => x.at - y.at || (x.kind === 'event' ? -1 : 1))
  }, [visible, actionsDone])

  const containedAt = containedAtOf(actionsDone)
  const eradicated = doneIds.includes('remove-persistence') && doneIds.includes('rotate-creds')
  const verify = actionsDone.find((a) => a.id === 'verify-monitor')
  const recoveredAt = verify ? verify.at + verify.cost : null
  const caseStatus = recoveredAt != null ? 'Recovered'
    : eradicated ? 'Eradicated'
    : containedAt != null ? 'Contained'
    : ackAt != null ? 'Investigating'
    : 'New'

  const alertCount = visible.filter((e) => e.alert).length
  const affectedHosts = scenario.assets.filter((a) => !a.external && (levels[a.id] || 0) > 0)
  const encryptedHosts = scenario.assets.filter((a) => (levels[a.id] || 0) === 3)
  const iocs = visible.filter((e) => e.ioc)

  const tick = (m) => setClock((c) => c + m)
  const runSearch = () => { setApplied(queryInput); tick(1) }
  const acknowledge = () => { if (ackAt == null) { setAckAt(clock); tick(1) } }
  const togglePin = (id) => setPinned((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]))
  const toggleFlag = (id) => setFlagged((f) => (f.includes(id) ? f.filter((x) => x !== id) : [...f, id]))

  const searchHost = (id) => {
    setQueryInput(`host:${id}`)
    setTab('search')
  }

  const runAction = (action) => {
    if (doneIds.includes(action.id) || !isUnlocked(action, doneIds)) return
    const r = resolveAction(action, levels)
    const entry = {
      id: action.id, label: action.label, phase: action.phase, cost: action.cost,
      effect: action.effect, at: clock, effectiveAt: clock + action.cost, rating: r.rating, feedback: r.feedback
    }
    setActionsDone((list) => [...list, entry])
    setLastFeedback(entry)
    setHintText('')
    tick(action.cost)
  }

  const getHint = () => {
    const next = scenario.actions.find((a) =>
      !doneIds.includes(a.id) && isUnlocked(a, doneIds) && a.rating === 'best' &&
      (a.core || (a.coreIfAffected && (levels[a.affectedHost] || 0) > 0)))
    setHintsUsed((n) => n + 1)
    setHintText(next ? `Consider next: ${next.label}` : 'Nothing urgent left. Finish your case notes and close the case.')
  }

  const finish = async () => {
    setSaving(true)
    const res = scoreRun({ scenario, actionsDone, pinned, flagged, severity, visible, levels, hintsUsed, ackAt, recoveredAt })
    const phaseDone = [
      ackAt != null && pinned.length > 0,
      containedAt != null,
      eradicated,
      recoveredAt != null,
      lessons.trim().length >= 20
    ]
    const encryptedList = res.encrypted
    const result = encryptedList.length === 0 && recoveredAt != null ? 'success' : 'failed'
    const failedAtStage = encryptedList.length
      ? `Containment (encryption reached ${encryptedList.join(', ')})`
      : recoveredAt == null ? 'Recovery (case closed before recovery was verified)' : null

    const ratioOutcome = (b) =>
      b.max === 0 || b.pts / b.max >= 0.7 ? 'best' : b.pts / b.max >= 0.4 ? 'risky' : 'fail'

    const choices = [
      ...actionsDone.map((a) => ({
        stage: PHASE_LABEL[a.phase],
        mitre: 'NIST 800-61',
        chosenText: `${a.label} (${fmt(a.at)})`,
        outcome: a.rating === 'best' ? 'best' : a.rating === 'risky' ? 'risky' : 'fail',
        usedHint: false,
        pointsEarned: PTS[a.rating]
      })),
      ...res.breakdown.filter((b) => b.label !== 'Response actions').map((b) => ({
        stage: b.label,
        mitre: 'Case quality',
        chosenText: `${b.pts} of ${b.max} points`,
        outcome: ratioOutcome(b),
        usedHint: false,
        pointsEarned: b.pts
      }))
    ]

    const m = res.metrics
    const metricLine = (k, v) => ({ stage: 'Metrics', text: `${k}: ${v == null ? 'not reached' : `${v} min`}` })
    const logLines = [
      ...visible.filter((e) => e.severity !== 'info').map((e) => ({ stage: e.source, text: `[${fmt(e.at)}] ${e.host}: ${e.message}` })),
      metricLine('MTTD (incident start to detection)', m.mttd),
      metricLine('MTTA (alert to acknowledgment)', m.mtta),
      metricLine('MTTC (incident start to containment)', m.mttc),
      metricLine('MTTR (incident start to recovery)', m.mttr),
      { stage: 'Case', text: `Severity: ${severity || 'not set'}. Affected assets flagged: ${flagged.join(', ') || 'none'}.` },
      ...(notes.trim() ? [{ stage: 'Analyst notes', text: notes.trim() }] : []),
      ...(lessons.trim() ? [{ stage: 'Lessons learned', text: lessons.trim() }] : [])
    ]

    const report = {
      mode: 'blue',
      attack: 'incident-response',
      guideTitle: 'Incident response (SIEM)',
      result,
      failedAtStage,
      totalStages: 5,
      stagesCompleted: phaseDone.filter(Boolean).length,
      score: res.score,
      maxScore: res.max,
      durationSeconds: Math.round((Date.now() - startTime) / 1000),
      choices,
      logLines,
      metrics: res.metrics
    }

    try {
      const r = await saveSimulationReport(report)
      navigate('/outcome', { state: { report, reportId: r.data.report_id } })
    } catch {
      navigate('/outcome', { state: { report, reportId: null, saveError: true } })
    } finally {
      setSaving(false)
    }
  }

  if (!started) {
    return (
      <div className="ir-page">
        <NetworkBackground variant="blue" />
        <div className="ir-brief">
          <span className="ir-eyebrow">BLUE TEAM // INCIDENT RESPONSE</span>
          <h1>{scenario.title}</h1>
          <p className="ir-brief-lead">
            You are the on-call analyst. At {fmt(scenario.detectAt)} your EDR raised an alert on a finance
            workstation. Investigate in the SIEM, decide what is real, and run the response before the damage spreads.
          </p>
          <div className="ir-lifecycle">
            {LIFECYCLE.map((p, i) => (
              <span key={p} className={`ir-chip ${i === 0 ? 'done' : ''}`}>{i + 1}. {p}</span>
            ))}
          </div>
          <ul className="ir-brief-list">
            <li>The simulated clock moves only when you search or act. Every search costs 1 minute.</li>
            <li>What you contain, and when, decides which events happen next.</li>
            <li>Pin the evidence that matters, scope the affected assets, then work the playbook.</li>
            <li>Preparation is already done: logging, EDR, and backups are in place.</li>
          </ul>
          <div className="ir-brief-actions">
            <button className="ir-btn-primary" onClick={() => setStarted(true)}>Start shift</button>
            <button className="ir-btn-ghost" onClick={() => navigate('/attack-select')}>Back</button>
          </div>
        </div>
      </div>
    )
  }

  const selectedAsset = scenario.assets.find((a) => a.id === selectedHost)

  return (
    <div className="ir-page">
      <NetworkBackground variant="blue" />
      <div className="ir-shell">
        <aside className="ir-sidebar">
          <div className="ir-logo">Sentinel IR</div>
          <nav className="ir-nav">
            {TABS.map((t) => (
              <button key={t.id} className={`ir-nav-item ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
                {t.label}
                {t.id === 'overview' && ackAt == null && <span className="ir-badge">1</span>}
                {t.id === 'case' && pinned.length > 0 && <span className="ir-badge soft">{pinned.length}</span>}
              </button>
            ))}
          </nav>
          <button className="ir-exit" onClick={() => navigate('/dashboard')}>Exit simulation</button>
        </aside>

        <main className="ir-main">
          <header className="ir-topbar">
            <div>
              <span className="ir-case-id">{scenario.caseId}</span>
              <span className={`ir-status ir-status-${caseStatus.toLowerCase()}`}>{caseStatus}</span>
            </div>
            <div className="ir-clock" aria-label="Simulated time">
              <span>Sim time</span>
              <strong>{fmt(clock)}</strong>
            </div>
          </header>

          {tab === 'overview' && (
            <section className="ir-tab">
              {ackAt == null ? (
                <div className="ir-alert">
                  <div>
                    <strong>New alert at {fmt(scenario.detectAt)}</strong>
                    <p>EDR: Office application spawned PowerShell with an encoded command on WS-014 (jcarter).</p>
                  </div>
                  <button className="ir-btn-primary" onClick={acknowledge}>Acknowledge alert</button>
                </div>
              ) : (
                <div className="ir-alert ack">
                  Alert acknowledged at {fmt(ackAt)}. Time to acknowledge: {ackAt - scenario.detectAt} min.
                </div>
              )}

              <div className="ir-stats">
                <div className="ir-stat"><span>Alerts</span><strong>{alertCount}</strong></div>
                <div className="ir-stat"><span>Hosts affected</span><strong>{affectedHosts.length}</strong></div>
                <div className="ir-stat danger"><span>Hosts encrypted</span><strong>{encryptedHosts.length}</strong></div>
                <div className="ir-stat"><span>Events in SIEM</span><strong>{visible.length}</strong></div>
              </div>

              <div className="ir-panel">
                <h3>Response metrics</h3>
                <table className="ir-table">
                  <tbody>
                    <tr><td>MTTD</td><td>{scenario.detectAt - scenario.incidentStart} min</td><td className="muted">Incident start ({fmt(scenario.incidentStart)}) to detection</td></tr>
                    <tr><td>MTTA</td><td>{ackAt != null ? `${ackAt - scenario.detectAt} min` : 'pending'}</td><td className="muted">Alert to analyst acknowledgment</td></tr>
                    <tr><td>MTTC</td><td>{containedAt != null ? `${containedAt - scenario.incidentStart} min` : 'pending'}</td><td className="muted">Incident start to first containment action</td></tr>
                    <tr><td>MTTR</td><td>{recoveredAt != null ? `${recoveredAt - scenario.incidentStart} min` : 'pending'}</td><td className="muted">Incident start to verified recovery</td></tr>
                  </tbody>
                </table>
                <p className="ir-note">Metric definitions vary by organization. Here, all four measure from the stated start or alert time shown above.</p>
              </div>
            </section>
          )}

          {tab === 'search' && (
            <section className="ir-tab">
              <h2>SIEM search</h2>
              <div className="ir-searchbar">
                <input
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') runSearch() }}
                  placeholder="host:WS-014 severity:high   |   powershell   |   source:dns   |   mitre:T1486"
                  aria-label="SIEM query"
                />
                <button className="ir-btn-primary" onClick={runSearch}>Search (+1 min)</button>
              </div>
              <p className="ir-note">
                Fields: host, user, source, severity, mitre, stage. Free text matches the message and indicators.
                Showing {results.length} of {visible.length} events up to {fmt(clock)}.
              </p>
              <div className="ir-log-list">
                {[...results].reverse().map((e) => (
                  <div key={e.id} className={`ir-log sev-${e.severity}`}>
                    <button className="ir-log-row" onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <span className="ir-log-time">{fmt(e.at)}</span>
                      <span className="ir-log-sev">{e.severity}</span>
                      <span className="ir-log-src">{e.source}</span>
                      <span className="ir-log-host">{e.host}</span>
                      <span className="ir-log-msg">{e.message}</span>
                    </button>
                    {expanded === e.id && (
                      <div className="ir-log-detail">
                        <div><span>User</span>{e.user || 'n/a'}</div>
                        <div><span>MITRE</span>{e.mitre || 'n/a'}</div>
                        <div><span>Stage</span>{e.stage || 'n/a'}</div>
                        <div><span>Indicator</span>{e.ioc || 'none'}</div>
                        <button className="ir-btn-small" onClick={() => togglePin(e.id)}>
                          {pinned.includes(e.id) ? 'Remove from case' : 'Add to case'}
                        </button>
                      </div>
                    )}
                  </div>
                ))}
                {results.length === 0 && <p className="ir-muted">No events match that query.</p>}
              </div>
            </section>
          )}

          {tab === 'timeline' && (
            <section className="ir-tab">
              <h2>Incident timeline</h2>
              <p className="ir-note">Attacker activity and your own actions on one line, in order.</p>
              <div className="ir-timeline">
                {timelineItems.map((it) => it.kind === 'event' ? (
                  <div key={it.e.id} className={`ir-tl-item sev-${it.e.severity}`}>
                    <span className="ir-tl-time">{fmt(it.at)}</span>
                    <div className="ir-tl-body">
                      <div className="ir-tl-head">
                        <span className="ir-tl-stage">{it.e.stage}</span>
                        {it.e.mitre && <span className="ir-tl-mitre">{it.e.mitre}</span>}
                        {pinned.includes(it.e.id) && <span className="ir-tl-pin">in case</span>}
                      </div>
                      <p>{it.e.host}: {it.e.message}</p>
                    </div>
                  </div>
                ) : (
                  <div key={it.a.id} className="ir-tl-item action">
                    <span className="ir-tl-time">{fmt(it.at)}</span>
                    <div className="ir-tl-body">
                      <div className="ir-tl-head"><span className="ir-tl-stage">Analyst action</span></div>
                      <p>{it.a.label}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {tab === 'graph' && (
            <section className="ir-tab">
              <h2>Asset graph</h2>
              <p className="ir-note">Node color shows what the evidence so far says. Click a host for details.</p>
              <AssetGraph levels={levels} state={state} visibleIds={visibleIds} selected={selectedHost} onSelect={setSelectedHost} />
              <div className="ir-legend">
                <span><i style={{ background: NODE_COLORS[0] }} />clean</span>
                <span><i style={{ background: NODE_COLORS[1] }} />suspicious</span>
                <span><i style={{ background: NODE_COLORS[2] }} />compromised</span>
                <span><i style={{ background: NODE_COLORS[3] }} />encrypted</span>
                <span><i className="dash" />isolated</span>
              </div>
              {selectedAsset && (
                <div className="ir-panel">
                  <h3>{selectedAsset.id}</h3>
                  <table className="ir-table">
                    <tbody>
                      <tr><td>Role</td><td>{selectedAsset.role}</td></tr>
                      <tr><td>Owner</td><td>{selectedAsset.owner}</td></tr>
                      <tr><td>OS</td><td>{selectedAsset.os}</td></tr>
                      <tr><td>Criticality</td><td>{selectedAsset.criticality}</td></tr>
                      <tr><td>Status</td><td>{state.isolated[selectedAsset.id] != null ? 'Isolated' : LEVEL_NAME[levels[selectedAsset.id] || 0]}</td></tr>
                    </tbody>
                  </table>
                  <button className="ir-btn-small" onClick={() => searchHost(selectedAsset.id)}>Search this host</button>
                </div>
              )}
            </section>
          )}

          {tab === 'case' && (
            <section className="ir-tab">
              <h2>Case management</h2>
              <div className="ir-grid2">
                <div className="ir-panel">
                  <h3>Details</h3>
                  <label className="ir-label">Severity</label>
                  <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                    <option value="">Select severity</option>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <label className="ir-label">Assignee</label>
                  <div className="ir-static">You (on-call analyst)</div>
                  <label className="ir-label">Status</label>
                  <div className="ir-static">{caseStatus}</div>
                </div>
                <div className="ir-panel">
                  <h3>Affected assets</h3>
                  <p className="ir-note">Flag every asset you believe is affected. Wrong flags cost points.</p>
                  {scenario.assets.filter((a) => !a.external && a.id !== 'MAIL-GW').map((a) => (
                    <label key={a.id} className="ir-check">
                      <input type="checkbox" checked={flagged.includes(a.id)} onChange={() => toggleFlag(a.id)} />
                      {a.id} <span className="muted">{a.role}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="ir-panel">
                <h3>Evidence ({pinned.length})</h3>
                {pinned.length === 0 && <p className="ir-muted">Nothing pinned yet. Open a log in Search and choose Add to case.</p>}
                {pinned.map((id) => {
                  const e = scenario.events.find((x) => x.id === id)
                  return (
                    <div key={id} className="ir-evidence">
                      <span className="ir-log-time">{fmt(e.at)}</span>
                      <span>{e.host}: {e.message}</span>
                      <button className="ir-btn-small" onClick={() => togglePin(id)}>Remove</button>
                    </div>
                  )
                })}
              </div>

              <div className="ir-panel">
                <h3>Indicators of compromise seen</h3>
                {iocs.length === 0 && <p className="ir-muted">No indicators visible yet.</p>}
                {iocs.map((e) => (
                  <div key={e.id} className="ir-ioc"><code>{e.ioc}</code><span className="muted">{e.iocType}</span></div>
                ))}
              </div>

              <div className="ir-panel">
                <h3>Analyst notes</h3>
                <textarea rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="What you found, what you decided, and why." />
              </div>

              <div className="ir-panel">
                <h3>Lessons learned</h3>
                <textarea rows={4} value={lessons} onChange={(e) => setLessons(e.target.value)} placeholder="Root cause, what worked, what to improve (detections, controls, process)." />
              </div>
            </section>
          )}

          {tab === 'response' && (
            <section className="ir-tab">
              <h2>Response playbook</h2>
              <p className="ir-note">Actions take simulated time and change what happens next. Eradication and recovery unlock as you progress.</p>
              <div className="ir-hintrow">
                <button className="ir-btn-small" onClick={getHint}>Hint (-3 pts)</button>
                {hintText && <span className="ir-hint">{hintText}</span>}
              </div>

              {lastFeedback && (
                <div className={`ir-feedback ${lastFeedback.rating}`}>
                  <strong>{lastFeedback.rating === 'best' ? 'Good call' : lastFeedback.rating === 'risky' ? 'Risky' : 'Mistake'}</strong>
                  <p>{lastFeedback.feedback}</p>
                </div>
              )}

              {['containment', 'eradication', 'recovery'].map((phase) => (
                <div key={phase} className="ir-phase">
                  <h3>{PHASE_LABEL[phase]}</h3>
                  {scenario.actions.filter((a) => a.phase === phase).map((a) => {
                    const done = actionsDone.find((x) => x.id === a.id)
                    const unlocked = isUnlocked(a, doneIds)
                    return (
                      <div key={a.id} className={`ir-action ${done ? `done ${done.rating}` : ''} ${!unlocked ? 'locked' : ''}`}>
                        <div className="ir-action-text">
                          <strong>{a.label}</strong>
                          <span>{a.detail}</span>
                          {!unlocked && <em>{a.lockedReason}</em>}
                        </div>
                        <div className="ir-action-side">
                          <span className="ir-cost">~{a.cost} min</span>
                          {done ? (
                            <span className="ir-done">Done {fmt(done.at)}</span>
                          ) : (
                            <button className="ir-btn-small" onClick={() => runAction(a)} disabled={!unlocked}>Run</button>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              ))}

              <div className="ir-panel ir-close">
                <h3>Close case</h3>
                <p className="ir-note">
                  Closing generates your incident report. For a full result, verify recovery first
                  and write your lessons learned in the Case tab.
                </p>
                <button className="ir-btn-primary" onClick={finish} disabled={saving}>
                  {saving ? 'Saving report…' : 'Close case and generate report'}
                </button>
              </div>
            </section>
          )}
        </main>
      </div>
    </div>
  )
}