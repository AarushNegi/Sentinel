// components/blue/mission/Debrief.jsx
// The mission debrief. Everything here is built from the server's report for
// this closed session: the score, what was missed and what cost points come
// from the engine, not from the browser. The report is only available after
// closing, which is the one moment ground truth is revealed.
import { useState } from 'react'
import { Fold } from '../guide/HelpUI'
import { formatTime } from '../blueApi'

const rank = (pct) => (pct >= 90 ? ['S', 'Expert responder'] : pct >= 75 ? ['A', 'Strong response']
  : pct >= 55 ? ['B', 'Solid, with gaps'] : pct >= 35 ? ['C', 'Needs practice'] : ['D', 'Keep training'])

export default function Debrief({ view, report, loading, error, seconds, busy, onReplay, onReport }) {
  const [showMissed, setShowMissed] = useState(false)
  const pct = Math.round((view.score / view.max_score) * 100)
  const [letter, label] = rank(pct)
  const ok = view.outcome === 'contained'
  const ev = report?.evaluation

  return (
    <div className="bg-debrief">
      <section className={`bg-final ${ok ? 'ok' : 'gap'}`}>
        <div className="bg-rank" role="img" aria-label={`Mission rating ${letter}`}>{letter}</div>
        <div>
          <h2>{ok ? 'Threat contained' : 'The threat was not fully contained'}</h2>
          <p className="bg-score"><strong>{view.score}</strong> / {view.max_score} · {label}</p>
          <p className="bg-small">Time {formatTime(seconds)} · {view.evidence.length} clues found</p>
        </div>
      </section>

      {loading && <p role="status">Preparing your debrief…</p>}
      {error && <p role="alert" className="bg-error-text">{error}</p>}

      {report && (
        <>
          <section className="bg-cards2">
            <article className="bg-card"><h3>What went well</h3>
              {ev.successful_actions.length ? <ul className="bg-plain">{ev.successful_actions.map((a, i) => <li key={i}>{a.label}</li>)}</ul>
                : <p>No effective response actions this time.</p>}
              {ev.classification.correct && <p>You classified the incident correctly.</p>}
            </article>
            <article className="bg-card"><h3>What cost you points</h3>
              {ev.incorrect_decisions.length ? <ul className="bg-plain">{ev.incorrect_decisions.map((d, i) => <li key={i}>−{d.points} {d.message}</li>)}</ul>
                : <p>Nothing. No decision cost you points.</p>}
              {!ev.classification.correct && <p>Your classification did not match what happened.</p>}
            </article>
          </section>

          <section className="bg-card">
            <h3>Containment and recovery</h3>
            <p>Containment: <strong className={ok ? 'bg-good' : 'bg-bad'}>{ok ? 'verified' : 'incomplete'}</strong> · Recovery: <strong className={ev.remediation.verified ? 'bg-good' : 'bg-bad'}>{ev.remediation.verified ? 'verified' : 'not verified'}</strong></p>
            {ev.containment.missing.length > 0 && <p className="bg-small">Still missing: {ev.containment.missing.join('; ')}</p>}
          </section>

          <div className="bg-row">
            <button type="button" className="bg-btn" aria-expanded={showMissed} onClick={() => setShowMissed(!showMissed)}>Review missed clues</button>
          </div>
          {showMissed && (
            <section className="bg-card" aria-label="Missed clues">
              {ev.missed_evidence.length === 0 && ev.missed_indicators.length === 0
                ? <p>You found every important clue.</p> : (
                  <ul className="bg-plain">
                    {ev.missed_evidence.map((m) => <li key={m.id}>{m.title}</li>)}
                    {ev.missed_indicators.map((m) => <li key={m.id}>Indicator not found: {m.label}</li>)}
                  </ul>
                )}
            </section>
          )}

          <Fold title="Inspect decision timeline">
            <ol className="bg-live-timeline">
              {report.timeline.map((t, i) => <li key={i} className={`kind-${t.kind}`}><small>{t.clock}</small> {t.message}</li>)}
            </ol>
          </Fold>
          <Fold title="What really happened">
            <ol className="bg-plain">{(report.debrief.ground_truth_timeline || []).map((t, i) => <li key={i}><small>{t.time}</small> {t.text}</li>)}</ol>
          </Fold>
          <Fold title="How your score was built">
            <ul className="bg-bars">
              {report.score_breakdown.categories.map((c) => (
                <li key={c.id}><span>{c.label}</span><strong>{c.earned} / {c.max}</strong>
                  <div className="bg-bar"><i style={{ width: `${(c.earned / c.max) * 100}%` }} /></div>
                  {c.detail && <small className="bg-small">{c.detail}</small>}</li>
              ))}
            </ul>
          </Fold>
          {report.debrief.ai_commentary && <p className="bg-mentor-note"><strong>AI mentor:</strong> {report.debrief.ai_commentary}</p>}
        </>
      )}

      <div className="bg-row">
        <button type="button" className="bg-btn bg-primary bg-big" disabled={busy} onClick={onReplay}>Replay incident</button>
        <button type="button" className="bg-btn" disabled={busy || !report} onClick={onReport}>View the full report</button>
      </div>
    </div>
  )
}
