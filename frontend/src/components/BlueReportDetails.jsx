// components/BlueReportDetails.jsx
// Evidence-based Blue Team phishing debrief shown on the Outcome page.
// Everything here comes from the backend report (recorded events + the
// scenario's ground truth, revealed only after the incident is closed).
import './BlueReportDetails.css'
import { clock } from './blue/blueApi'

const label = (value) => (value ? String(value).replace(/_/g, ' ') : '—')
const Verdict = ({ ok, yes = 'Correct', no }) => (
  <small className={ok ? 'ok' : 'bad'}>{ok ? yes : no}</small>
)

export default function BlueReportDetails({ report }) {
  const evaluation = report.evaluation || {}
  const breakdown = report.score_breakdown || { categories: [], penalties: [] }
  const debrief = report.debrief || {}
  const generation = report.generation || {}
  const containment = evaluation.containment || {}
  const remediation = evaluation.remediation || {}
  const preservation = evaluation.preservation || {}
  const cls = evaluation.classification || {}
  const root = evaluation.root_cause || {}
  const users = evaluation.affected_users || {}
  const assets = evaluation.affected_assets || {}
  const risk = evaluation.residual_risk || {}

  return (
    <>
      <section className="outcome-section">
        <h2>Score Breakdown</h2>
        <p className="brd-note">Why points were gained or lost, category by category.</p>
        <div className="brd-bars">
          {breakdown.categories.map((c) => (
            <div className="brd-bar-row" key={c.id}>
              <div>
                <span>{c.label}</span>
                <strong>{c.earned} / {c.max}</strong>
              </div>
              <div className="brd-bar"><i style={{ width: `${(c.earned / c.max) * 100}%` }} /></div>
              {c.detail && <p className="brd-why">{c.detail}</p>}
            </div>
          ))}
          {breakdown.penalties.length > 0 && (
            <div className="brd-penalties">
              <strong>Penalties (−{breakdown.penalty_total})</strong>
              <ul>
                {breakdown.penalties.map((p, i) => (
                  <li key={i}>−{p.points} · {p.message}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>

      <section className="outcome-section">
        <h2>Your Conclusions Versus the Facts</h2>
        <div className="brd-grid">
          <div>
            <span>Classification</span>
            <strong>{label(cls.analyst)}</strong>
            <Verdict ok={cls.correct} no={`Actual: ${label(cls.truth)}`} />
          </div>
          <div>
            <span>Severity</span>
            <strong>{(evaluation.severity?.analyst || '—').toUpperCase()}</strong>
            <small>Actual: {(evaluation.severity?.truth || '—').toUpperCase()}</small>
          </div>
          <div>
            <span>Root cause</span>
            <strong>{label(root.analyst)}</strong>
            <Verdict ok={root.correct} no={`Actual: ${label(root.truth)}`} />
          </div>
          <div>
            <span>Affected users</span>
            <strong>{(users.analyst || []).join(', ') || 'None'}</strong>
            <small>Actual: {(users.truth || []).join(', ') || 'None'}</small>
          </div>
          <div>
            <span>Affected assets</span>
            <strong>{(assets.analyst || []).join(', ') || 'None'}</strong>
            <small>Actual: {(assets.truth || []).join(', ') || 'None'}</small>
          </div>
          <div>
            <span>Residual risk</span>
            <strong>{label(risk.analyst)}</strong>
            <Verdict ok={risk.analyst === risk.expected} no={`Actual: ${label(risk.expected)}`} />
          </div>
        </div>
      </section>

      <section className="outcome-section">
        <h2>Response and Recovery</h2>
        <div className="brd-grid">
          <div>
            <span>Containment &amp; remediation</span>
            <strong>{containment.completed ?? 0} / {containment.required_total ?? 0} controls</strong>
            <small className={report.outcome === 'contained' ? 'ok' : 'bad'}>
              {report.outcome === 'contained' ? 'Threat contained' : 'Threat not fully contained'}
            </small>
          </div>
          <div>
            <span>Remediation</span>
            <strong>{remediation.completed ?? 0} / {remediation.required ?? 0} steps</strong>
            <small className={remediation.verified ? 'ok' : 'bad'}>
              {remediation.verified ? 'Recovery verified' : 'Recovery not verified clean'}
            </small>
          </div>
          <div>
            <span>Evidence preserved</span>
            <strong>{preservation.preserved ?? 0} / {preservation.required ?? 0} artifacts</strong>
            <small>Attack progressed {evaluation.attack_progress ?? 0}× unopposed</small>
          </div>
          <div>
            <span>Response time</span>
            <strong>{Math.floor((report.duration_seconds || 0) / 60)}m {(report.duration_seconds || 0) % 60}s</strong>
            <small>Closed in simulated SOC time</small>
          </div>
        </div>

        {(evaluation.remaining_risks || []).length > 0 && (
          <div className="brd-list bad">
            <strong>Remaining risks at closure</strong>
            <ul>{evaluation.remaining_risks.map((m) => <li key={m}>{m}</li>)}</ul>
          </div>
        )}
        {(preservation.missing || []).length > 0 && (
          <div className="brd-list">
            <strong>Forensic artifacts not preserved</strong>
            <ul>{preservation.missing.map((m) => <li key={m}>{m}</li>)}</ul>
          </div>
        )}
        {(evaluation.incorrect_decisions || []).length > 0 && (
          <div className="brd-list bad">
            <strong>Incorrect or unnecessary decisions</strong>
            <ul>{evaluation.incorrect_decisions.map((d, i) => <li key={i}>{d.message} (−{d.points})</li>)}</ul>
          </div>
        )}
        {(evaluation.successful_actions || []).length > 0 && (
          <div className="brd-list ok">
            <strong>Appropriate defensive actions ({evaluation.successful_actions.length})</strong>
            <ul>
              {evaluation.successful_actions.map((a, i) => (
                <li key={i}>{a.label}{a.target ? ` · ${a.target}` : ''}</li>
              ))}
            </ul>
          </div>
        )}
        {evaluation.justification && (
          <div className="brd-list">
            <strong>Your final summary</strong>
            <p>{evaluation.justification}</p>
          </div>
        )}
      </section>

      <section className="outcome-section">
        <h2>Alert Triage</h2>
        <div className="brd-table-wrap">
          <table className="brd-table">
            <thead><tr><th>Alert</th><th>Your decision</th><th>Expected</th><th /></tr></thead>
            <tbody>
              {(evaluation.triage || []).map((t) => (
                <tr key={t.alert_id}>
                  <td>{t.title}<small>{t.alert_id}</small></td>
                  <td>{label(t.analyst) === '—' ? 'Not triaged' : label(t.analyst)}</td>
                  <td>{label(t.expected)}</td>
                  <td className={t.correct ? 'ok' : 'bad'}>{t.correct ? '✓' : '✕'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="outcome-section">
        <h2>Evidence and Indicators</h2>
        {(evaluation.missed_evidence || []).length > 0 && (
          <div className="brd-list bad">
            <strong>Critical evidence you did not collect ({evaluation.missed_evidence.length})</strong>
            <ul>{evaluation.missed_evidence.map((m) => <li key={m.id}>{m.title}</li>)}</ul>
          </div>
        )}
        {(evaluation.missed_indicators || []).length > 0 && (
          <div className="brd-list">
            <strong>Malicious indicators you never identified</strong>
            <ul>{evaluation.missed_indicators.map((m) => <li key={m.id}>{m.value} — {m.label}</li>)}</ul>
          </div>
        )}
        <div className="brd-table-wrap">
          <table className="brd-table">
            <thead><tr><th>Evidence collected ({(report.evidence_collected || []).length})</th><th>Type</th><th>Source</th><th>When</th><th /></tr></thead>
            <tbody>
              {(report.evidence_collected || []).map((e) => (
                <tr key={e.id}>
                  <td>{e.title}{e.critical && <em className="brd-crit">critical</em>}</td>
                  <td>{e.type}</td>
                  <td>{e.source || '—'}</td>
                  <td>{clock(e.discovered_at)}</td>
                  <td className={e.preserved ? 'ok' : ''}>{e.preserved ? 'preserved' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(report.indicators_discovered || []).length > 0 && (
          <div className="brd-list">
            <strong>Indicators you discovered</strong>
            <ul>
              {report.indicators_discovered.map((i, k) => (
                <li key={k}>{i.value} — {i.label}{i.blocked ? ' (blocked)' : ''}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className="outcome-section">
        <h2>Debrief: What Actually Happened</h2>
        {debrief.attack_objective && (
          <p className="brd-objective"><span>Attacker objective</span>{debrief.attack_objective}</p>
        )}
        <ol className="brd-chain">
          {(debrief.ground_truth_timeline || []).map((e, i) => (
            <li key={i}><time>{e.time}</time>{e.text}</li>
          ))}
        </ol>
        {(report.findings || []).length > 0 && (
          <div className="brd-list">
            <strong>User and endpoint findings</strong>
            <ul>
              {report.findings.map((f, i) => (
                <li key={i}>{f.user} ({f.endpoint}): {f.finding}{f.identified ? '' : ' — never identified by you'}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="brd-list ok">
          <strong>Lessons learned</strong>
          <ul>{(debrief.lessons_learned || []).map((l, i) => <li key={i}>{l}</li>)}</ul>
        </div>
        <div className="brd-list">
          <strong>Recommended improvements</strong>
          <ul>{(debrief.recommendations || []).map((l, i) => <li key={i}>{l}</li>)}</ul>
        </div>
        {debrief.ai_commentary && (
          <p className="brd-ai">
            <span>AI mentor commentary (generated locally, not used for scoring)</span>
            {debrief.ai_commentary}
          </p>
        )}
        <p className="brd-source">
          Scenario source: {generation.source === 'ollama'
            ? `AI-generated (${generation.model})`
            : generation.fallback
              ? 'built-in template (AI unavailable — fallback used)'
              : 'built-in template'}
        </p>
      </section>
    </>
  )
}
