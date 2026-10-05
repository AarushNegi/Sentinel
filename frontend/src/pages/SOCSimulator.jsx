// pages/SOCSimulator.jsx
// Blue Team defense flow — modeled on TryHackMe's SOC Simulator.
// Internal tab navigation (Dashboard / Alert Queue / SIEM / Case Reports)
// rather than separate routes, so state (alerts, verdicts, score) stays in one place.

import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import { saveSimulationReport } from '../services/api'
import './SOCSimulator.css'

const TABS = ['dashboard', 'queue', 'siem', 'reports']

export default function SOCSimulator() {
  const navigate = useNavigate()
  const location = useLocation()
  const { attack = 'phishing' } = location.state || {}

  const [alertsData, setAlertsData] = useState([])
  const [logsData, setLogsData]     = useState([])
  const [tab, setTab]               = useState('dashboard')
  const [assignedId, setAssignedId] = useState(null)
  const [siemQuery, setSiemQuery]   = useState('')
  const [startTime]                 = useState(() => Date.now())
  const [saving, setSaving]         = useState(false)

  // alert.id -> { verdict: 'TP'|'FP', correct: bool, usedSiem: bool, resolvedAt: string }
  const [resolutions, setResolutions] = useState({})

  useEffect(() => {
    import(`../data/scenarios/${attack}-alerts.js`).then(m => setAlertsData(m.default))
    import(`../data/scenarios/${attack}-siem-logs.js`).then(m => setLogsData(m.default))
  }, [attack])

  const totalAlerts   = alertsData.length
  const closedIds     = Object.keys(resolutions)
  const closedCount   = closedIds.length
  const closedAsTP    = closedIds.filter(id => resolutions[id].verdict === 'TP').length
  const closedAsFP    = closedIds.filter(id => resolutions[id].verdict === 'FP').length
  const correctCount  = closedIds.filter(id => resolutions[id].correct).length
  const allDone       = totalAlerts > 0 && closedCount === totalAlerts

  const assignedAlert = alertsData.find(a => a.id === assignedId)
  const [usedSiemForCurrent, setUsedSiemForCurrent] = useState(false)

  const assignToMe = (alertId) => {
    setAssignedId(alertId)
    setUsedSiemForCurrent(false)
  }

  const closeAlert = (verdict) => {
    if (!assignedAlert) return
    const correct = (verdict === 'TP') === assignedAlert.isThreat
    setResolutions(prev => ({
      ...prev,
      [assignedAlert.id]: {
        verdict,
        correct,
        usedSiem: usedSiemForCurrent,
        resolvedAt: new Date().toISOString()
      }
    }))
    setAssignedId(null)
    setTab('queue')
  }

  const filteredLogs = siemQuery.trim()
    ? logsData.filter(l =>
        l.message.toLowerCase().includes(siemQuery.toLowerCase()) ||
        l.source.toLowerCase().includes(siemQuery.toLowerCase()) ||
        l.tags.some(t => t.toLowerCase().includes(siemQuery.toLowerCase()))
      )
    : logsData

  const buildReport = () => {
    const durationSec = Math.round((Date.now() - startTime) / 1000)
    const points = closedIds.reduce((sum, id) => sum + (resolutions[id].correct ? 10 : 0), 0)
    const firstMistake = alertsData.find(a => resolutions[a.id] && !resolutions[a.id].correct)

    return {
      mode: 'blue',
      attack,
      guideTitle: 'Phishing (SOC Simulator)',
      result: correctCount === totalAlerts ? 'success' : 'failed',
      failedAtStage: firstMistake ? firstMistake.rule : null,
      totalStages: totalAlerts,
      stagesCompleted: closedCount,
      score: points,
      maxScore: totalAlerts * 10,
      durationSeconds: durationSec,
      choices: alertsData.map(a => {
        const r = resolutions[a.id]
        return {
          stage: a.rule,
          mitre: a.type,
          chosenText: r ? `Closed as ${r.verdict === 'TP' ? 'True Positive' : 'False Positive'}` : 'Not resolved',
          outcome: !r ? 'fail' : r.correct ? 'best' : 'fail',
          usedHint: r?.usedSiem || false,
          pointsEarned: r?.correct ? 10 : 0
        }
      }),
      logLines: closedIds.map(id => {
        const a = alertsData.find(x => x.id === id)
        const r = resolutions[id]
        return { stage: a.rule, text: `Closed as ${r.verdict} — ${r.correct ? 'correct' : 'incorrect'} verdict` }
      })
    }
  }

  const finishAndReport = async () => {
    setSaving(true)
    const report = buildReport()
    try {
      const res = await saveSimulationReport(report)
      navigate('/outcome', { state: { report, reportId: res.data.report_id } })
    } catch {
      navigate('/outcome', { state: { report, reportId: null, saveError: true } })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="soc-page">
      <NetworkBackground variant="blue" />

      <div className="soc-shell">
        {/* ── Sidebar ── */}
        <aside className="soc-sidebar">
          <div className="soc-logo">🛡️ Sentinel</div>

          <nav className="soc-nav">
            <button className={`soc-nav-item ${tab === 'dashboard' ? 'active' : ''}`} onClick={() => setTab('dashboard')}>
              Dashboard
            </button>
            <button className={`soc-nav-item ${tab === 'queue' ? 'active' : ''}`} onClick={() => setTab('queue')}>
              Alert queue
              {totalAlerts - closedCount > 0 && <span className="soc-nav-badge">{totalAlerts - closedCount}</span>}
            </button>
            <button className={`soc-nav-item ${tab === 'siem' ? 'active' : ''}`} onClick={() => setTab('siem')}>
              SIEM
            </button>
            <button className={`soc-nav-item ${tab === 'reports' ? 'active' : ''}`} onClick={() => setTab('reports')}>
              Case reports
            </button>
          </nav>

          <button className="soc-exit-btn" onClick={() => navigate('/dashboard')}>Exit simulation</button>
        </aside>

        {/* ── Main ── */}
        <main className="soc-main">

          {tab === 'dashboard' && (
            <div className="soc-tab">
              <div className="soc-intro-card">
                <div className="soc-intro-icon">🎣</div>
                <div>
                  <h2>Introduction to Phishing</h2>
                  <p>Work the alert queue. Assign yourself an alert, cross-reference the SIEM, and close it as a True or False Positive.</p>
                </div>
              </div>

              <div className="soc-stats-row">
                <div className="soc-stat-card">
                  <span className="soc-stat-label">Total alerts</span>
                  <span className="soc-stat-num">{totalAlerts}</span>
                </div>
                <div className="soc-stat-card">
                  <span className="soc-stat-label">Closed alerts</span>
                  <span className="soc-stat-num">{closedCount}</span>
                </div>
                <div className="soc-stat-card soc-stat-tp">
                  <span className="soc-stat-label">Closed as TP</span>
                  <span className="soc-stat-num">{closedAsTP}</span>
                </div>
                <div className="soc-stat-card soc-stat-fp">
                  <span className="soc-stat-label">Closed as FP</span>
                  <span className="soc-stat-num">{closedAsFP}</span>
                </div>
              </div>

              <div className="soc-panel">
                <h3>Open alerts</h3>
                {totalAlerts - closedCount === 0 ? (
                  <p className="soc-muted">All alerts resolved. Check Case Reports for your results.</p>
                ) : (
                  <p className="soc-muted">Access the alert queue to monitor and investigate new alerts as they arrive.</p>
                )}
                <button className="soc-primary-btn" onClick={() => setTab('queue')}>Go to Alert Queue →</button>
              </div>

              {allDone && (
                <button className="soc-finish-btn" onClick={finishAndReport} disabled={saving}>
                  {saving ? 'Saving report…' : 'Finish Shift — View Outcome Report →'}
                </button>
              )}
            </div>
          )}

          {tab === 'queue' && !assignedAlert && (
            <div className="soc-tab">
              <h2>Alert queue</h2>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>ID</th><th>Alert rule</th><th>Severity</th><th>Type</th><th>Status</th><th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {alertsData.map(a => {
                    const resolved = resolutions[a.id]
                    return (
                      <tr key={a.id}>
                        <td>{a.id}</td>
                        <td>{a.rule}</td>
                        <td><span className={`soc-sev soc-sev-${a.severity.toLowerCase()}`}>{a.severity}</span></td>
                        <td>{a.type}</td>
                        <td>
                          {resolved
                            ? <span className="soc-status soc-status-closed">Closed</span>
                            : <span className="soc-status soc-status-open">Awaiting action</span>}
                        </td>
                        <td>
                          {!resolved && (
                            <button className="soc-assign-btn" onClick={() => assignToMe(a.id)}>Assign to me</button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'queue' && assignedAlert && (
            <div className="soc-tab">
              <button className="soc-back-link" onClick={() => setAssignedId(null)}>← Back to queue</button>

              <div className="soc-investigate">
                <div className="soc-investigate-header">
                  <h2>{assignedAlert.rule}</h2>
                  <span className={`soc-sev soc-sev-${assignedAlert.severity.toLowerCase()}`}>{assignedAlert.severity}</span>
                </div>
                <p className="soc-investigate-desc">{assignedAlert.description}</p>

                <div className="soc-fields">
                  {Object.entries(assignedAlert.fields).map(([k, v]) => (
                    <div key={k} className="soc-field-row">
                      <span className="soc-field-key">{k}</span>
                      <span className="soc-field-val">{v}</span>
                    </div>
                  ))}
                </div>

                <button className="soc-siem-link" onClick={() => { setTab('siem'); setUsedSiemForCurrent(true) }}>
                  🔍 Cross-reference in SIEM
                </button>

                <div className="soc-verdict-row">
                  <button className="soc-verdict-btn soc-verdict-tp" onClick={() => closeAlert('TP')}>
                    Close as True Positive
                  </button>
                  <button className="soc-verdict-btn soc-verdict-fp" onClick={() => closeAlert('FP')}>
                    Close as False Positive
                  </button>
                </div>
              </div>
            </div>
          )}

          {tab === 'siem' && (
            <div className="soc-tab">
              <h2>SIEM</h2>
              <input
                className="soc-search"
                placeholder="Search logs by sender, domain, IP, or keyword…"
                value={siemQuery}
                onChange={e => setSiemQuery(e.target.value)}
              />
              <div className="soc-log-list">
                {filteredLogs.map(l => (
                  <div key={l.id} className={`soc-log-row soc-log-${l.level.toLowerCase()}`}>
                    <span className="soc-log-level">{l.level}</span>
                    <span className="soc-log-source">{l.source}</span>
                    <span className="soc-log-msg">{l.message}</span>
                    <span className="soc-log-time">{l.timestamp}</span>
                  </div>
                ))}
                {filteredLogs.length === 0 && <p className="soc-muted">No matching logs.</p>}
              </div>
              {assignedId && (
                <button className="soc-back-link" onClick={() => setTab('queue')}>← Back to investigation</button>
              )}
            </div>
          )}

          {tab === 'reports' && (
            <div className="soc-tab">
              <h2>Case reports</h2>
              {closedCount === 0 ? (
                <p className="soc-muted">No resolved alerts yet.</p>
              ) : (
                <table className="soc-table">
                  <thead>
                    <tr><th>ID</th><th>Alert rule</th><th>Verdict</th><th>Result</th><th>Resolved</th></tr>
                  </thead>
                  <tbody>
                    {closedIds.map(id => {
                      const a = alertsData.find(x => x.id === id)
                      const r = resolutions[id]
                      return (
                        <tr key={id}>
                          <td>{a.id}</td>
                          <td>{a.rule}</td>
                          <td>{r.verdict === 'TP' ? 'True Positive' : 'False Positive'}</td>
                          <td>
                            <span className={r.correct ? 'soc-verdict-correct' : 'soc-verdict-wrong'}>
                              {r.correct ? '✓ Correct' : '✕ Incorrect'}
                            </span>
                          </td>
                          <td>{new Date(r.resolvedAt).toLocaleString()}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}

              {allDone && (
                <button className="soc-finish-btn" onClick={finishAndReport} disabled={saving}>
                  {saving ? 'Saving report…' : 'Finish Shift — View Outcome Report →'}
                </button>
              )}
            </div>
          )}

        </main>
      </div>
    </div>
  )
}