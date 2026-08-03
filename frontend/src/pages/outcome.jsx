// pages/Outcome.jsx
import { useLocation, useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './Outcome.css'

export default function Outcome() {
  const navigate = useNavigate()
  const location = useLocation()
  const { report, saveError } = location.state || {}

  if (!report) {
    return (
      <div className="oc-page">
        <p className="oc-empty">No report data. Run a simulation first.</p>
        <button className="oc-btn" onClick={() => navigate('/dashboard')}>Back to Dashboard</button>
      </div>
    )
  }

  const {
    mode, attack, guideTitle, result, failedAtStage,
    totalStages, stagesCompleted, score, maxScore,
    durationSeconds, choices, logLines
  } = report

  const pct = Math.round((score / maxScore) * 100)
  const mins = Math.floor(durationSeconds / 60)
  const secs = durationSeconds % 60

  const downloadCSV = () => {
    const rows = [
      ['Stage', 'MITRE', 'Choice Made', 'Outcome', 'Used Hint', 'Points'],
      ...choices.map(c => [c.stage, c.mitre, c.chosenText, c.outcome, c.usedHint, c.pointsEarned])
    ]
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentinel-${attack}-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className={`oc-page oc-${mode}`}>
      <NetworkBackground variant={mode} />

      <div className="oc-content">
        <div className="oc-summary-card">
          <span className={`oc-result-badge oc-result-${result}`}>
            {result === 'success' ? '✓ Attack Successful' : '✕ Attack Failed'}
          </span>
          <h1>{guideTitle} — {mode === 'red' ? 'Red Team' : 'Blue Team'} Report</h1>
          {failedAtStage && <p className="oc-failed-note">Detected/failed at: <strong>{failedAtStage}</strong></p>}

          <div className="oc-stats-grid">
            <div className="oc-stat">
              <span className="oc-stat-label">Score</span>
              <span className="oc-stat-value">{score} / {maxScore}</span>
              <span className="oc-stat-sub">{pct}%</span>
            </div>
            <div className="oc-stat">
              <span className="oc-stat-label">Stages Completed</span>
              <span className="oc-stat-value">{stagesCompleted} / {totalStages}</span>
            </div>
            <div className="oc-stat">
              <span className="oc-stat-label">Time Taken</span>
              <span className="oc-stat-value">{mins}m {secs}s</span>
            </div>
          </div>
        </div>

        {saveError && (
          <div className="oc-warning">⚠ Report couldn't be saved to your history, but you can still review it below.</div>
        )}

        {/* Timeline / Choices breakdown */}
        <div className="oc-section">
          <h2>Stage-by-Stage Breakdown</h2>
          <div className="oc-timeline">
            {choices.map((c, i) => (
              <div key={i} className={`oc-timeline-item oc-outcome-${c.outcome}`}>
                <div className="oc-timeline-marker">{i + 1}</div>
                <div className="oc-timeline-body">
                  <div className="oc-timeline-header">
                    <span className="oc-timeline-stage">{c.stage}</span>
                    <span className="oc-timeline-mitre">{c.mitre}</span>
                  </div>
                  <p className="oc-timeline-choice">"{c.chosenText}"</p>
                  <div className="oc-timeline-meta">
                    <span className={`oc-outcome-pill oc-outcome-pill-${c.outcome}`}>{c.outcome}</span>
                    {c.usedHint && <span className="oc-hint-used">Used hint</span>}
                    <span className="oc-points">+{c.pointsEarned} pts</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Raw logs */}
        <div className="oc-section">
          <h2>Event Log</h2>
          <div className="oc-log-box">
            {logLines.map((l, i) => (
              <div key={i} className="oc-log-line">
                <span className="oc-log-stage">[{l.stage}]</span> {l.text}
              </div>
            ))}
          </div>
        </div>

        <div className="oc-actions">
          <button className="oc-btn oc-btn-primary" onClick={downloadCSV}>⬇ Download CSV</button>
          <button className="oc-btn" onClick={() => navigate('/dashboard')}>Back to Dashboard</button>
          <button className="oc-btn" onClick={() => navigate('/attack-select', { state: { mode } })}>Run Another Simulation</button>
        </div>
      </div>
    </div>
  )
}