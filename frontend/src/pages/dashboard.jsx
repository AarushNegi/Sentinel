// pages/Dashboard.jsx
import { useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { getMyReports } from '../services/api'
import NetworkBackground from '../components/NetworkBackground'
import './Dashboard.css'

function useCountUp(target, duration = 1200) {
  const [value, setValue] = useState(0)
  useEffect(() => {
    let start = null
    const step = (ts) => {
      if (!start) start = ts
      const progress = Math.min((ts - start) / duration, 1)
      setValue(Math.floor(progress * target))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [target, duration])
  return value
}

// Convert a stored (snake_case) report back into the shape Outcome.jsx expects
function mapReportForOutcome(r) {
  return {
    mode: r.mode,
    attack: r.attack,
    guideTitle: r.guide_title,
    result: r.result,
    failedAtStage: r.failed_at_stage,
    totalStages: r.total_stages,
    stagesCompleted: r.stages_completed,
    score: r.score,
    maxScore: r.max_score,
    durationSeconds: r.duration_seconds,
    choices: r.choices,
    logLines: r.log_lines,
  }
}

function computeStreak(reports) {
  if (!reports.length) return 0
  const days = new Set(
    reports
      .map(r => {
        const d = new Date(r.created_at)
        return isNaN(d) ? null : d.toISOString().slice(0, 10)
      })
      .filter(Boolean)
  )
  let streak = 0
  let cursor = new Date()
  while (true) {
    const key = cursor.toISOString().slice(0, 10)
    if (days.has(key)) {
      streak++
      cursor.setDate(cursor.getDate() - 1)
    } else {
      break
    }
  }
  return streak
}

function timeAgo(iso) {
  const d = new Date(iso)
  if (isNaN(d)) return 'unknown'
  const diffMs = Date.now() - d.getTime()
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

export default function Dashboard() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getMyReports()
      .then(res => setReports(res.data.reports || []))
      .catch(() => setReports([]))
      .finally(() => setLoading(false))
  }, [])

  const totalCount   = reports.length
  const successCount = reports.filter(r => r.result === 'success').length
  const accuracy     = totalCount ? Math.round((successCount / totalCount) * 100) : null
  const streak       = computeStreak(reports)

  const simsCount   = useCountUp(totalCount)
  const streakCount = useCountUp(streak)

  const recent = reports.slice(0, 5)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const openReport = (r) => {
    navigate('/outcome', { state: { report: mapReportForOutcome(r), reportId: r._id } })
  }

  return (
    <div className="db-page">
      <NetworkBackground variant="blue" />

     <header className="db-topbar">
        <span className="db-logo">
          Sentinel
          <span className="db-live-dot" />
        </span>

        <nav className="db-nav">
          <button className="db-nav-link" onClick={() => navigate('/learn')}>Learn</button>
          <button className="db-nav-link db-nav-link-disabled" disabled>Challenges</button>
        </nav>

        <div className="db-user-pill">
          <span>{user?.name}</span>
          <span className="db-role">{user?.role}</span>
          <button className="db-signout" onClick={handleLogout}>Sign Out</button>
        </div>
      </header>

      <main className="db-main">
        <h1 className="db-heading">Welcome back, {user?.name}</h1>
        <p className="db-sub">Pick up where you left off or start a new simulation.</p>

        <div className="db-stats">
          <div className="db-stat-card">
            <span className="db-stat-num">{simsCount}</span>
            <span className="db-stat-label">Simulations completed</span>
          </div>
          <div className="db-stat-card">
            <span className="db-stat-num">{streakCount}</span>
            <span className="db-stat-label">Current streak</span>
          </div>
          <div className="db-stat-card">
            <span className="db-stat-num">{accuracy === null ? '—' : `${accuracy}%`}</span>
            <span className="db-stat-label">Accuracy</span>
          </div>
        </div>

        <button className="db-start-card" onClick={() => navigate('/mode-select')}>
          <div className="db-start-text">
            <span className="db-start-label">Start New Simulation</span>
            <span className="db-start-desc">Choose Red or Blue team and run a live kill chain scenario.</span>
          </div>
          <span className="db-start-arrow">→</span>
        </button>

        <section className="db-activity">
          <h2>Recent Activity</h2>

          {loading && (
            <div className="db-activity-empty">Loading…</div>
          )}

          {!loading && recent.length === 0 && (
            <div className="db-activity-empty">
              No simulations yet — start your first one above.
            </div>
          )}

          {!loading && recent.length > 0 && (
            <div className="db-activity-list">
              {recent.map((r) => (
                <button key={r._id} className="db-activity-item" onClick={() => openReport(r)}>
                  <span className={`db-activity-dot db-activity-${r.result}`} />
                  <div className="db-activity-info">
                    <span className="db-activity-title">
                      {r.guide_title} <span className="db-activity-mode">· {r.mode === 'red' ? 'Red Team' : 'Blue Team'}</span>
                    </span>
                    <span className="db-activity-sub">
                      {r.result === 'success' ? 'Completed' : `Failed at ${r.failed_at_stage}`} · {r.score}/{r.max_score} pts
                    </span>
                  </div>
                  <span className="db-activity-time">{timeAgo(r.created_at)}</span>
                </button>
              ))}
            </div>
          )}
        </section>
      </main>
    </div>
  )
}