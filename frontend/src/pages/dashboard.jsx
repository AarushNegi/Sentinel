// pages/Dashboard.jsx
import { useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useAuth } from '../context/AuthContext'
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

export default function Dashboard() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const simsCount = useCountUp(0)
  const streakCount = useCountUp(0)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="db-page">
     <NetworkBackground variant="blue" />

      <header className="db-topbar">
        <span className="db-logo">
          Sentinel
          <span className="db-live-dot" />
        </span>
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
            <span className="db-stat-num">—</span>
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
          <div className="db-activity-empty">
            No simulations yet — start your first one above.
          </div>
        </section>
      </main>
    </div>
  )
}