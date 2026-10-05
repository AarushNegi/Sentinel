// pages/Dashboard.jsx
import { useNavigate } from 'react-router-dom'
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { getMyReports } from '../services/api'
import NetworkBackground from '../components/NetworkBackground'
import DashboardSidebar from '../components/DashboardSidebar'
import DashboardHeader from '../components/DashboardHeader'
import DashboardStatCard from '../components/DashboardStatCard'
import TeamModeCard from '../components/TeamModeCard'
import RecentActivity from '../components/RecentActivity'
import RecommendedSimulations from '../components/RecommendedSimulations'
import ThreatFeed from '../components/ThreatFeed'
import {
  GraduationCap, Target, Trophy, Flame, Clock, Crosshair, Info, Terminal,
  ShieldCheck, Eye, Search, Activity,
} from 'lucide-react'
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

// Real training-time rollup for the current calendar month, from each
// report's duration_seconds. Falls back to "--" when no durations exist yet.
function computeTrainingTimeThisMonth(reports) {
  const now = new Date()
  const totalSeconds = reports.reduce((sum, r) => {
    const d = new Date(r.created_at)
    const sameMonth = !isNaN(d) && d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear()
    const dur = typeof r.duration_seconds === 'number' ? r.duration_seconds : 0
    return sameMonth ? sum + dur : sum
  }, 0)
  if (totalSeconds <= 0) return null
  return (totalSeconds / 3600).toFixed(1)
}

export default function Dashboard() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const recentRef = useRef(null)

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
  const trainingTime  = computeTrainingTimeThisMonth(reports)

  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
  const thisWeekCount = reports.filter(r => {
    const d = new Date(r.created_at)
    return !isNaN(d) && d.getTime() >= weekAgo
  }).length

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

  const scrollToRecent = () => {
    recentRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const firstName = (user?.name || 'Analyst').split(' ')[0]
  const roleLabel = user?.role === 'guest' ? 'Guest Analyst' : 'Student Analyst'

  return (
    <div className="db-shell">
      <DashboardSidebar onLogout={handleLogout} onReportsClick={scrollToRecent} />

      <div className="db-content">
        <NetworkBackground variant="blue" />

        <DashboardHeader
          user={user}
          onLogout={handleLogout}
          searchValue={search}
          onSearchChange={setSearch}
        />

        <main className="db-main">
          <section className="db-welcome">
            <div className="db-welcome-text">
              <h1>👋 Welcome back, <span className="db-welcome-accent">{firstName}!</span></h1>
              <p>Ready to simulate, analyze, and defend against real-world cyber threats.</p>
            </div>
            <div className="db-role-card">
              <span className="db-role-icon"><GraduationCap size={18} /></span>
              <div>
                <span className="db-role-title">{roleLabel.toUpperCase()}</span>
                <span className="db-role-sub">Cybersecurity Learner</span>
              </div>
            </div>
          </section>

          <section className="db-teams">
            <TeamModeCard
              team="red"
              title="RED TEAM"
              tagline="Attack. Simulate. Exploit."
              description="Practice offensive security in a safe, controlled environment."
              chips={['Reconnaissance', 'Exploitation', 'Privilege Escalation']}
              chipIcons={[Search, Terminal, Crosshair]}
              onEnter={() => navigate('/attack-select', { state: { mode: 'red' } })}
              illustration={<Crosshair size={76} strokeWidth={1.2} className="tmc-glyph" />}
            />
            <TeamModeCard
              team="blue"
              title="BLUE TEAM"
              tagline="Detect. Analyze. Defend."
              description="Investigate alerts, analyze threats, and practice incident response."
              chips={['Monitoring', 'Analysis', 'Response']}
              chipIcons={[Eye, Activity, ShieldCheck]}
              onEnter={() => navigate('/attack-select', { state: { mode: 'blue' } })}
              illustration={<ShieldCheck size={76} strokeWidth={1.2} className="tmc-glyph" />}
            />
          </section>

          <section className="db-stats">
            <DashboardStatCard
              icon={Target}
              tone="purple"
              label="Simulations Completed"
              value={simsCount}
              sub={`+${thisWeekCount} this week`}
            />
            <DashboardStatCard
              icon={Trophy}
              tone="yellow"
              label="Success Rate"
              value={accuracy === null ? '—' : `${accuracy}%`}
              sub={totalCount ? `${successCount}/${totalCount} runs` : 'No runs yet'}
              subTone="green"
            />
            <DashboardStatCard
              icon={Flame}
              tone="red"
              label="Learning Streak"
              value={`${streakCount} ${streakCount === 1 ? 'day' : 'days'}`}
              sub={streak > 0 ? 'Keep it up!' : 'Start today'}
            />
            <DashboardStatCard
              icon={Clock}
              tone="blue"
              label="Training Time"
              value={trainingTime ? `${trainingTime} hrs` : '--'}
              sub="This month"
            />
          </section>

          <section className="db-split">
            <ThreatFeed
              title="Live Threat Intelligence"
              icon={Activity}
              dotColor="green"
              badgeText="SIMULATED FEED"
              rows={[
                { time: '20:14:12', type: 'Phishing Email',        source: '185.226.12.41', target: 'India',          severity: 'High' },
                { time: '20:13:58', type: 'Brute Force Login',     source: '41.77.33.102',  target: 'United States',  severity: 'Medium' },
                { time: '20:13:41', type: 'Malware Distribution',  source: '103.21.244.18', target: 'Germany',        severity: 'High' },
                { time: '20:13:27', type: 'DDoS Attack',           source: '190.42.12.76',  target: 'Singapore',      severity: 'Critical' },
                { time: '20:13:10', type: 'Suspicious Login',      source: '45.67.89.12',   target: 'United Kingdom', severity: 'Medium' },
              ]}
              onViewAll={() => {}}
            />
            <RecommendedSimulations query={search} />
          </section>

          <section className="db-recent" ref={recentRef}>
            <RecentActivity
              reports={recent}
              loading={loading}
              onOpen={openReport}
              timeAgo={timeAgo}
            />
          </section>

          <footer className="db-footer">
            <span><Info size={12} /> Threat examples are simulated for training purposes. No real attacks are performed.</span>
            <span>SENTINEL · v1.0.0</span>
          </footer>
        </main>
      </div>
    </div>
  )
}
