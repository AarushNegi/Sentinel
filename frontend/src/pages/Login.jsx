import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { loginUser, guestLogin } from '../services/api'
import ThreatMap from '../components/ThreatMap'
import ThreatFeed, { DEFAULT_THREAT_ROWS } from '../components/ThreatFeed'
import LoginStatCard from '../components/LoginStatCard'
import {
  Shield, Mail, Lock, Eye, EyeOff, ArrowRight, User, AlertCircle,
  Info, ShieldCheck, Crosshair, Globe, Radio,
} from 'lucide-react'
import './Login.css'

const EXTRA_THREAT_ROWS = [
  { time: '20:12:54', type: 'Suspicious Login',      source: '77.91.10.5',    target: 'Brazil',    severity: 'Medium' },
  { time: '20:12:30', type: 'Malware Distribution',  source: '201.14.88.3',   target: 'Vietnam',   severity: 'High' },
  { time: '20:12:08', type: 'DDoS Attack',           source: '12.55.201.9',   target: 'France',    severity: 'Critical' },
  { time: '20:11:49', type: 'Phishing Email',        source: '88.202.17.44',  target: 'Canada',    severity: 'Medium' },
  { time: '20:11:21', type: 'Brute Force Login',     source: '5.188.60.21',   target: 'Japan',      severity: 'High' },
]

export default function Login() {
  const navigate = useNavigate()
  const { login } = useAuth()

  const [form, setForm]       = useState({ email: '', password: '' })
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const [remember, setRemember] = useState(true)
  const [expandFeed, setExpandFeed] = useState(false)

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.email || !form.password) return setError('All fields are required.')
    setLoading(true)
    try {
      const res = await loginUser(form)
      login(res.data.token, res.data.user)
      if (remember) localStorage.setItem('savedEmail', form.email)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleGuest = async () => {
    setLoading(true)
    try {
      const res = await guestLogin()
      login(res.data.token, res.data.user)
      navigate('/dashboard')
    } catch {
      setError('Cannot connect to server.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="lg-page">
      <div className="lg-wrapper">
        {/* LEFT — authentication panel */}
        <div className="lg-left">
          <div className="lg-brand">
            <Shield className="lg-shield-icon" size={40} strokeWidth={1.75} />
          </div>

          <h1 className="lg-title">
            Welcome back, <span className="lg-accent">Analyst</span>
          </h1>
          <p className="lg-sub">Sign in to continue your cybersecurity training.</p>

          <form className="lg-form" onSubmit={handleSubmit}>
            {error && (
              <div className="lg-error">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            )}

            <div className="lg-field">
              <label htmlFor="email">Email Address</label>
              <div className="lg-input">
                <Mail size={16} />
                <input
                  id="email"
                  type="email"
                  name="email"
                  placeholder="you@sentinel.local"
                  value={form.email}
                  onChange={handleChange}
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="lg-field">
              <label htmlFor="password">Password</label>
              <div className="lg-input">
                <Lock size={16} />
                <input
                  id="password"
                  type={showPw ? 'text' : 'password'}
                  name="password"
                  placeholder="Enter your password"
                  value={form.password}
                  onChange={handleChange}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="lg-toggle-pw"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div className="lg-meta">
              <label className="lg-remember">
                <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
                <span className="lg-check" />
                Remember me
              </label>
              <Link to="/forgot" className="lg-link">Forgot Password?</Link>
            </div>

            <button type="submit" className="lg-btn-primary" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In to Dashboard'} <ArrowRight size={16} />
            </button>

            <div className="lg-divider"><span>OR</span></div>

            <button type="button" className="lg-btn-guest" onClick={handleGuest} disabled={loading}>
              <User size={16} /> Continue as a guest
            </button>

            <div className="lg-redirect">
              Don't have an account? <Link to="/register" className="lg-link">Create one</Link>
            </div>
          </form>
        </div>

        {/* RIGHT — simulated live threat monitoring preview */}
        <div className="lg-right">
          <div className="lg-right-head">
            <div className="lg-right-head-left">
              <span className="lg-pulse-dot" />
              <div>
                <h2>Live Threat Simulation</h2>
                <p>Real-time global cyber attack activity (simulated)</p>
              </div>
            </div>
            <div className="lg-right-head-right">
              <span className="lg-sim-pill"><Info size={11} /> SIMULATED LIVE FEED</span>
              <span className="lg-live-pill"><Radio size={11} /> LIVE</span>
            </div>
          </div>

          <ThreatMap />

          <ThreatFeed
            title="Live Threat Feed"
            rows={expandFeed ? [...DEFAULT_THREAT_ROWS, ...EXTRA_THREAT_ROWS] : DEFAULT_THREAT_ROWS}
            onViewAll={() => setExpandFeed(v => !v)}
          />

          <div className="lg-stats-row">
            <LoginStatCard icon={ShieldCheck} tone="green" value="12,428" label="Threat Events" delta="18% today" />
            <LoginStatCard icon={Crosshair} tone="red" value="3,192" label="Phishing Attempts" delta="27% today" />
            <LoginStatCard icon={Globe} tone="blue" value="86" label="Countries Involved" delta="12% today" />
          </div>
        </div>
      </div>
    </div>
  )
}
