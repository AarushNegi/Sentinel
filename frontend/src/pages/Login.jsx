import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { loginUser, guestLogin } from '../services/api'
import './Auth.css'

export default function Login() {
  const navigate = useNavigate()
  const { login } = useAuth()

  const [form, setForm]       = useState({ email: '', password: '' })
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const [remember, setRemember] = useState(true)

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
    <div className="auth-page">
      <div className="sim-notice">
        <span className="sim-dot" />
        This is a simulation environment.
      </div>

      <div className="auth-wrapper">
        {/* LEFT */}
        <div className="auth-left">
          <div className="hero-title">
            <h1>Let's Analyze</h1>
            <h1><span className="the">the</span> <span className="attack">Attack</span></h1>
          </div>
          <p className="hero-sub">Simulate. Detect. Analyze. Defend.</p>

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && <div className="auth-error">{error}</div>}

            <div className="input-group">
              <span className="input-icon">✉</span>
              <input
                type="email"
                name="email"
                placeholder="Email Address"
                value={form.email}
                onChange={handleChange}
                autoComplete="email"
              />
            </div>

            <div className="input-group">
              <span className="input-icon">🔒</span>
              <input
                type={showPw ? 'text' : 'password'}
                name="password"
                placeholder="Password"
                value={form.password}
                onChange={handleChange}
                autoComplete="current-password"
              />
              <button type="button" className="toggle-pw" onClick={() => setShowPw(!showPw)}>
                {showPw ? '🙈' : '👁'}
              </button>
            </div>

            <div className="form-meta">
              <label className="remember-label">
                <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
                <span className="custom-check" />
                Remember me
              </label>
              <Link to="/forgot" className="forgot-link">Forgot Password?</Link>
            </div>

            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In to Dashboard'} →
            </button>

            <div className="divider"><span>or</span></div>

            <div className="redirect-text">
              Don't have an account? <Link to="/register" className="forgot-link">Create one</Link>
            </div>

            <button type="button" className="btn-guest" onClick={handleGuest} disabled={loading}>
              👤 Continue as a guest
            </button>
          </form>
        </div>

        {/* RIGHT */}
        <div className="auth-right">
          <div className="right-header">
            <h2>Simulate. Analyze. <span className="defend">Defend.</span></h2>
            <p>Understand the cyber kill chain through interactive simulations,<br />real-time logs, and actionable insights.</p>
          </div>

          <div className="dashboard-grid">
            <div className="dash-card">
              <div className="card-icon blue">⚡</div>
              <div className="card-info">
                <span className="card-label">Simulation Status</span>
                <span className="card-value cyan">Running</span>
                <span className="card-sub"><span className="dot-active" /> Active</span>
              </div>
            </div>

            <div className="dash-card shield-card">
              <div className="shield-icon">🛡️</div>
            </div>

            <div className="dash-card">
              <div className="card-icon green">🛡</div>
              <div className="card-info">
                <span className="card-label">Threat Level</span>
                <span className="card-value white">High</span>
              </div>
            </div>

            <div className="dash-card">
              <div className="card-icon red">📄</div>
              <div className="card-info">
                <span className="card-label">Logs Generated</span>
                <span className="card-value red">18,392</span>
                <span className="card-sub" style={{color:'#22c55e'}}>+2,389 today</span>
              </div>
            </div>

            <div className="dash-card">
              <div className="card-icon yellow">🎯</div>
              <div className="card-info">
                <span className="card-label">Attack Stage</span>
                <span className="card-value yellow">Exploitation</span>
              </div>
            </div>

            <div className="dash-card wide-card">
              <div className="bottom-stat">
                <div className="card-icon purple">👥</div>
                <div className="card-info">
                  <span className="card-label">Active Scenarios</span>
                  <span className="card-value white">42</span>
                  <span className="card-sub">Across all modules</span>
                </div>
              </div>
              <div className="bottom-divider" />
              <div className="bottom-stat">
                <div className="card-icon purple">🏆</div>
                <div className="card-info">
                  <span className="card-label">Success Rate</span>
                  <span className="card-value" style={{color:'#a855f7'}}>87%</span>
                  <span className="card-sub">Average</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}