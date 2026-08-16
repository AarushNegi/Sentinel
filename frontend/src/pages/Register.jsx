import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { registerUser, loginUser } from '../services/api'
import './Auth.css'

export default function Register() {
  const navigate = useNavigate()
  const { login } = useAuth()

  const [form, setForm]       = useState({ name: '', email: '', password: '', confirm: '' })
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const [strength, setStrength] = useState(0)

  const handleChange = (e) => {
    const updated = { ...form, [e.target.name]: e.target.value }
    setForm(updated)
    setError('')
    if (e.target.name === 'password') setStrength(getStrength(e.target.value))
  }

  const getStrength = (pw) => {
    let s = 0
    if (pw.length >= 8)           s++
    if (/[A-Z]/.test(pw))        s++
    if (/[0-9]/.test(pw))        s++
    if (/[^A-Za-z0-9]/.test(pw)) s++
    return s
  }

  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong']
  const strengthColor = ['', '#ef4444', '#eab308', '#3b82f6', '#22c55e']

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.name || !form.email || !form.password) return setError('All fields are required.')
    if (form.password !== form.confirm) return setError('Passwords do not match.')
    if (form.password.length < 6) return setError('Password must be at least 6 characters.')

    setLoading(true)
    try {
      await registerUser({ name: form.name, email: form.email, password: form.password })
      const res = await loginUser({ email: form.email, password: form.password })
      login(res.data.token, res.data.user)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. Try again.')
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
            <h1>Create Your</h1>
            <h1><span className="the">Sentinel</span> <span className="attack">Account</span></h1>
          </div>
          <p className="hero-sub">Join the platform. Start simulating. Start learning.</p>

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && <div className="auth-error">{error}</div>}

            <div className="input-group">
              <span className="input-icon">👤</span>
              <input
                type="text"
                name="name"
                placeholder="Full Name"
                value={form.name}
                onChange={handleChange}
              />
            </div>

            <div className="input-group">
              <span className="input-icon">✉</span>
              <input
                type="email"
                name="email"
                placeholder="Email Address"
                value={form.email}
                onChange={handleChange}
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
              />
              <button type="button" className="toggle-pw" onClick={() => setShowPw(!showPw)}>
                {showPw ? '🙈' : '👁'}
              </button>
            </div>

            {/* Password strength */}
            {form.password && (
              <div className="strength-wrap">
                <div className="strength-bar">
                  <div className="strength-fill" style={{
                    width: `${(strength / 4) * 100}%`,
                    background: strengthColor[strength]
                  }} />
                </div>
                <span className="strength-label" style={{ color: strengthColor[strength] }}>
                  {strengthLabel[strength]}
                </span>
              </div>
            )}

            <div className="input-group">
              <span className="input-icon">🔒</span>
              <input
                type="password"
                name="confirm"
                placeholder="Confirm Password"
                value={form.confirm}
                onChange={handleChange}
              />
            </div>

            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Creating account…' : 'Create Account'} →
            </button>

            <div className="divider"><span>or</span></div>

            <div className="redirect-text">
              Already have an account? <Link to="/login" className="forgot-link">Sign In</Link>
            </div>
          </form>
        </div>

        {/* RIGHT */}
        <div className="auth-right">
          <div className="right-header">
            <h2>Simulate. Analyze. <span className="defend">Defend.</span></h2>
            <p>Understand the cyber kill chain through interactive simulations,<br />real-time logs, and actionable insights.</p>
          </div>

          <div className="feature-grid">
            {[
              { icon: '⚡', title: 'Live Simulations', desc: 'Run real attack scenarios in a safe, controlled environment.' },
              { icon: '🛡️', title: 'Threat Analysis', desc: 'Analyze threats with visual dashboards and kill chain breakdowns.' },
              { icon: '📄', title: 'Real-Time Logs', desc: 'Watch live attack logs scroll in a terminal-style feed.' },
              { icon: '👥', title: 'Team Collaboration', desc: 'Work with your team on shared scenarios and reports.' },
            ].map((f, i) => (
              <div key={i} className="feature-card">
                <div className="feature-icon">{f.icon}</div>
                <div>
                  <div className="feature-title">{f.title}</div>
                  <div className="feature-desc">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}