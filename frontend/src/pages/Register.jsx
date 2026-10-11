import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { registerUser, loginUser } from '../services/api'
import {
  Shield, User, Mail, Lock, Eye, EyeOff, ArrowRight, AlertCircle,
  Radar, ShieldCheck, FileText, Users,
} from 'lucide-react'
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
  const strengthColor = ['', '#FF1744', '#FFB020', '#0099FF', '#00E5A0']

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
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. Try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-wrapper">
        {/* LEFT */}
        <div className="auth-left">
          <div className="auth-brand">
            <Shield className="auth-shield-icon" size={36} strokeWidth={1.75} />
          </div>

          <h1 className="auth-title">
            Join <span className="auth-accent">Sentinel</span>
          </h1>
          <p className="auth-sub">Create your account and start simulating today.</p>

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && (
              <div className="auth-error">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            )}

            <div className="auth-field">
              <label>Full Name</label>
              <div className="auth-input">
                <User size={16} />
                <input
                  type="text"
                  name="name"
                  placeholder="Jane Analyst"
                  value={form.name}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="auth-field">
              <label>Email Address</label>
              <div className="auth-input">
                <Mail size={16} />
                <input
                  type="email"
                  name="email"
                  placeholder="you@sentinel.local"
                  value={form.email}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="auth-field">
              <label>Password</label>
              <div className="auth-input">
                <Lock size={16} />
                <input
                  type={showPw ? 'text' : 'password'}
                  name="password"
                  placeholder="Create a password"
                  value={form.password}
                  onChange={handleChange}
                />
                <button type="button" className="auth-toggle-pw" onClick={() => setShowPw(!showPw)}>
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

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

            <div className="auth-field">
              <label>Confirm Password</label>
              <div className="auth-input">
                <Lock size={16} />
                <input
                  type="password"
                  name="confirm"
                  placeholder="Re-enter password"
                  value={form.confirm}
                  onChange={handleChange}
                />
              </div>
            </div>

            <button type="submit" className="auth-btn-primary" disabled={loading}>
              {loading ? 'Creating account…' : 'Create Account'} <ArrowRight size={16} />
            </button>

            <div className="auth-divider"><span>OR</span></div>

            <div className="auth-redirect">
              Already have an account? <Link to="/login" className="auth-link">Sign In</Link>
            </div>
          </form>
        </div>

        {/* RIGHT */}
        <div className="auth-right">
          <div className="auth-right-header">
            <h2>Train like a real <span className="auth-right-accent">SOC analyst.</span></h2>
            <p>Live kill-chain simulations, real-time logs, and scored outcomes built for learning.</p>
          </div>

          <div className="feature-grid">
            {[
              { icon: Radar,       title: 'Live Simulations', desc: 'Run real attack scenarios in a safe, controlled environment.' },
              { icon: ShieldCheck, title: 'Threat Analysis',  desc: 'Analyze threats with visual dashboards and kill chain breakdowns.' },
              { icon: FileText,    title: 'Real-Time Logs',   desc: 'Watch live attack logs scroll in a terminal-style feed.' },
              { icon: Users,       title: 'Track Progress',   desc: 'Build a streak, climb your accuracy, and review every report.' },
            ].map((f, i) => (
              <div key={i} className="feature-card">
                <div className="feature-icon"><f.icon size={18} /></div>
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
