import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Dashboard() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0a0a0f',
      color: '#fff',
      fontFamily: 'Inter, sans-serif',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '16px',
      textAlign: 'center',
      padding: '40px'
    }}>
      <div style={{
        background: 'rgba(34,197,94,0.1)',
        border: '1px solid rgba(34,197,94,0.3)',
        borderRadius: '99px',
        padding: '6px 18px',
        fontSize: '13px',
        color: '#22c55e'
      }}>
        ✅ Logged In Successfully
      </div>

      <h1 style={{ fontSize: '48px', fontWeight: 800, margin: 0 }}>
        Welcome to <span style={{ color: '#3b82f6' }}>Sentinel</span>
      </h1>

      <p style={{ color: '#6b7280', fontSize: '15px' }}>
        Dashboard is being built. Stay tuned!
      </p>

      <div style={{
        background: '#111118',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '12px',
        padding: '20px 32px',
        fontSize: '14px',
        color: '#9ca3af'
      }}>
        Logged in as: <span style={{ color: '#3b82f6', fontWeight: 600 }}>{user?.name}</span>
        &nbsp;|&nbsp;
        Role: <span style={{ color: '#3b82f6', fontWeight: 600 }}>{user?.role}</span>
      </div>

      <button onClick={handleLogout} style={{
        background: 'transparent',
        border: '1px solid rgba(239,68,68,0.4)',
        color: '#ef4444',
        borderRadius: '10px',
        padding: '10px 24px',
        fontFamily: 'Inter, sans-serif',
        fontSize: '13.5px',
        cursor: 'pointer',
        marginTop: '8px'
      }}>
        Sign Out
      </button>
    </div>
  )
}