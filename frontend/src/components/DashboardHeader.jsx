// components/DashboardHeader.jsx
import { useEffect, useRef, useState } from 'react'
import { Search, Bell, ChevronDown, User, Settings, LogOut } from 'lucide-react'
import './DashboardHeader.css'

const NOTIFICATIONS = [
  { id: 1, text: 'New phishing scenario available', time: '2h ago' },
  { id: 2, text: 'Simulation report generated', time: '5h ago' },
  { id: 3, text: 'Learning streak: 6 days', time: '1d ago' },
]

export default function DashboardHeader({ user, onLogout, searchValue, onSearchChange }) {
  const [notifOpen, setNotifOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const notifRef = useRef(null)
  const profileRef = useRef(null)

  useEffect(() => {
    const onClick = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false)
      if (profileRef.current && !profileRef.current.contains(e.target)) setProfileOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const initial = (user?.name || 'A').trim().charAt(0).toUpperCase()

  return (
    <header className="dhd-header">
      <div className="dhd-search">
        <Search size={16} />
        <input
          type="text"
          placeholder="Search simulations, tools, or resources…"
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
        />
      </div>

      <div className="dhd-actions">
        <div className="dhd-notif-wrap" ref={notifRef}>
          <button className="dhd-icon-btn" onClick={() => setNotifOpen(v => !v)} aria-label="Notifications">
            <Bell size={18} />
            <span className="dhd-notif-dot" />
          </button>
          {notifOpen && (
            <div className="dhd-dropdown dhd-notif-dropdown">
              <div className="dhd-dropdown-title">Notifications</div>
              {NOTIFICATIONS.map(n => (
                <div key={n.id} className="dhd-notif-item">
                  <span className="dhd-notif-bullet" />
                  <div>
                    <p>{n.text}</p>
                    <span>{n.time}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="dhd-profile-wrap" ref={profileRef}>
          <button className="dhd-profile-btn" onClick={() => setProfileOpen(v => !v)}>
            <span className="dhd-avatar">{initial}</span>
            <span className="dhd-username">{user?.name || 'Analyst'}</span>
            <ChevronDown size={14} />
          </button>
          {profileOpen && (
            <div className="dhd-dropdown dhd-profile-dropdown">
              <div className="dhd-profile-meta">
                <span className="dhd-profile-name">{user?.name || 'Analyst'}</span>
                {user?.email && <span className="dhd-profile-email">{user.email}</span>}
                <span className="dhd-profile-role">{user?.role || 'student'}</span>
              </div>
              <div className="dhd-dropdown-divider" />
              <button className="dhd-dropdown-item" disabled>
                <User size={15} /> Profile
              </button>
              <button className="dhd-dropdown-item" disabled>
                <Settings size={15} /> Settings
              </button>
              <button className="dhd-dropdown-item dhd-dropdown-danger" onClick={onLogout}>
                <LogOut size={15} /> Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
