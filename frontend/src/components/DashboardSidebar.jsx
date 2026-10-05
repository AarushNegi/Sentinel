// components/DashboardSidebar.jsx
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Home, Radar, Crosshair, ShieldCheck, BookOpen, FileText, User, Settings, LogOut,
} from 'lucide-react'
import './DashboardSidebar.css'

export default function DashboardSidebar({ onLogout, onReportsClick }) {
  const navigate = useNavigate()
  const location = useLocation()
  const isHome = location.pathname === '/dashboard'

  const navItems = [
    { key: 'home',  label: 'Home',               icon: Home,       onClick: () => navigate('/dashboard'), active: isHome },
    { key: 'sims',  label: 'Simulations',         icon: Radar,      onClick: () => navigate('/mode-select') },
    { key: 'red',   label: 'Red Team',            icon: Crosshair,  onClick: () => navigate('/attack-select', { state: { mode: 'red' } }) },
    { key: 'blue',  label: 'Blue Team',           icon: ShieldCheck, onClick: () => navigate('/attack-select', { state: { mode: 'blue' } }) },
    { key: 'learn', label: 'Learning Resources',  icon: BookOpen,   onClick: () => navigate('/learn') },
    { key: 'rep',   label: 'Reports',             icon: FileText,   onClick: onReportsClick },
  ]

  const soonItems = [
    { key: 'profile',  label: 'Profile',  icon: User },
    { key: 'settings', label: 'Settings', icon: Settings },
  ]

  return (
    <aside className="dsb-sidebar">
      <div className="dsb-brand">
        <div className="dsb-logo-mark" aria-hidden />
        <div className="dsb-brand-text">
          <span className="dsb-brand-name">SENTINEL</span>
          <span className="dsb-brand-tagline">CYBERSECURITY TRAINING<br />SIMULATION PLATFORM</span>
        </div>
      </div>

      <nav className="dsb-nav">
        {navItems.map(item => (
          <button
            key={item.key}
            className={`dsb-nav-item ${item.active ? 'dsb-nav-active' : ''}`}
            onClick={item.onClick}
          >
            <item.icon size={17} />
            <span>{item.label}</span>
          </button>
        ))}

        <div className="dsb-nav-divider" />

        {soonItems.map(item => (
          <button key={item.key} className="dsb-nav-item dsb-nav-disabled" disabled>
            <item.icon size={17} />
            <span>{item.label}</span>
            <span className="dsb-soon">Soon</span>
          </button>
        ))}
      </nav>

      <button className="dsb-logout" onClick={onLogout}>
        <LogOut size={17} />
        <span>Logout</span>
      </button>
    </aside>
  )
}
