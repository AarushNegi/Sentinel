// components/HomeButton.jsx
// Fixed-position button shown on every in-app page to jump back to the Dashboard.
import { useNavigate } from 'react-router-dom'
import './HomeButton.css'

export default function HomeButton() {
  const navigate = useNavigate()
  return (
    <button className="home-btn" onClick={() => navigate('/dashboard')} aria-label="Back to Dashboard">
      🛡️ <span>Dashboard</span>
    </button>
  )
}