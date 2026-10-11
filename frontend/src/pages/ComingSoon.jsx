// pages/ComingSoon.jsx
// Placeholder for recommended simulations that are not built yet. The
// simulation is identified by the URL (/coming-soon/:slug), so a direct visit
// or a refresh works the same as arriving from the Dashboard.
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Construction } from 'lucide-react'
import './ComingSoon.css'

const UPCOMING = {
  soc: { title: 'SOC Alert Analysis', team: 'Blue Team', level: 'Intermediate', mode: 'blue' },
  webapp: { title: 'Web Application Attack', team: 'Red Team', level: 'Advanced', mode: 'red' },
}

export default function ComingSoon() {
  const navigate = useNavigate()
  const { slug } = useParams()
  const sim = UPCOMING[slug]

  return (
    <div className={`cs-page cs-${sim ? sim.mode : 'blue'}`}>
      <div className="cs-card" role="main">
        <span className="cs-icon" aria-hidden="true"><Construction size={28} /></span>
        {sim && <span className="cs-meta">{sim.team} · {sim.level}</span>}
        <h2 className="cs-sim">{sim ? sim.title : 'This simulation'}</h2>
        <h1 className="cs-title">Coming Soon</h1>
        <p className="cs-text">This simulation is currently under development. Stay tuned for updates.</p>
        <button type="button" className="cs-btn" onClick={() => navigate('/dashboard')}>
          <ArrowLeft size={15} /> Back to Dashboard
        </button>
      </div>
    </div>
  )
}
