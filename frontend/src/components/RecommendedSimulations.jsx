// components/RecommendedSimulations.jsx
// Static educational catalogue — not backed by fake report data, just
// shortcuts into the existing Red/Blue team flow with a preset attack vector.
import { useNavigate } from 'react-router-dom'
import { Mail, Shield, Bug, Globe, ChevronRight } from 'lucide-react'
import './RecommendedSimulations.css'

const ITEMS = [
  { id: 'phishing',    title: 'Phishing Attack Simulation', team: 'Red Team',  level: 'Beginner',     icon: Mail,  mode: 'red',  attack: 'phishing' },
  { id: 'soc',         title: 'SOC Alert Analysis',         team: 'Blue Team', level: 'Intermediate', icon: Shield, mode: 'blue', attack: null, comingSoon: true },
  { id: 'ransomware',  title: 'Ransomware Investigation',   team: 'Blue Team', level: 'Intermediate', icon: Bug,   mode: 'blue', attack: 'ransomware' },
  { id: 'webapp',      title: 'Web Application Attack',     team: 'Red Team',  level: 'Advanced',     icon: Globe, mode: 'red',  attack: null, comingSoon: true },
]

export default function RecommendedSimulations({ query = '' }) {
  const navigate = useNavigate()
  const q = query.trim().toLowerCase()
  const items = q ? ITEMS.filter(i => i.title.toLowerCase().includes(q)) : ITEMS

  const open = (item) => {
    if (item.comingSoon) {
      navigate(`/coming-soon/${item.id}`)
    } else if (item.attack) {
      navigate('/guide', { state: { mode: item.mode, attack: item.attack } })
    } else {
      navigate('/attack-select', { state: { mode: item.mode } })
    }
  }

  return (
    <div className="rsim-card">
      <div className="rsim-head">
        <span className="rsim-dot" />
        <h3>Recommended Simulations</h3>
      </div>

      <div className="rsim-list">
        {items.map(item => (
          <button key={item.id} className="rsim-row" onClick={() => open(item)}>
            <span className={`rsim-icon rsim-${item.mode}`}><item.icon size={16} /></span>
            <div className="rsim-info">
              <span className="rsim-title">{item.title}</span>
              <span className="rsim-sub">{item.team} · {item.level}</span>
            </div>
            <ChevronRight size={15} className="rsim-chevron" />
          </button>
        ))}
        {items.length === 0 && <div className="rsim-empty">No matches for "{query}".</div>}
      </div>
    </div>
  )
}
