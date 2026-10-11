import { useLocation, useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './AttackSelect.css'

const ATTACKS = [
  {
    id: 'phishing',
    name: 'Phishing',
    target: 'Employee credentials',
    desc: 'Trick a target into handing over access through a fake login page or email.'
  },
  {
    id: 'ransomware',
    name: 'Ransomware',
    target: 'Workstation → file shares',
    desc: 'Encrypt files across a machine and spread to shared drives before demanding payment.'
  },
  {
    id: 'incidentResponse',
    name: 'Incident Response',
    target: 'Organization',
    desc: 'Respond to and mitigate the impact of a security breach or incident.',
    blueOnly: true
  },
  
  {
    id: 'va',
    name: 'Vulnerability Assessment',
    target: 'Full asset inventory',
    desc: 'Discover assets, assess CVEs, score risk, assign remediation, and verify fixes.',
    badge: 'TVM',
    blueOnly: true
  },
]

export default function AttackSelect() {
  const navigate = useNavigate()
  const location = useLocation()
  const mode = location.state?.mode || 'red'

  const visibleAttacks = ATTACKS.filter((atk) => !atk.blueOnly || mode === 'blue')

  const selectAttack = (attackId) => {
    if (attackId === 'incidentResponse') {
      navigate('/incident-response')
      return
    }
    if (attackId === 'va') {
      navigate('/va-simulation', { state: { mode: 'blue' } })
      return
    }
    navigate('/guide', { state: { mode, attack: attackId } })
  }

  return (
    <div className={`as-page as-${mode}`}>
      <NetworkBackground variant={mode} />
      <div className="as-header">
        <span className="as-eyebrow">
          {mode === 'red' ? 'RED TEAM // SELECT ATTACK' : 'BLUE TEAM // SELECT SCENARIO'}
        </span>
        <h1>{mode === 'red' ? 'Choose your attack vector' : 'Choose the scenario to defend'}</h1>
      </div>

      <div className="as-grid">
        {visibleAttacks.map((atk) => (
          <button
            key={atk.id}
            className={`as-card ${atk.id === 'va' ? 'as-card-va' : ''}`}
            onClick={() => selectAttack(atk.id)}
          >
            {atk.badge && <span className="as-badge">{atk.badge}</span>}
            <h2>{atk.name}</h2>
            <span className="as-target">Target: {atk.target}</span>
            <p>{atk.desc}</p>
            <span className="as-cta">Select →</span>
          </button>
        ))}
      </div>
    </div>
  )
}