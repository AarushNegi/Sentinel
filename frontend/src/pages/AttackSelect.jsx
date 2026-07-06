// pages/AttackSelect.jsx
import { useLocation, useNavigate } from 'react-router-dom'
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
    id: 'supplyChain',
    name: 'Supply-Chain',
    target: 'Trusted third-party software',
    desc: 'Poison a vendor update so it gets installed automatically by every downstream user.'
  }
]

export default function AttackSelect() {
  const navigate = useNavigate()
  const location = useLocation()
  const mode = location.state?.mode || 'red'

  const selectAttack = (attackId) => {
    navigate('/guide', { state: { mode, attack: attackId } })
  }

  return (
    <div className={`as-page as-${mode}`}>
      <div className="as-header">
        <span className="as-eyebrow">
          {mode === 'red' ? 'RED TEAM // SELECT ATTACK' : 'BLUE TEAM // SELECT SCENARIO'}
        </span>
        <h1>{mode === 'red' ? 'Choose your attack vector' : 'Choose the scenario to defend'}</h1>
      </div>

      <div className="as-grid">
        {ATTACKS.map((atk) => (
          <button
            key={atk.id}
            className="as-card"
            onClick={() => selectAttack(atk.id)}
          >
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