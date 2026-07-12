// pages/ModeSelect.jsx
import { useNavigate } from 'react-router-dom'
import './ModeSelect.css'
import NetworkBackground from '../components/NetworkBackground'

export default function ModeSelect() {
  const navigate = useNavigate()

  const selectMode = (mode) => {
    navigate('/attack-select', { state: { mode } })
  }

  return (
    <div className="ms-page">
      <NetworkBackground variant="blue" />
      <div className="ms-intro">
        <span className="ms-eyebrow">SENTINEL // KILL CHAIN SIMULATOR</span>
        <h1 className="ms-heading">Learn offense and defense<br />through live simulation</h1>
        <p className="ms-desc">
          Step through a real Cyber Kill Chain as either side of the fight.
          Choose your role to begin.
        </p>
      </div>

      <div className="ms-split">
        <button className="ms-panel ms-panel-red" onClick={() => selectMode('red')}>
          <span className="ms-tag ms-tag-red">ATTACKER</span>
          <h2>Red Team</h2>
          <p>Run the offense. Weaponize, deliver, exploit — and reach your objective before you're caught.</p>
          <span className="ms-cta">Select Red Team →</span>
        </button>

        <div className="ms-seam" />

        <button className="ms-panel ms-panel-blue" onClick={() => selectMode('blue')}>
          <span className="ms-tag ms-tag-blue">DEFENDER</span>
          <h2>Blue Team</h2>
          <p>Watch the signals. Detect each stage as it happens and intervene before impact.</p>
          <span className="ms-cta">Select Blue Team →</span>
        </button>
      </div>
    </div>
  )
}