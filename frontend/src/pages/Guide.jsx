// pages/Guide.jsx
import { useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import NetworkBackground from '../components/NetworkBackground'
import './Guide.css'

export default function Guide() {
  const navigate = useNavigate()
  const location = useLocation()
  const { mode = 'red', attack = 'phishing' } = location.state || {}

  const [guide, setGuide] = useState(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    setGuide(null)
    setError(false)

    import(`../data/guides/${mode}/${attack}.js`)
      .then((mod) => setGuide(mod.default))
      .catch(() => setError(true))
  }, [mode, attack])

  const startSimulation = () => {
    navigate('/simulation', { state: { mode, attack } })
  }

  if (error) {
    return (
      <div className={`gd-page gd-${mode}`}>
        <NetworkBackground variant={mode} />
        <p className="gd-error">Couldn't load the guide for this combination.</p>
      </div>
    )
  }

  if (!guide) {
    return (
      <div className={`gd-page gd-${mode}`}>
        <NetworkBackground variant={mode} />
        <p className="gd-loading">Loading guide…</p>
      </div>
    )
  }

  return (
    <div className={`gd-page gd-${mode}`}>
      <NetworkBackground variant={mode} />
      <div className="gd-header">
        <span className="gd-eyebrow">
          {mode === 'red' ? 'RED TEAM BRIEFING' : 'BLUE TEAM BRIEFING'} — {guide.title}
        </span>
        <h1>{guide.headline}</h1>
      </div>

      <section className="gd-section">
        <h2>Overview</h2>
        <p>{guide.overview}</p>
      </section>

      <section className="gd-section">
        <h2>{mode === 'red' ? 'Targets' : 'What to Protect'}</h2>
        <ul className="gd-list">
          {guide.targets.map((t, i) => <li key={i}>{t}</li>)}
        </ul>
      </section>

      <section className="gd-section">
        <h2>Stage-by-Stage Tactics</h2>
        <div className="gd-stages">
          {guide.stages.map((s, i) => (
            <div className="gd-stage-row" key={i}>
              <span className="gd-stage-num">{i + 1}</span>
              <div>
                <h3>{s.name}</h3>
                <p>{s.tactic}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="gd-section">
        <h2>Field Tips</h2>
        <ul className="gd-tips">
          {guide.tips.map((t, i) => <li key={i}>{t}</li>)}
        </ul>
      </section>

      <button className="gd-start" onClick={startSimulation}>
        Start Simulation →
      </button>
    </div>
  )
}