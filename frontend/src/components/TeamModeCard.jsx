// components/TeamModeCard.jsx
import { ArrowRight } from 'lucide-react'
import './TeamModeCard.css'

export default function TeamModeCard({ team, title, tagline, description, chips, chipIcons, onEnter, illustration }) {
  return (
    <div className={`tmc-card tmc-${team}`}>
      <div className="tmc-text">
        <span className="tmc-title">{title}</span>
        <h3 className="tmc-tagline">{tagline}</h3>
        <p className="tmc-desc">{description}</p>

        <div className="tmc-chips">
          {chips.map((chip, i) => {
            const Icon = chipIcons?.[i]
            return (
              <span className="tmc-chip" key={chip}>
                {Icon && <Icon size={12} />}
                {chip}
              </span>
            )
          })}
        </div>

        <button className="tmc-btn" onClick={onEnter}>
          {title === 'RED TEAM' ? 'Enter Red Team' : 'Enter Blue Team'} <ArrowRight size={15} />
        </button>
      </div>

      <div className="tmc-illustration">
        {illustration}
      </div>
    </div>
  )
}
