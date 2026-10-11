// components/AttackTimeline.jsx
// Stage 9/10 — attack-chain recap + defender-visible indicators, shown once
// the operation reaches its conclusion. This is a summary, not a second
// progress system — the kill-chain rail at the top of the page still owns
// stage navigation.
import { CheckCircle2 } from 'lucide-react'
import './AttackTimeline.css'

export default function AttackTimeline({ milestones, indicators }) {
  return (
    <div className="at-wrap">
      <div className="at-block">
        <span className="at-label">ATTACK CHAIN RESULT</span>
        <div className="at-milestones">
          {milestones.map((m) => (
            <div key={m.label} className="at-milestone">
              <CheckCircle2 size={14} className="at-check" />
              <span>{m.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="at-block">
        <span className="at-label">DEFENDER INDICATORS GENERATED</span>
        <p className="at-defender-note">
          These indicators are structured so the Blue Team SOC simulator can investigate this
          operation later.
        </p>
        <div className="at-indicators">
          {indicators.map((ind) => (
            <div key={ind.type} className="at-indicator">
              <span className="at-indicator-dot" />
              <div>
                <strong>{ind.label}</strong>
                <span className="at-indicator-detail">{ind.detail}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
