// components/LearningPopup.jsx
// Dismissible contextual popup used across the phishing simulation stages.
// Never auto-selects anything for the student — purely informational.
import { Lightbulb, AlertTriangle, GraduationCap, X } from 'lucide-react'
import './LearningPopup.css'

const CONFIG = {
  hint:    { icon: Lightbulb,      label: 'Analyst Tip',     cls: 'lp-hint' },
  warning: { icon: AlertTriangle,  label: 'Suspicious Strategy', cls: 'lp-warning' },
  learning:{ icon: GraduationCap,  label: 'Learning Moment', cls: 'lp-learning' },
}

export default function LearningPopup({ type = 'hint', title, children, onDismiss }) {
  const cfg = CONFIG[type] || CONFIG.hint
  const Icon = cfg.icon

  return (
    <div className={`lp-popup ${cfg.cls}`}>
      <div className="lp-head">
        <Icon size={15} />
        <span>{title || cfg.label}</span>
        {onDismiss && (
          <button type="button" className="lp-dismiss" onClick={onDismiss} aria-label="Dismiss">
            <X size={13} />
          </button>
        )}
      </div>
      <div className="lp-body">{children}</div>
    </div>
  )
}
