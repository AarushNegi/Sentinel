// components/DashboardStatCard.jsx
import './DashboardStatCard.css'

export default function DashboardStatCard({ icon: Icon, tone, label, value, sub, subTone }) {
  return (
    <div className="dsc-card">
      <div className={`dsc-icon dsc-${tone}`}>
        <Icon size={19} />
      </div>
      <div className="dsc-info">
        <span className="dsc-label">{label}</span>
        <span className="dsc-value">{value}</span>
        {sub && <span className={`dsc-sub ${subTone ? `dsc-sub-${subTone}` : ''}`}>{sub}</span>}
      </div>
    </div>
  )
}
