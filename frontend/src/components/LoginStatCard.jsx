// components/LoginStatCard.jsx
// Small glass stat card used in the Login page's simulated threat preview.
import './LoginStatCard.css'

const SPARK_SEED = [30, 45, 38, 55, 48, 62, 58, 70, 64, 80]

export default function LoginStatCard({ icon: Icon, tone = 'green', value, label, delta }) {
  return (
    <div className={`lsc-card lsc-${tone}`}>
      <div className="lsc-icon">
        <Icon size={18} />
      </div>
      <div className="lsc-info">
        <span className="lsc-value">{value}</span>
        <span className="lsc-label">{label}</span>
        {delta && <span className="lsc-delta">↑ {delta}</span>}
      </div>
      <div className="lsc-spark" aria-hidden>
        {SPARK_SEED.map((h, i) => (
          <span key={i} style={{ height: `${h}%` }} />
        ))}
      </div>
    </div>
  )
}
