// components/CampaignAnalysis.jsx
// Live, deterministic "training simulation estimate" for the email the
// student is actually composing. Never calls an external/AI service.
import './CampaignAnalysis.css'

const METRICS = [
  { key: 'relevance',   label: 'Relevance',   tone: 'blue' },
  { key: 'credibility', label: 'Credibility', tone: 'green' },
  { key: 'urgency',     label: 'Urgency',     tone: 'yellow' },
  { key: 'suspicion',   label: 'Suspicion',   tone: 'red' },
]

export default function CampaignAnalysis({ analysis }) {
  return (
    <div className="ca-wrap">
      <div className="ca-head">
        <span>Campaign Analysis</span>
        <span className="ca-badge">TRAINING SIMULATION ESTIMATE</span>
      </div>
      <div className="ca-metrics">
        {METRICS.map((m) => (
          <div className="ca-metric" key={m.key}>
            <div className="ca-metric-top">
              <span>{m.label}</span>
              <strong>{analysis[m.key]}%</strong>
            </div>
            <div className="ca-bar">
              <div className={`ca-bar-fill ca-${m.tone}`} style={{ width: `${analysis[m.key]}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
