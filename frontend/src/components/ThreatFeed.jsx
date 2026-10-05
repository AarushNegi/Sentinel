// components/ThreatFeed.jsx
// Simulated threat-feed table, shared by the Login preview and the Dashboard.
// All rows are static example data — never a real/live external feed.
import { Mail, KeyRound, Bug, Radar, UploadCloud, LogIn, Activity } from 'lucide-react'
import './ThreatFeed.css'

const ICONS = {
  'Phishing Email': Mail,
  'Brute Force Login': KeyRound,
  'Malware Distribution': Bug,
  'DDoS Attack': Radar,
  'Suspicious File Upload': UploadCloud,
  'Suspicious Login': LogIn,
}

export const DEFAULT_THREAT_ROWS = [
  { time: '20:14:12', type: 'Phishing Email',          source: '185.226.12.41', target: 'India',           severity: 'High' },
  { time: '20:13:58', type: 'Brute Force Login',        source: '41.77.33.102',  target: 'United States',   severity: 'Medium' },
  { time: '20:13:41', type: 'Malware Distribution',     source: '103.21.244.18', target: 'Germany',         severity: 'High' },
  { time: '20:13:27', type: 'DDoS Attack',              source: '190.42.12.76',  target: 'Singapore',       severity: 'Critical' },
  { time: '20:13:10', type: 'Suspicious File Upload',   source: '45.67.89.12',   target: 'United Kingdom',  severity: 'Medium' },
]

function SeverityBadge({ level }) {
  return <span className={`tf-badge tf-badge-${level.toLowerCase()}`}>{level}</span>
}

export default function ThreatFeed({
  title = 'Live Threat Feed',
  icon,
  badgeText,
  rows = DEFAULT_THREAT_ROWS,
  onViewAll,
  dotColor = 'red',
}) {
  const Icon = icon || Activity

  return (
    <div className="tf-card">
      <div className="tf-head">
        <div className="tf-head-left">
          <span className={`tf-dot tf-dot-${dotColor}`} />
          <Icon className="tf-head-icon" size={15} />
          <h3>{title}</h3>
          {badgeText && <span className="tf-feed-badge">{badgeText}</span>}
        </div>
        {onViewAll && (
          <button type="button" className="tf-viewall" onClick={onViewAll}>
            View All →
          </button>
        )}
      </div>

      <div className="tf-table">
        <div className="tf-row tf-row-head">
          <span>TIME</span>
          <span>THREAT TYPE</span>
          <span>SOURCE</span>
          <span>TARGET</span>
          <span>SEVERITY</span>
        </div>
        {rows.map((r, i) => {
          const RowIcon = ICONS[r.type] || Activity
          return (
            <div className="tf-row" key={i} style={{ animationDelay: `${i * 60}ms` }}>
              <span className="tf-time">{r.time}</span>
              <span className="tf-type">
                <RowIcon size={13} className="tf-type-icon" />
                {r.type}
              </span>
              <span className="tf-source">{r.source}</span>
              <span className="tf-target">{r.target}</span>
              <span><SeverityBadge level={r.severity} /></span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
