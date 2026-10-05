// components/ThreatFeed.jsx
// Simulated threat-feed table, shared by the Login preview and the Dashboard.
// All rows are generated locally — never fetched from a real/live external feed.
import { useEffect, useRef, useState } from 'react'
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

const THREAT_TYPES = Object.keys(ICONS)
const SEVERITIES = ['High', 'High', 'Medium', 'Medium', 'Medium', 'Critical']
const TARGETS = [
  'India', 'United States', 'Germany', 'Singapore', 'United Kingdom', 'Brazil',
  'Japan', 'France', 'Canada', 'Vietnam', 'Australia', 'South Africa', 'Mexico',
]

function formatClock(d) {
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
}
function currentTime() {
  return formatClock(new Date())
}
// Seed rows are timestamped relative to "now" (computed once, at module load —
// i.e. on every page load/refresh) so they never show a stale fixed clock time.
export function timeAgo(secondsAgo) {
  return formatClock(new Date(Date.now() - secondsAgo * 1000))
}

export const DEFAULT_THREAT_ROWS = [
  { time: timeAgo(0),  type: 'Phishing Email',          source: '185.226.12.41', target: 'India',           severity: 'High' },
  { time: timeAgo(14), type: 'Brute Force Login',        source: '41.77.33.102',  target: 'United States',   severity: 'Medium' },
  { time: timeAgo(31), type: 'Malware Distribution',     source: '103.21.244.18', target: 'Germany',         severity: 'High' },
  { time: timeAgo(45), type: 'DDoS Attack',              source: '190.42.12.76',  target: 'Singapore',       severity: 'Critical' },
  { time: timeAgo(62), type: 'Suspicious File Upload',   source: '45.67.89.12',   target: 'United Kingdom',  severity: 'Medium' },
]

let rowIdSeq = 0
function randomIp() {
  return `${1 + Math.floor(Math.random() * 223)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
}
function generateRow() {
  rowIdSeq += 1
  return {
    id: `live-${Date.now()}-${rowIdSeq}`,
    time: currentTime(),
    type: THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)],
    source: randomIp(),
    target: TARGETS[Math.floor(Math.random() * TARGETS.length)],
    severity: SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)],
  }
}

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
  live = false,
}) {
  const Icon = icon || Activity
  const [liveRows, setLiveRows] = useState(rows)
  const lengthRef = useRef(rows.length)

  // Reseed whenever the caller swaps the base row set (e.g. Login's "View All" expand).
  useEffect(() => {
    lengthRef.current = rows.length
    setLiveRows(rows)
  }, [rows])

  useEffect(() => {
    if (!live) return
    const tick = () => {
      setLiveRows(prev => [generateRow(), ...prev].slice(0, lengthRef.current))
    }
    const id = setInterval(tick, 3200 + Math.random() * 1800)
    return () => clearInterval(id)
  }, [live])

  const displayRows = live ? liveRows : rows

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
        {displayRows.map((r, i) => {
          const RowIcon = ICONS[r.type] || Activity
          return (
            <div className="tf-row" key={r.id ?? i} style={{ animationDelay: `${i * 60}ms` }}>
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
