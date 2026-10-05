// components/ThreatMap.jsx
// Stylized, fully simulated global "attack map" for the login screen preview.
// All data below is static/simulated — this never calls a live threat feed.
import './ThreatMap.css'

const REGIONS = [
  { id: 'na', label: 'North America', x: 165, y: 150, count: 1224, tone: 'red' },
  { id: 'sa', label: 'South America', x: 250, y: 365, count: 421,  tone: 'cyan' },
  { id: 'eu', label: 'Europe',        x: 490, y: 115, count: 2418, tone: 'white' },
  { id: 'af', label: 'Africa',        x: 505, y: 320, count: 389,  tone: 'cyan' },
  { id: 'as', label: 'Asia',          x: 700, y: 175, count: 3105, tone: 'red' },
  { id: 'oc', label: 'Oceania',       x: 790, y: 390, count: 276,  tone: 'cyan' },
]

const byId = Object.fromEntries(REGIONS.map(r => [r.id, r]))

const LINKS = [
  { from: 'as', to: 'eu', type: 'attack' },
  { from: 'as', to: 'na', type: 'attack' },
  { from: 'eu', to: 'na', type: 'data' },
  { from: 'af', to: 'eu', type: 'attack' },
  { from: 'sa', to: 'na', type: 'data' },
  { from: 'as', to: 'oc', type: 'attack' },
  { from: 'oc', to: 'af', type: 'data' },
  { from: 'na', to: 'af', type: 'attack' },
]

function curvePath(a, b) {
  const mx = (a.x + b.x) / 2
  const my = (a.y + b.y) / 2 - 60
  return `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`
}

export default function ThreatMap() {
  return (
    <div className="tm-wrap">
      <svg viewBox="0 0 1000 500" className="tm-svg" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id="tm-node-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#00D9FF" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#00D9FF" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="tm-attack-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#FF1744" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#FF1744" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#FF1744" stopOpacity="0.1" />
          </linearGradient>
          <linearGradient id="tm-data-line" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#00D9FF" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#00D9FF" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#00D9FF" stopOpacity="0.1" />
          </linearGradient>
        </defs>

        {/* faint continental blobs for a "world map" feel, purely decorative */}
        <g className="tm-landmass" opacity="0.5">
          <ellipse cx="165" cy="150" rx="110" ry="70" />
          <ellipse cx="250" cy="370" rx="75" ry="100" />
          <ellipse cx="490" cy="120" rx="80" ry="55" />
          <ellipse cx="510" cy="310" rx="90" ry="110" />
          <ellipse cx="700" cy="175" rx="140" ry="90" />
          <ellipse cx="790" cy="395" rx="60" ry="45" />
        </g>

        {LINKS.map((l, i) => {
          const a = byId[l.from]
          const b = byId[l.to]
          return (
            <path
              key={i}
              d={curvePath(a, b)}
              className={`tm-link tm-link-${l.type}`}
              stroke={l.type === 'attack' ? 'url(#tm-attack-line)' : 'url(#tm-data-line)'}
              style={{ animationDelay: `${i * 0.35}s` }}
            />
          )
        })}

        {REGIONS.map((r) => (
          <g key={r.id} className="tm-node-group">
            <circle cx={r.x} cy={r.y} r="26" fill="url(#tm-node-glow)" className="tm-node-halo" />
            <circle cx={r.x} cy={r.y} r="4.5" className="tm-node-dot" />
          </g>
        ))}
      </svg>

      <div className="tm-labels">
        {REGIONS.map((r) => (
          <div key={r.id} className="tm-label" style={{ left: `${r.x / 10}%`, top: `${r.y / 5}%` }}>
            <span className="tm-label-name">{r.label}</span>
            <span className={`tm-label-count tm-tone-${r.tone}`}>{r.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
