// components/blue/mission/IncidentHeader.jsx
// Brand, incident title, a plain status and a threat indicator. Nothing else.
const THREAT = (view) => {
  if (view.status === 'completed') return view.outcome === 'contained' ? ['calm', 'Contained'] : ['high', 'Not fully contained']
  const attacked = view.timeline.some((t) => t.kind === 'attacker')
  if (attacked) return ['high', 'Threat is escalating']
  return view.incident.open ? ['mid', 'Threat active'] : ['low', 'Waiting']
}

export default function IncidentHeader({ view, sound, onSound, onTray, onHelp, onExit }) {
  const [level, label] = THREAT(view)
  return (
    <header className="bg-topbar">
      <div className="bg-brand"><span className="bg-brand-mark" aria-hidden="true" /><strong>Sentinel</strong><span>Blue Team</span></div>
      <div className="bg-top-info">
        <strong className="bg-incident-title">{view.incident.open ? view.incident.title : 'New alert'}</strong>
        <span className={`bg-threat bg-threat-${level}`} role="status">{label}</span>
      </div>
      <div className="bg-top-actions">
        <button type="button" className="bg-btn" onClick={onTray}>Clues ({view.evidence.length})</button>
        <button type="button" className="bg-btn" aria-pressed={sound} onClick={onSound}>{sound ? 'Sound on' : 'Sound off'}</button>
        <button type="button" className="bg-btn" onClick={onHelp}>Help</button>
        <button type="button" className="bg-btn bg-btn-danger" onClick={onExit}>Exit</button>
      </div>
    </header>
  )
}
