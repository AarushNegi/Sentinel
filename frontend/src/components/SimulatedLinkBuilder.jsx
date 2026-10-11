// components/SimulatedLinkBuilder.jsx
// Stage 4 — entirely local/simulated URL builder. Never creates or contacts
// a real domain; the training domain is fictional and not resolvable.
// URL/domain risk analysis is intentionally not shown here — that's the
// Blue Team's job in the SOC simulator, not something handed to the attacker.
import { ArrowRight } from 'lucide-react'
import './SimulatedLinkBuilder.css'

export default function SimulatedLinkBuilder({ platform, path, onPathChange, onContinue }) {
  const cleanPath = path.replace(/^\/+/, '')
  const url = `${platform.trainingDomain}/${cleanPath}`

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // LINK BUILDER</div>
      <h1>Build the simulated link.</h1>
      <p>This domain is entirely fictional and local to Sentinel — it is never contacted over the network.</p>

      <div className="sl-builder">
        <div className="sl-field">
          <span>PLATFORM</span>
          <strong>{platform.platform}</strong>
        </div>
        <div className="sl-field">
          <span>TRAINING DOMAIN</span>
          <strong>{platform.trainingDomain}</strong>
        </div>
        <div className="sl-field">
          <span>PATH</span>
          <input value={path} onChange={(e) => onPathChange(e.target.value)} />
        </div>
      </div>

      <div className="sl-generated">
        <span>GENERATED URL</span>
        <strong>{url}</strong>
      </div>

      <button className="rp-primary-btn" onClick={onContinue}>
        Continue to Delivery <ArrowRight size={15} />
      </button>
    </div>
  )
}
