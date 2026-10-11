// components/CredentialSimulation.jsx
// Stage 7/8 — appears on the attacker side the instant the (scripted) target
// submits the login form. The account/password shown here are always the
// fixed, fictional training credential (same for every persona, never a
// real-typed secret) — safe to display explicitly. Never persisted to
// MongoDB regardless.
import './CredentialSimulation.css'

export default function CredentialSimulation({ visible, target }) {
  if (!visible || !target) return null

  return (
    <div className="cs-panel">
      <div className="cs-title">SIMULATED CREDENTIAL SUBMISSION</div>
      <div className="cs-row"><span>TARGET</span><strong>{target.name}</strong></div>
      <div className="cs-row"><span>ACCOUNT</span><strong>{target.trainingAccount}</strong></div>
      <div className="cs-row"><span>PASSWORD</span><strong className="cs-mono">{target.trainingPassword}</strong></div>
      <div className="cs-status">
        <span className="cs-pulse" />
        SIMULATION ONLY — a fixed training credential, never a real password
      </div>
    </div>
  )
}
