// components/CampaignMonitorStage.jsx
// Visual CTA picker for the Exploitation stage. Renders the email as the victim
// sees it, with the CTA button swapping per option. On selection, simulates the
// victim's reaction — either ignoring it, or clicking through to a fake login
// page where credentials get "captured".

import { useState, useEffect } from 'react'
import './CampaignMonitorStage.css'

export default function CampaignMonitorStage({ options, onSelect, selectedId, feedback }) {
  const [hoveredId, setHoveredId] = useState(null)
  const [captureStage, setCaptureStage] = useState('idle') // idle | typing | captured
  const activeId = selectedId || hoveredId || options[0]?.id
  const active = options.find(o => o.id === activeId) || options[0]
  const locked = !!feedback
  const selected = options.find(o => o.id === selectedId)

  useEffect(() => {
    if (!selected) { setCaptureStage('idle'); return }
    if (!selected.preview.clicks) return
    const t1 = setTimeout(() => setCaptureStage('typing'), 500)
    const t2 = setTimeout(() => setCaptureStage('captured'), 1800)
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [selected])

  if (!active || options.some(o => !o.preview)) {
    return <div className="cm-wrapper-error">Campaign preview data missing for this stage.</div>
  }

  return (
    <div className="cm-wrapper">
      {/* Rendered inbox / email view */}
      <div className="cm-inbox">
        <div className="cm-inbox-topbar">
          <span className="cm-dot" /><span className="cm-dot" /><span className="cm-dot" />
          <span className="cm-inbox-title">Victim's Inbox</span>
        </div>
        <div className="cm-email">
          <div className="cm-email-header">
            <div className="cm-avatar">IT</div>
            <div>
              <div className="cm-sender">IT Support</div>
              <div className="cm-subject">Action Required: Your Password Expires Today</div>
            </div>
          </div>
          <div className="cm-email-body">
            <p>Hi there,</p>
            <p>Our records show your network password will expire in 1 hour. To avoid being locked out, please act now.</p>
            <button
              className={`cm-cta-btn ${active.preview.urgency ? 'urgency' : ''}`}
              onMouseEnter={() => !locked && setHoveredId(active.id)}
            >
              {active.preview.ctaText}
            </button>
            {active.preview.requiresMacro && (
              <p className="cm-macro-note">⚠ Requires macros enabled to open</p>
            )}
          </div>
        </div>
      </div>

      {/* Option picker (which CTA to send) */}
      <div className="cm-options">
        <span className="cm-options-label">Choose call-to-action</span>
        {options.map(opt => {
          const isSelected = selectedId === opt.id
          return (
            <button
              key={opt.id}
              className={`cm-option-btn ${isSelected ? `result-${opt.outcome}` : ''} ${locked && !isSelected ? 'dimmed' : ''}`}
              onMouseEnter={() => !locked && setHoveredId(opt.id)}
              onClick={() => !locked && onSelect(opt)}
              disabled={locked}
            >
              {opt.text}
            </button>
          )
        })}

        {/* Victim reaction simulation */}
        {selected && (
          <div className="cm-reaction">
            {!selected.preview.clicks ? (
              <p className="cm-reaction-none">No interaction — the victim ignored the email.</p>
            ) : (
              <div className="cm-capture-box">
                {captureStage === 'idle' && <p className="cm-reaction-none">Victim opened the email…</p>}
                {captureStage === 'typing' && (
                  <>
                    <div className="cm-fake-login">
                      <div className="cm-fake-login-title">🔒 Secure Login</div>
                      <div className="cm-fake-field">victim@company.com</div>
                      <div className="cm-fake-field cm-typing">••••••••<span className="cm-cursor">|</span></div>
                    </div>
                    <p className="cm-reaction-typing">Victim is entering credentials…</p>
                  </>
                )}
                {captureStage === 'captured' && (
                  <div className="cm-captured">
                    <span className="cm-captured-icon">✓</span>
                    <span>Credentials captured</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}