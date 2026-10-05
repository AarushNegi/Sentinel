// components/EmailBuilderStage.jsx
// Visual template picker for the Weaponization stage — a live email preview
// pane instead of plain text buttons. Selecting a template calls onSelect(option),
// same as the generic MCQ flow, just wrapped in a real-feeling tool.

import { useState } from 'react'
import './EmailBuilderStage.css'

export default function EmailBuilderStage({ options, onSelect, selectedId, feedback }) {
  const [hoveredId, setHoveredId] = useState(null)
  const activeId = selectedId || hoveredId || options[0]?.id
  const active = options.find(o => o.id === activeId) || options[0]
  const locked = !!feedback

  // Guard: this component requires preview data on every option. If it's missing
  // (e.g. wired up to a stage whose data wasn't updated), show a clear message
  // instead of crashing on undefined access.
  if (!active || options.some(o => !o.preview)) {
    return <div className="eb-wrapper-error">Email preview data missing for this stage.</div>
  }

  return (
    <div className="eb-wrapper">
      {/* Template picker */}
      <div className="eb-templates">
        <span className="eb-templates-label">Templates</span>
        {options.map(opt => {
          const isActive   = activeId === opt.id
          const isSelected = selectedId === opt.id
          return (
            <button
              key={opt.id}
              className={`eb-template-card ${isActive ? 'active' : ''} ${isSelected ? `result-${opt.outcome}` : ''} ${locked && !isSelected ? 'dimmed' : ''}`}
              onMouseEnter={() => !locked && setHoveredId(opt.id)}
              onClick={() => !locked && onSelect(opt)}
              disabled={locked}
            >
              <span className="eb-template-swatch" style={{ background: opt.preview.brandColor }} />
              <span className="eb-template-info">
                <span className="eb-template-subject">{opt.preview.subject}</span>
                <span className="eb-template-badge">{opt.preview.badge}</span>
              </span>
            </button>
          )
        })}
      </div>

      {/* Live email preview */}
      <div className="eb-preview">
        <div className="eb-preview-topbar">
          <span className="eb-dot" /><span className="eb-dot" /><span className="eb-dot" />
          <span className="eb-preview-title">Live Preview</span>
        </div>
        <div className="eb-preview-body">
          <div className="eb-preview-header" style={{ borderColor: active.preview.brandColor }}>
            <div className="eb-avatar" style={{ background: active.preview.brandColor }}>
              {active.preview.sender[0]}
            </div>
            <div className="eb-header-text">
              <span className="eb-sender">{active.preview.sender} <span className="eb-sender-email">&lt;{active.preview.senderEmail}&gt;</span></span>
              <span className="eb-subject">{active.preview.subject}</span>
            </div>
          </div>
          <div className="eb-preview-content">
            {active.preview.body.split('\n').map((line, i) => <p key={i}>{line || '\u00A0'}</p>)}
            {active.preview.attachment && (
              <div className="eb-attachment">📎 {active.preview.attachment}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}