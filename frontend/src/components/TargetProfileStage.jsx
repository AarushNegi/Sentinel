// components/TargetProfileStage.jsx
// Stage 2 — Target Profiling workspace. The student chooses which intel to
// carry forward into the campaign; this directly feeds the scoring engine.
import './TargetProfileStage.css'

export default function TargetProfileStage({ intelItems, selectedIds, onToggle, onContinue }) {
  const selected = intelItems.filter((i) => selectedIds.includes(i.id))

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // TARGET PROFILING</div>
      <h1>Build your target profile.</h1>
      <p>Select the intelligence you want to carry into the campaign. Not everything here is equally useful.</p>

      <div className="tp-checklist">
        {intelItems.map((item) => {
          const checked = selectedIds.includes(item.id)
          return (
            <label key={item.id} className={`tp-item ${checked ? 'checked' : ''}`}>
              <input type="checkbox" checked={checked} onChange={() => onToggle(item.id)} />
              <span className="tp-box" />
              {item.label}
            </label>
          )
        })}
      </div>

      <div className="tp-selected">
        <span className="tp-selected-label">SELECTED INTELLIGENCE</span>
        {selected.length === 0 ? (
          <span className="tp-selected-empty">Nothing selected yet.</span>
        ) : (
          <div className="tp-selected-chips">
            {selected.map((i) => <span key={i.id} className="tp-chip">{i.label}</span>)}
          </div>
        )}
      </div>

      <button className="rp-primary-btn" onClick={() => onContinue(selected)} disabled={selected.length === 0}>
        Build Campaign Context →
      </button>
    </div>
  )
}
