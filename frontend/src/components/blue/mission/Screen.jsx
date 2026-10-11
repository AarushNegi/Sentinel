// components/blue/mission/Screen.jsx
// The frame every step shares: one title, one sentence, one activity, one
// primary button, an optional hint and a simple progress label.
import { TipBanner } from '../guide/HelpUI'
import { STEP_TIPS } from './steps'
import ContextualHint from './ContextualHint'

export default function Screen({ view, step, index, total, ready, onBack, onNext, nextLabel, children, hideNav = false }) {
  return (
    <section className="bg-screen" aria-labelledby="bg-step-title">
      <p className="bg-progress" aria-live="polite">Step {index + 1} of {total}</p>
      <div className="bg-bar bg-bar-thin" aria-hidden="true"><i style={{ width: `${((index + 1) / total) * 100}%` }} /></div>
      <h1 id="bg-step-title" className="bg-title">{step.title}</h1>
      <p className="bg-objective">{step.objective}</p>
      <TipBanner id={`tip-${step.id}`} tip={STEP_TIPS[step.id]} />
      <div className="bg-activity">{children}</div>
      {!hideNav && (
        <footer className="bg-footer">
          <div className="bg-footer-left">
            {index > 0 && <button type="button" className="bg-btn bg-btn-quiet" onClick={onBack}>← Back</button>}
            <ContextualHint key={step.id} view={view} step={step} />
          </div>
          <div className="bg-footer-right">
            {!ready && step.gate && <span className="bg-small">{step.gate}</span>}
            {nextLabel && <button type="button" className="bg-btn bg-primary bg-big" disabled={!ready} onClick={onNext}>{nextLabel}</button>}
          </div>
        </footer>
      )}
    </section>
  )
}
