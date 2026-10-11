// components/blue/guide/HelpUI.jsx
// Small, unobtrusive learning UI shared by every mission step: the modal
// shell, "?" terms, a dismissible first-time tip, result cards, folds and the
// glossary. Only one overlay is ever open: the page owns that state.
import { useEffect, useRef } from 'react'
import { GLOSSARY } from './glossary'
import { useGuide } from './guideContext'

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function Modal({ labelledBy, onClose, children, size = 'md', initialFocus }) {
  const ref = useRef(null)

  useEffect(() => {
    const previous = document.activeElement
    const node = ref.current
    const target = (initialFocus && node.querySelector(initialFocus)) || node.querySelector(FOCUSABLE) || node
    target.focus()
    const onKey = (e) => {
      if (e.key === 'Escape') { e.stopPropagation(); onClose() }
      if (e.key !== 'Tab') return
      const items = [...node.querySelectorAll(FOCUSABLE)]
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (previous && previous.focus) previous.focus()
    }
    // The shell mounts once per overlay; onClose identity changes must not refocus.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="bg-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div ref={ref} className={`bg-modal bg-modal-${size}`} role="dialog" aria-modal="true"
        aria-labelledby={labelledBy} tabIndex={-1}>
        {children}
      </div>
    </div>
  )
}

export function Term({ id, children }) {
  const { openTerm } = useGuide()
  const entry = GLOSSARY[id]
  if (!entry) return <>{children}</>
  return (
    <span className="bg-term">
      {children}
      <button type="button" className="bg-q" aria-label={`What is ${entry.title}?`}
        onClick={() => openTerm(id)}>?</button>
    </span>
  )
}

export function TermDialog({ id, onClose }) {
  const t = GLOSSARY[id]
  if (!t) return null
  return (
    <Modal labelledBy="bg-term-title" onClose={onClose} size="sm" initialFocus=".bg-close">
      <header className="bg-modal-head">
        <h2 id="bg-term-title">What is {t.title}?</h2>
        <button type="button" className="bg-close" aria-label="Close explanation" onClick={onClose}>×</button>
      </header>
      <p>{t.what}</p>
      <p className="bg-example"><strong>Example: </strong>{t.example}</p>
      <details className="bg-fold">
        <summary>Learn more</summary>
        <div className="bg-fold-body">
          <p><strong>Why analysts use it: </strong>{t.why}</p>
          <p><strong>What to look for: </strong>{t.look}</p>
        </div>
      </details>
      <div className="bg-modal-actions">
        <button type="button" className="bg-btn" onClick={onClose}>Close</button>
      </div>
    </Modal>
  )
}

export function GlossaryDialog({ onClose }) {
  const { openTerm } = useGuide()
  return (
    <Modal labelledBy="bg-help-title" onClose={onClose} initialFocus=".bg-close">
      <header className="bg-modal-head">
        <h2 id="bg-help-title">What does this word mean?</h2>
        <button type="button" className="bg-close" aria-label="Close help" onClick={onClose}>×</button>
      </header>
      <div className="bg-term-list">
        {Object.entries(GLOSSARY).map(([id, t]) => (
          <button type="button" key={id} className="bg-chip" onClick={() => openTerm(id)}>{t.title}</button>
        ))}
      </div>
    </Modal>
  )
}

// A short, dismissible tip shown the first time a kind of step is met.
export function TipBanner({ id, tip }) {
  const { seen, markSeen } = useGuide()
  if (!tip || seen[id]) return null
  return (
    <div className="bg-tip" role="note" aria-label={tip.title}>
      <p><strong>{tip.title}</strong> {tip.body}</p>
      <button type="button" className="bg-btn" onClick={() => markSeen(id)}>{tip.button || 'Got it'}</button>
    </div>
  )
}

export function ResultCard({ result, onDismiss }) {
  if (!result) return null
  const icon = { ok: '✓', warn: '!', error: '×', info: 'i' }[result.kind] || 'i'
  return (
    <section className={`bg-result bg-result-${result.kind}`} role={result.kind === 'error' ? 'alert' : 'status'} aria-live="polite">
      <span className="bg-result-icon" aria-hidden="true">{icon}</span>
      <div className="bg-result-body">
        <strong>{result.title}</strong>
        <p>{result.body}</p>
        {result.lines && result.lines.length > 0 && (
          <ul>{result.lines.map((l) => <li key={l}>{l}</li>)}</ul>
        )}
        {result.risks && result.risks.length > 0 && (
          <ul>{result.risks.map((r) => <li key={r}>{r}</li>)}</ul>
        )}
        {result.extra && result.extra.map((x, i) => <p key={i} className="bg-small">{x}</p>)}
        {result.next && <p className="bg-small"><strong>Next:</strong> {result.next}</p>}
      </div>
      <button type="button" className="bg-close" aria-label="Dismiss message" onClick={onDismiss}>×</button>
    </section>
  )
}

// Collapsible section used for "Learn more" / advanced details (closed by default).
export function Fold({ title, children, defaultOpen = false }) {
  return (
    <details className="bg-fold" open={defaultOpen || undefined}>
      <summary>{title}</summary>
      <div className="bg-fold-body">{children}</div>
    </details>
  )
}
