// components/blue/mission/ContextualHint.jsx
// "Need a hint?": three graduated hints. The server may supply a hint written
// by the local model from clues the student already has; if it cannot, the
// built-in hint for the step is used. Hints never complete anything.
import { useState } from 'react'
import { callApi } from '../blueApi'
import { staticHints } from './steps'

const LABELS = ['Where to look', 'What to look for', 'Why it matters']

export default function ContextualHint({ view, step }) {
  const [open, setOpen] = useState(false)
  const [shown, setShown] = useState([])
  const [loading, setLoading] = useState(false)
  const builtin = staticHints(step.id, view)

  const reveal = async () => {
    const level = shown.length + 1
    setLoading(true)
    let text = builtin[level - 1]
    let source = 'builtin'
    try {
      const { ok, data } = await callApi(`/api/blue-phishing/${view.session_id}/hint`, {
        body: { level, step: step.id, title: step.title },
      })
      if (ok && data.hint) { text = data.hint; source = 'ai' }
    } catch {
      /* the built-in hint is used */
    }
    setShown((s) => [...s, { level, text, source }])
    setLoading(false)
  }

  return (
    <div className="bg-hint-wrap">
      <button type="button" className="bg-btn bg-btn-quiet" aria-expanded={open} onClick={() => setOpen(!open)}>
        Need a hint?
      </button>
      {open && (
        <div className="bg-hint-panel" role="region" aria-label="Hints">
          {shown.map((h) => (
            <p key={h.level} className="bg-hint">
              <strong>Hint {h.level} — {LABELS[h.level - 1]}{h.source === 'ai' ? ' (AI mentor)' : ''}:</strong> {h.text}
            </p>
          ))}
          {shown.length < 3 ? (
            <button type="button" className="bg-btn" disabled={loading} onClick={reveal}>
              {loading ? 'Thinking…' : `Show hint ${shown.length + 1}`}
            </button>
          ) : <p className="bg-small">That is all the help for this step.</p>}
          <p className="bg-small">Hints never give the answer and do not change your score.</p>
        </div>
      )}
    </div>
  )
}
