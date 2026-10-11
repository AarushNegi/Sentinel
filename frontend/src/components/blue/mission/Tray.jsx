// components/blue/mission/Tray.jsx
// The clue tray: a drawer that opens on request. Clues come from the server
// and carry where they came from and when. Opening it reveals nothing new.
import { useState } from 'react'
import { Modal } from '../guide/HelpUI'
import { clock, prettify } from '../blueApi'

export default function Tray({ view, evidenceCard, pinned, onClose }) {
  const [tab, setTab] = useState('clues')
  const [openId, setOpenId] = useState(null)
  const clues = [...view.evidence].reverse()

  return (
    <Modal labelledBy="bg-tray-title" onClose={onClose} size="lg" initialFocus=".bg-close">
      <header className="bg-modal-head">
        <h2 id="bg-tray-title">Your clues</h2>
        <button type="button" className="bg-close" aria-label="Close clues" onClick={onClose}>×</button>
      </header>
      <div className="bg-tabs" role="tablist">
        <button type="button" role="tab" aria-selected={tab === 'clues'} className={tab === 'clues' ? 'on' : ''} onClick={() => setTab('clues')}>
          Clues ({view.evidence.length})
        </button>
        <button type="button" role="tab" aria-selected={tab === 'timeline'} className={tab === 'timeline' ? 'on' : ''} onClick={() => setTab('timeline')}>
          What happened
        </button>
      </div>

      {tab === 'clues' && (
        clues.length === 0 ? <p className="bg-small">No clues yet. Click things in the investigation to find some.</p> : (
          <ul className="bg-clues">
            {clues.map((e) => (
              <li key={e.id}>
                <button type="button" className="bg-clue" aria-expanded={openId === e.id} onClick={() => setOpenId(openId === e.id ? null : e.id)}>
                  <strong>{e.title}</strong>
                  <span>{e.content.verdict || e.content.summary}</span>
                  <small>{e.source_artifact || prettify(e.category)} · found at {clock(e.discovered_at)}{pinned.includes(e.id) ? ' · used as proof' : ''}</small>
                </button>
                {openId === e.id && evidenceCard(e)}
              </li>
            ))}
          </ul>
        )
      )}

      {tab === 'timeline' && (
        <ol className="bg-live-timeline">
          {view.timeline.map((t, i) => (
            <li key={`${t.clock}-${i}`} className={`kind-${t.kind}`}><small>{t.clock}</small> {t.message}</li>
          ))}
        </ol>
      )}
    </Modal>
  )
}
