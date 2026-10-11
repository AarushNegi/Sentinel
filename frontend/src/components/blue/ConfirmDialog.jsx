// components/blue/ConfirmDialog.jsx
// Every consequential defensive action is confirmed here first. The dialog
// names the real target and the real expected effect (from the server's
// action list); it never claims success. The server refuses unconfirmed
// actions independently, so this cannot be bypassed from the UI alone.
import { CONFIRM_COPY } from './guide/guidance'
import { Modal } from './guide/HelpUI'

export default function ConfirmDialog({ pending, busy, onConfirm, onCancel }) {
  if (!pending) return null
  const copy = CONFIRM_COPY[pending.action] || {
    title: `${pending.actionLabel}?`, verb: 'Confirm', body: pending.impact, consideration: '',
  }
  const targetLabel = pending.targetLabel || 'The whole incident'

  return (
    <Modal labelledBy="bg-confirm-title" onClose={onCancel} initialFocus=".bg-primary">
      <header className="bg-modal-head">
        <h2 id="bg-confirm-title">{copy.title}</h2>
        <button type="button" className="bg-close" aria-label="Close dialog" onClick={onCancel}>×</button>
      </header>
      <p>{copy.body}</p>
      <dl className="bg-facts">
        <div><dt>Target</dt><dd>{targetLabel}</dd></div>
        <div><dt>Expected result</dt><dd>{pending.impact || copy.body}</dd></div>
        {copy.consideration && <div><dt>Consideration</dt><dd>{copy.consideration}</dd></div>}
      </dl>
      <p className="bg-small">
        This is a simulation, but your decision is scored. The result is only shown once the server confirms it.
      </p>
      <div className="bg-modal-actions">
        <button type="button" className="bg-btn" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="button" className="bg-btn bg-primary" onClick={onConfirm} disabled={busy}>
          {busy ? 'Working…' : `Confirm ${copy.verb}`}
        </button>
      </div>
    </Modal>
  )
}
