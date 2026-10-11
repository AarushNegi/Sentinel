// components/EmailPreviewWebmail.jsx
// Renders the student's draft inside a generic, familiar webmail-reader
// layout (inbox-style chrome) so it reads the way the target would actually
// see it. Deliberately generic — no real mail provider's logo or branding.
import { Reply, Forward, Star, MoreVertical } from 'lucide-react'
import './EmailPreviewWebmail.css'

function domainOf(sender) {
  const at = sender.indexOf('@')
  return at >= 0 ? sender.slice(at + 1) : ''
}

export default function EmailPreviewWebmail({ target, sender, subject, body, cta }) {
  const senderName = sender.split('@')[0] || 'unknown-sender'
  const domain = domainOf(sender)

  return (
    <div className="wm-wrap">
      <div className="wm-disclaimer">SENTINEL TRAINING ENVIRONMENT — SIMULATED WEBMAIL, NOT A REAL INBOX</div>
      <div className="wm-card">
        <div className="wm-toolbar">
          <Reply size={15} /><Forward size={15} /><MoreVertical size={15} />
          <Star size={15} className="wm-toolbar-right" />
        </div>

        <h2 className="wm-subject">{subject || '(no subject)'}</h2>

        <div className="wm-sender-row">
          <div className="wm-avatar">{senderName.charAt(0).toUpperCase()}</div>
          <div className="wm-sender-info">
            <div><strong>{senderName}</strong> <span className="wm-sender-email">&lt;{sender || 'unknown@unknown'}&gt;</span></div>
            <span className="wm-to">to {target.name.toLowerCase().replace(' ', '.')}</span>
          </div>
          <span className="wm-time">9:41 AM</span>
        </div>

        {domain && <div className="wm-domain-chip">via {domain}</div>}

        <div className="wm-body">
          {(body || '').split('\n').map((line, i) => <p key={i}>{line || ' '}</p>)}
          {cta && <a className="wm-cta" href="#" onClick={(e) => e.preventDefault()}>{cta}</a>}
        </div>
      </div>
    </div>
  )
}
