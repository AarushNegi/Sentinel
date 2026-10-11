// components/EmailComposerStage.jsx
// Stage 3 — the student writes the actual phishing email. No predefined
// choices: free-text sender, subject, body and call-to-action, with a live
// (local, deterministic) Campaign Analysis readout as they type.
import { useMemo, useState } from 'react'
import { Eye, ArrowRight, Sparkles } from 'lucide-react'
import CampaignAnalysis from './CampaignAnalysis'
import LearningPopup from './LearningPopup'
import EmailPreviewWebmail from './EmailPreviewWebmail'
import { analyzeCampaign, buildSenderExample, buildSuggestedDraft } from '../data/phishingSimulation'
import './EmailComposerStage.css'

export default function EmailComposerStage({ target, platform, selectedIntel, draft, onChange, onContinue, attempt = 1 }) {
  const [showPreview, setShowPreview] = useState(false)
  const [assistantDismissed, setAssistantDismissed] = useState(false)
  const [suggestionDismissed, setSuggestionDismissed] = useState(false)

  const isBlank = !draft.sender.trim() && !draft.subject.trim() && !draft.body.trim() && !draft.cta.trim()
  const showSuggestion = attempt > 1 && isBlank && !suggestionDismissed

  const useSuggestedDraft = () => {
    onChange(buildSuggestedDraft(target, platform))
  }

  const analysis = useMemo(
    () => analyzeCampaign({ ...draft, selectedIntel, target }),
    [draft, selectedIntel, target]
  )

  const hasContent = draft.body.trim().length > 30
  const needsAssistant = hasContent && (analysis.credibility < 45 || analysis.suspicion > 70)

  const missing = []
  if (!draft.sender.trim()) missing.push('Sender (From)')
  if (!draft.subject.trim()) missing.push('Subject')
  if (!draft.body.trim()) missing.push('Email Body')
  if (!draft.cta.trim()) missing.push('Call to Action')
  const canContinue = missing.length === 0

  const set = (field) => (e) => onChange({ ...draft, [field]: e.target.value })

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // EMAIL COMPOSER</div>
      <h1>Write the phishing email.</h1>
      <p>Construct the message yourself — nothing here is pre-written for you.</p>

      {showSuggestion && (
        <div className="ec-suggestion-banner">
          <Sparkles size={15} />
          <span>Attempt #{attempt}. Want a worked example to learn from? You can still edit it before sending.</span>
          <button type="button" onClick={useSuggestedDraft}>Use Suggested Draft</button>
          <button type="button" className="ec-suggestion-dismiss" onClick={() => setSuggestionDismissed(true)}>Write it myself</button>
        </div>
      )}

      <div className="ec-composer">
        <div className="ec-field">
          <span>FROM</span>
          <input
            placeholder={`e.g. ${buildSenderExample(target, platform)}`}
            value={draft.sender}
            onChange={set('sender')}
          />
        </div>
        <div className="ec-field">
          <span>TO</span>
          <strong>{target.name} &lt;{target.email}&gt;</strong>
        </div>
        <div className="ec-field">
          <span>SUBJECT</span>
          <input
            placeholder="Write a subject line..."
            value={draft.subject}
            onChange={set('subject')}
          />
        </div>
        <div className="ec-body-field">
          <span>EMAIL BODY</span>
          <textarea
            rows={6}
            placeholder="Write the message body..."
            value={draft.body}
            onChange={set('body')}
          />
        </div>
        <div className="ec-field">
          <span>CALL TO ACTION</span>
          <input
            placeholder="e.g. Verify Account Now"
            value={draft.cta}
            onChange={set('cta')}
          />
        </div>
      </div>

      <CampaignAnalysis analysis={analysis} />

      {needsAssistant && !assistantDismissed && (
        <LearningPopup type="hint" title="Campaign Assistant" onDismiss={() => setAssistantDismissed(true)}>
          Your message is reading as generic or hard to trust. Consider the target's role and
          organization when building context — you selected intelligence earlier for a reason.
        </LearningPopup>
      )}

      <div className="ec-actions">
        <button type="button" className="rp-secondary-btn" onClick={() => setShowPreview((v) => !v)}>
          <Eye size={14} /> {showPreview ? 'Hide Preview' : 'Preview Email'}
        </button>
        <button className="rp-primary-btn" onClick={onContinue} disabled={!canContinue}>
          Continue to Link Builder <ArrowRight size={15} />
        </button>
      </div>
      {!canContinue && (
        <div className="ec-missing-hint">Fill in to continue: {missing.join(', ')}</div>
      )}

      {showPreview && (
        <EmailPreviewWebmail target={target} sender={draft.sender} subject={draft.subject} body={draft.body} cta={draft.cta} />
      )}
    </div>
  )
}
