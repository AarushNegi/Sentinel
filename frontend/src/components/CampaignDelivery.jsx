// components/CampaignDelivery.jsx
// Stage 5 — Campaign Delivery. Deploying doesn't guarantee success: the
// target's reaction is driven deterministically by the student's own
// campaign quality (see data/phishingSimulation.js), never by chance.
import { useEffect, useRef, useState } from 'react'
import LearningPopup from './LearningPopup'
import { determineDeliveryOutcome, getFailureReasons, LEARNING_MOMENTS } from '../data/phishingSimulation'
import './CampaignDelivery.css'

function stamp() {
  return new Date().toLocaleTimeString([], { hour12: false })
}

export default function CampaignDelivery({ draft, analysis, onLog, onSuccess, onTryAgain, onContinueToAnalysis }) {
  const [phase, setPhase] = useState('ready') // ready | sending | resolved
  const [timeline, setTimeline] = useState([])
  const [resolution, setResolution] = useState(null)
  const timers = useRef([])

  useEffect(() => () => timers.current.forEach(clearTimeout), [])

  const push = (message) => setTimeline((prev) => [...prev, `[${stamp()}] ${message}`])

  const deploy = () => {
    setPhase('sending')
    push('Campaign created')
    onLog('Campaign initialized')

    timers.current.push(setTimeout(() => { push('Email queued'); onLog('Message queued') }, 500))
    timers.current.push(setTimeout(() => {
      push('Email delivered')
      onLog('Message delivered to target mailbox')
    }, 1300))

    timers.current.push(setTimeout(() => {
      const { outcome, quality } = determineDeliveryOutcome(analysis)

      if (outcome === 'ignored') {
        push('Target did not open the message')
        onLog('Target ignored the message')
        setResolution({ outcome, quality, reasons: getFailureReasons(analysis) })
        setPhase('resolved')
        return
      }

      push('Target opened message')
      onLog('Target opened phishing email')

      timers.current.push(setTimeout(() => {
        if (outcome === 'partial') {
          push('Target did not click the link')
          onLog('Target did not interact further')
          setResolution({ outcome, quality, reasons: getFailureReasons(analysis) })
          setPhase('resolved')
        } else {
          push('Target clicked simulated link')
          onLog('Target clicked simulated phishing link')
          setResolution({ outcome, quality, reasons: [] })
          setPhase('resolved')
        }
      }, 1100))
    }, 2200))
  }

  const resolved = phase === 'resolved' && resolution

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // DELIVERY</div>
      <h1>Deploy the campaign.</h1>

      {phase === 'ready' && (
        <>
          <p>The campaign is ready. Deploy it into the simulated target environment.</p>
          <div className="cd-summary">
            <div><span>SUBJECT</span><strong>{draft.subject}</strong></div>
            <div><span>SENDER</span><strong>{draft.sender}</strong></div>
            <div><span>STATUS</span><strong className="cd-yellow">READY</strong></div>
          </div>
          <button className="rp-primary-btn" onClick={deploy}>Deploy Campaign →</button>
        </>
      )}

      {phase !== 'ready' && (
        <div className="cd-timeline">
          {timeline.map((line, i) => <div key={i} className="cd-timeline-line">{line}</div>)}
        </div>
      )}

      {resolved && resolution.outcome === 'clicked' && (
        <div className="cd-outcome cd-success">
          <strong>TARGET CLICKED LINK</strong>
          <p>The target followed the simulated link. Continue to observe their interaction.</p>
          <button className="rp-primary-btn" onClick={onSuccess}>Continue to Target Browser →</button>
        </div>
      )}

      {resolved && resolution.outcome !== 'clicked' && (
        <div className="cd-outcome cd-fail">
          <strong>{resolution.outcome === 'ignored' ? 'TARGET IGNORED EMAIL' : 'TARGET OPENED EMAIL — DID NOT CLICK'}</strong>
          <div className="cd-reasons">
            <span className="cd-reasons-label">WHY?</span>
            <ul>{resolution.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
          </div>
          <LearningPopup type="learning">
            {LEARNING_MOMENTS[resolution.outcome]}
          </LearningPopup>
          <div className="cd-fail-actions">
            <button className="rp-secondary-btn" onClick={onTryAgain}>Try Again</button>
            <button className="rp-primary-btn" onClick={() => onContinueToAnalysis(resolution)}>Continue to Analysis →</button>
          </div>
        </div>
      )}
    </div>
  )
}
