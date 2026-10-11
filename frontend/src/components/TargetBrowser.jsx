// components/TargetBrowser.jsx
// Stage 6 — a simulated browser INSIDE Sentinel showing the chosen fictional
// platform (social media or banking). The target's actions here are
// scripted/animated — this is never a real authentication flow and never
// contacts a real domain. The social variant uses a two-column "marketing +
// login" layout — a common pattern across real social platforms — built
// entirely from FaceWorld's own fictional mark/copy/icons, not any real
// company's logo, wordmark, or imagery.
import { useEffect, useRef, useState } from 'react'
import { Landmark, X, Image, Users, Heart, MessageCircle, Search, Bell } from 'lucide-react'
import LearningPopup from './LearningPopup'
import './TargetBrowser.css'

export default function TargetBrowser({ target, platform, onSubmitted, onContinue, onLog, linkUrl }) {
  const [phase, setPhase] = useState('loading') // loading | loaded | typing-email | typing-password | submitting | authenticating | error | closed
  const [emailTyped, setEmailTyped] = useState('')
  const [passwordLen, setPasswordLen] = useState(0)
  const firedSubmit = useRef(false)
  const firedClosed = useRef(false)
  const isBanking = platform.key === 'banking'

  useEffect(() => {
    const timers = []
    const at = (ms, fn) => timers.push(setTimeout(fn, ms))

    at(900, () => setPhase('loaded'))
    at(1500, () => setPhase('typing-email'))

    const email = target.trainingAccount
    for (let i = 1; i <= email.length; i++) {
      at(1500 + i * 35, () => setEmailTyped(email.slice(0, i)))
    }
    const emailDoneAt = 1500 + email.length * 35

    at(emailDoneAt + 300, () => setPhase('typing-password'))
    const pwLen = target.trainingPassword.length
    for (let i = 1; i <= pwLen; i++) {
      at(emailDoneAt + 300 + i * 40, () => setPasswordLen(i))
    }
    const pwDoneAt = emailDoneAt + 300 + pwLen * 40

    at(pwDoneAt + 400, () => {
      setPhase('submitting')
      if (!firedSubmit.current) {
        firedSubmit.current = true
        onSubmitted()
      }
    })
    at(pwDoneAt + 1000, () => setPhase('authenticating'))
    at(pwDoneAt + 1900, () => setPhase('error'))
    at(pwDoneAt + 3600, () => {
      setPhase('closed')
      if (!firedClosed.current) {
        firedClosed.current = true
        onLog('Target dismissed the error as a site glitch and closed the tab — no suspicion raised')
      }
    })

    return () => timers.forEach(clearTimeout)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loginForm = (
    <>
      <h3>{platform.loginTitle}</h3>

      <div className="tb-field">
        <span>{isBanking ? 'Username' : 'Email address or mobile number'}</span>
        <div className="tb-input">{emailTyped}<span className="tb-caret">|</span></div>
      </div>
      <div className="tb-field">
        <span>Password</span>
        <div className="tb-input">{'•'.repeat(passwordLen)}{passwordLen > 0 && phase === 'typing-password' && <span className="tb-caret">|</span>}</div>
      </div>

      <button type="button" className="tb-login-btn" disabled>
        {phase === 'submitting' ? 'Signing in…' : phase === 'authenticating' ? 'Authenticating…' : (isBanking ? 'Log In to Online Banking' : 'Log In')}
      </button>

      {(phase === 'error' || phase === 'closed') && (
        <div className="tb-error">
          Unable to complete sign-in.<br />
          Something went wrong. Please try again later.
        </div>
      )}

      {isBanking ? (
        <div className="tb-trust-badge">🔒 256-bit encrypted connection</div>
      ) : (
        <div className="tb-links"><span>Forgotten password?</span><span>Create new account</span></div>
      )}
    </>
  )

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // TARGET BROWSER</div>
      <h1>Observe the target's session.</h1>
      <p>This is a fictional Sentinel training environment — not a real platform or authentication flow.</p>

      <div className={`tb-browser ${isBanking ? 'banking' : 'social'} ${phase === 'closed' ? 'tb-dimmed' : ''}`}>
        <div className="tb-bar">
          <span>←</span><span>→</span><span>⟳</span>
          <div className="tb-url">🔒 {linkUrl}</div>
        </div>

        <div className="tb-banner-strip">
          SENTINEL TRAINING ENVIRONMENT — SIMULATED {isBanking ? 'BANKING PLATFORM' : 'SOCIAL PLATFORM'}, NOT A REAL SITE
        </div>

        {phase === 'loading' ? (
          <div className="tb-loading">Loading…</div>
        ) : isBanking ? (
          <div className="tb-page">
            <div className="tb-logo tb-logo-bank"><Landmark size={20} />{platform.platform}</div>
            {loginForm}
          </div>
        ) : (
          <>
            <div className="tb-social-nav">
              <span className="tb-social-nav-logo">{platform.platform}</span>
              <div className="tb-social-nav-search"><Search size={12} /><span>Search {platform.platform}</span></div>
              <div className="tb-social-nav-icons"><Bell size={15} /><span className="tb-social-nav-avatar">{target.name.charAt(0)}</span></div>
            </div>
            <div className="tb-social-layout">
              <div className="tb-marketing">
                <div className="tb-logo">{platform.platform}</div>
                <div className="tb-collage">
                  <div className="tb-tile tb-tile-a"><Users size={26} /></div>
                  <div className="tb-tile tb-tile-b"><Image size={22} /></div>
                  <div className="tb-tile tb-tile-c"><Heart size={18} /></div>
                  <div className="tb-tile tb-tile-d"><MessageCircle size={20} /></div>
                </div>
                <p className="tb-marketing-copy">Connect with friends and the world around you on {platform.platform}.</p>
              </div>
              <div className="tb-login-panel">
                {loginForm}
              </div>
            </div>
          </>
        )}

        {phase === 'closed' && (
          <div className="tb-closed-overlay">
            <X size={22} />
            <strong>Target closed the tab</strong>
          </div>
        )}
      </div>

      {phase === 'closed' && (
        <>
          <LearningPopup type="learning">
            The target saw a generic, believable error — not an obvious attack — and assumed it was a
            temporary site glitch. They closed the tab without reporting anything. This is exactly why a
            plausible failure message is more dangerous than a flashy one: it ends the interaction without
            raising suspicion, even after credentials were already captured.
          </LearningPopup>
          <button className="rp-primary-btn" onClick={onContinue}>Continue →</button>
        </>
      )}
    </div>
  )
}
