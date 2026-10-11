// pages/RedPhishingSimulation.jsx
// Red Team — "FaceWorld Account Security Verification" phishing simulation.
// Orchestrates the interactive stages; all scenario content and scoring
// logic lives in data/phishingSimulation.js (deterministic, no AI dependency).
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import TargetIntelStage from '../components/TargetIntelStage'
import TargetProfileStage from '../components/TargetProfileStage'
import EmailComposerStage from '../components/EmailComposerStage'
import SimulatedLinkBuilder from '../components/SimulatedLinkBuilder'
import CampaignDelivery from '../components/CampaignDelivery'
import TargetBrowser from '../components/TargetBrowser'
import CredentialSimulation from '../components/CredentialSimulation'
import AttackTimeline from '../components/AttackTimeline'
import { completeRedPhishing } from '../services/api'
import {
  analyzeCampaign, campaignQuality, buildIndicators, buildIntelItems,
} from '../data/phishingSimulation'
import './RedPhishingSimulation.css'

const STAGES = [
  { id: 'recon', label: 'RECON' },
  { id: 'target', label: 'TARGET' },
  { id: 'craft', label: 'CRAFT' },
  { id: 'delivery', label: 'DELIVERY' },
  { id: 'access', label: 'ACCESS' },
  { id: 'capture', label: 'CAPTURE' },
  { id: 'compromised', label: 'COMPROMISED' },
]

const MAX_SCORE = 1025

export default function RedPhishingSimulation() {
  const navigate = useNavigate()

  // Stage/phase live in the URL (not plain useState) so the browser's own
  // Back/Forward buttons step through the simulation's stages instead of
  // leaving the page and losing all progress. Every other piece of state
  // below (target, draft, score, events, ...) is untouched by this —
  // going back a stage just re-shows an earlier screen with everything the
  // student already entered still intact.
  const [searchParams, setSearchParams] = useSearchParams()
  const rawStage = searchParams.get('stage') || 'recon'
  const rawPhase = searchParams.get('phase') || 'compose'
  const goTo = (newStage, newPhase) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('stage', newStage)
      if (newPhase) next.set('phase', newPhase)
      else next.delete('phase')
      return next
    }, { replace: false })
  }

  // Guards against re-awarding score/log lines if a stage is replayed via
  // Back/Forward (the stage component remounts, and auto-firing effects —
  // or a re-clicked "Continue" button — would otherwise double-count).
  const milestonesRef = useRef(new Set())
  const awardOnce = (key, points, logMsg) => {
    if (milestonesRef.current.has(key)) return false
    milestonesRef.current.add(key)
    if (points) setScore((v) => v + points)
    if (logMsg) addEvent(logMsg)
    return true
  }

  const [platform, setPlatform] = useState(null)
  const [target, setTarget] = useState(null)
  const intelItems = useMemo(() => (target && platform ? buildIntelItems(target, platform) : []), [target, platform])

  // The URL can outlive the in-memory state (page reload, a bookmarked or
  // stale link, a hot reload). Any stage after recon needs the chosen target
  // and platform, so an unknown stage or one whose state is missing falls back
  // to the first stage instead of rendering against null data (blank page).
  const stageKnown = STAGES.some((s) => s.id === rawStage)
  const stage = stageKnown && (rawStage === 'recon' || (target && platform)) ? rawStage : 'recon'
  const craftPhase = rawPhase === 'link' ? 'link' : 'compose'
  useEffect(() => {
    if (stage === rawStage) return
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('stage', 'recon')
      next.delete('phase')
      return next
    }, { replace: true })
  }, [stage, rawStage, setSearchParams])

  const [inspected, setInspected] = useState(new Set())
  const [selectedIntelIds, setSelectedIntelIds] = useState([])
  const [selectedIntel, setSelectedIntel] = useState([])

  const [draft, setDraft] = useState({ sender: '', subject: '', body: '', cta: '' })
  const [linkPath, setLinkPath] = useState('')
  const [attempt, setAttempt] = useState(1)

  const handlePlatformChosen = (p) => {
    setPlatform(p)
    setLinkPath(p.defaultPath)
  }

  const [events, setEvents] = useState(['Operation initialized', 'Reconnaissance environment ready'])
  const [score, setScore] = useState(0)
  const [seconds, setSeconds] = useState(0)

  const [credentialSubmitted, setCredentialSubmitted] = useState(false)
  const [environmentEnumerated, setEnvironmentEnumerated] = useState(false)

  const [completed, setCompleted] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)

  useEffect(() => {
    if (completed) return
    const timer = setInterval(() => setSeconds((v) => v + 1), 1000)
    return () => clearInterval(timer)
  }, [completed])

  const time = useMemo(() => {
    const m = String(Math.floor(seconds / 60)).padStart(2, '0')
    const s = String(seconds % 60).padStart(2, '0')
    return `${m}:${s}`
  }, [seconds])

  const addEvent = (message) => {
    const ts = new Date().toLocaleTimeString([], { hour12: false })
    setEvents((prev) => [...prev, `${ts}  ${message}`])
  }

  const linkUrl = platform ? `${platform.trainingDomain}/${linkPath.replace(/^\/+/, '')}` : ''
  const analysis = useMemo(
    () => analyzeCampaign({ ...draft, selectedIntel, target }),
    [draft, selectedIntel, target]
  )

  // ── Stage 1 — Reconnaissance ──────────────────────────────
  const handleInspect = (id, log) => {
    setInspected((prev) => new Set(prev).add(id))
    addEvent(`[INFO] ${log}`)
    setScore((v) => v + 10)
  }
  const handleReconContinue = () => {
    awardOnce('recon-complete', 50, 'Reconnaissance complete')
    goTo('target')
  }

  // ── Stage 2 — Target Profiling ─────────────────────────────
  const toggleIntel = (id) => {
    setSelectedIntelIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]))
  }
  const handleProfileContinue = (selectedItems) => {
    setSelectedIntel(selectedItems)
    const highCount = selectedItems.filter((i) => i.value === 'high').length
    const lowCount = selectedItems.filter((i) => i.value === 'low').length
    const bonus = Math.max(0, Math.min(60, highCount * 20) - lowCount * 10)
    awardOnce('target-profiled', 40 + bonus, `Campaign context built from ${selectedItems.length} intelligence item(s)`)
    goTo('craft', 'compose')
  }

  // ── Stage 3/4 — Email Composer + Link Builder ──────────────
  const handleComposerContinue = () => {
    awardOnce('email-drafted', 0, 'Phishing email drafted')
    goTo('craft', 'link')
  }
  const handleLinkContinue = () => {
    const quality = campaignQuality(analysis)
    const craftPoints = Math.min(160, Math.round(quality * 1.6)) + 40
    awardOnce('link-built', craftPoints, `Simulated link generated: ${linkUrl}`)
    goTo('delivery')
  }

  // ── Stage 5 — Delivery (branching) ─────────────────────────
  const handleDeliverySuccess = () => {
    awardOnce('delivery-success', 100, null)
    goTo('access')
  }
  const handleTryAgain = () => {
    addEvent('Revising campaign after failed delivery')
    setAttempt((v) => v + 1)
    setDraft({ sender: '', subject: '', body: '', cta: '' })
    goTo('craft', 'compose')
  }
  const saveAndExit = async (resultInfo) => {
    const result = await saveSimulation(resultInfo)
    if (result.success) {
      navigate('/outcome', {
        state: {
          reportId: result.reportId,
          report: buildOutcomeReport(resultInfo, result.reportId),
        },
      })
    } else {
      setCompleted(true)
    }
  }
  const handleContinueToAnalysis = (resolution) => {
    addEvent(`Operation concluded: ${resolution.outcome}`)
    saveAndExit({
      outcomeType: resolution.outcome,
      reasons: resolution.reasons,
      quality: resolution.quality,
      failedAtStage: 'delivery',
    })
  }

  // ── Stage 6 — Target Browser ────────────────────────────────
  const handleCredentialSubmitted = () => {
    setCredentialSubmitted(true)
    const first = awardOnce('credential-submitted', 150, `Target submitted training credentials on simulated ${platform.platform} login`)
    if (first) addEvent('Simulated credential submission captured — no real password stored')
  }
  const handleBrowserContinue = () => goTo('capture')

  // ── Stage 7/8 — Credential capture confirmation ────────────
  const handleAuthenticate = () => {
    awardOnce('authenticated', 200, `Simulated access established as ${target.name}`)
    goTo('compromised')
  }

  // ── Stage 9/10 — Final / compromised ───────────────────────
  useEffect(() => {
    if (stage === 'compromised') {
      awardOnce('compromised-entered', 75, 'Compromised account environment enumerated — pending')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stage])

  const handleEnumerate = () => {
    setEnvironmentEnumerated(true)
    awardOnce('enumerated', 100, 'Marketing and partner-communication resources discovered')
  }

  const milestones = [
    { label: 'Email Created' },
    { label: 'Email Delivered' },
    { label: 'Target Opened' },
    { label: 'Link Clicked' },
    { label: 'Login Page Displayed' },
    { label: 'Credential Submitted' },
    { label: 'Simulated Access' },
  ]

  const indicators = useMemo(
    () => buildIndicators({
      sender: draft.sender,
      subject: draft.subject,
      simulatedLink: linkUrl,
      targetAccount: target?.trainingAccount,
      timestamp: new Date().toISOString(),
      credentialSubmitted,
    }),
    [draft.sender, draft.subject, linkUrl, credentialSubmitted, target]
  )

  function buildOutcomeReport(resultInfo, reportId) {
    return {
      mode: 'red',
      attack: 'phishing',
      guideTitle: `Red Team — ${platform.platform} Phishing`,
      target: { name: target.name, role: target.role, department: target.organization, email: target.email },
      credential_capture: credentialSubmitted
        ? { username: target.trainingAccount, credential_submission: true, credential_type: 'simulated', source: platform.trainingDomain }
        : null,
      campaign_analysis: analysis,
      learning_outcomes: [
        'Reconnaissance', 'Social engineering', 'Phishing construction',
        'Malicious-link concepts', 'Credential phishing', 'Detection opportunities',
      ],
      defender_indicators: indicators,
      score,
      max_score: MAX_SCORE,
      duration_seconds: seconds,
      stages_completed: STAGES.slice(0, STAGES.findIndex((s) => s.id === stage) + 1).map((s) => s.id),
      total_stages: STAGES.length,
      failed_at_stage: resultInfo?.failedAtStage || null,
      result: resultInfo ? (resultInfo.outcomeType === 'ignored' ? 'failed' : 'partial') : 'success',
      choices: [
        { type: 'sender', value: draft.sender },
        { type: 'subject', value: draft.subject },
        { type: 'cta', value: draft.cta },
        { type: 'simulatedLink', value: linkUrl },
      ],
      log_lines: events,
      logLines: events,
      report_id: reportId,
    }
  }

  async function saveSimulation(resultInfo) {
    setSaving(true)
    setSaveStatus(null)
    try {
      const res = await completeRedPhishing({
        target: { id: target.name.toLowerCase().replace(/\s+/g, '-'), name: target.name, role: target.role, department: target.organization, email: target.email },
        credentialSubmitted,
        targetAccount: target.trainingAccount,
        campaign: { sender: draft.sender, subject: draft.subject, cta: draft.cta, simulatedLink: linkUrl },
        campaignAnalysis: analysis,
        indicators,
        score,
        maxScore: MAX_SCORE,
        durationSeconds: seconds,
        stagesCompleted: STAGES.slice(0, STAGES.findIndex((s) => s.id === stage) + 1).map((s) => s.id),
        totalStages: STAGES.length,
        result: resultInfo ? (resultInfo.outcomeType === 'ignored' ? 'failed' : 'partial') : 'success',
        failedAtStage: resultInfo?.failedAtStage || null,
        choices: [
          { type: 'sender', value: draft.sender },
          { type: 'subject', value: draft.subject },
          { type: 'cta', value: draft.cta },
          { type: 'simulatedLink', value: linkUrl },
        ],
        logLines: events,
      })
      setSaveStatus('success')
      return { success: true, reportId: res.data.report_id }
    } catch (err) {
      console.error('Simulation save error:', err)
      setSaveStatus('error')
      return { success: false, reportId: null }
    } finally {
      setSaving(false)
    }
  }

  const finishMission = async () => {
    addEvent('Phishing operation completed successfully')
    const result = await saveSimulation(null)
    if (result.success) {
      addEvent('Simulation report saved to Sentinel database')
      setCompleted(true)
      navigate('/outcome', { state: { reportId: result.reportId, report: buildOutcomeReport(null, result.reportId) } })
    } else {
      addEvent('Warning: simulation report could not be saved')
      setCompleted(true)
    }
  }

  const resetSimulation = () => window.location.reload()

  const currentIndex = STAGES.findIndex((s) => s.id === stage)

  return (
    <div className="red-phishing-page">
      <NetworkBackground variant="red" />

      <header className="rp-header">
        <div>
          <div className="rp-brand"><span className="rp-brand-dot" />SENTINEL // RED TEAM</div>
          <div className="rp-subtitle">{platform ? platform.title.toUpperCase() : 'CHOOSE YOUR ATTACK'}</div>
        </div>
        <div className="rp-header-status">
          <div><span>OPERATION TIME</span><strong>{time}</strong></div>
          <div><span>THREAT</span><strong className="rp-threat">{completed ? 'COMPLETE' : 'ACTIVE'}</strong></div>
          <div><span>SCORE</span><strong>{score}</strong></div>
        </div>
      </header>

      <main className="rp-main">
        <section className="rp-killchain">
          {STAGES.map((item, index) => {
            let state = 'pending'
            if (index < currentIndex) state = 'complete'
            if (item.id === stage) state = 'active'
            if (completed) state = 'complete'
            return (
              <div key={item.id} className={`rp-chain-item ${state}`}>
                <div className="rp-chain-dot">{state === 'complete' ? '✓' : index + 1}</div>
                <span>{item.label}</span>
                {index < STAGES.length - 1 && <div className="rp-chain-line" />}
              </div>
            )
          })}
        </section>

        <section className="rp-grid">
          <div className="rp-left">
            <div className="rp-panel">
              <div className="rp-panel-label">TARGET INTELLIGENCE</div>
              {target ? (
                <div className="rp-target-selected">
                  <div>
                    <span className="rp-small">TARGET</span>
                    <h2>{target.name}</h2>
                    <p>{target.role} · {target.organization}</p>
                  </div>
                </div>
              ) : (
                <p className="rp-muted">No target identified yet — specify one to begin.</p>
              )}
              {selectedIntel.length > 0 && (
                <div className="rp-intel-list">
                  {selectedIntel.map((i) => <div key={i.id}><span>›</span>{i.label}</div>)}
                </div>
              )}
            </div>

            <div className="rp-panel rp-log-panel">
              <div className="rp-panel-label">LIVE ATTACK TELEMETRY</div>
              <div className="rp-log">
                {events.map((event, i) => (
                  <div key={`${event}-${i}`} className="rp-log-line"><span className="rp-log-cursor">›</span>{event}</div>
                ))}
              </div>
            </div>

            {stage === 'access' && <CredentialSimulation visible={credentialSubmitted} target={target} />}
          </div>

          <div className="rp-right">
            {stage === 'recon' && (
              <TargetIntelStage
                inspected={inspected}
                onInspect={handleInspect}
                onContinue={handleReconContinue}
                onTargetFound={setTarget}
                onPlatformChosen={handlePlatformChosen}
              />
            )}

            {stage === 'target' && (
              <TargetProfileStage
                intelItems={intelItems}
                selectedIds={selectedIntelIds}
                onToggle={toggleIntel}
                onContinue={handleProfileContinue}
              />
            )}

            {stage === 'craft' && craftPhase === 'compose' && (
              <EmailComposerStage
                target={target}
                platform={platform}
                selectedIntel={selectedIntel}
                draft={draft}
                onChange={setDraft}
                onContinue={handleComposerContinue}
                attempt={attempt}
              />
            )}

            {stage === 'craft' && craftPhase === 'link' && (
              <SimulatedLinkBuilder platform={platform} path={linkPath} onPathChange={setLinkPath} onContinue={handleLinkContinue} />
            )}

            {stage === 'delivery' && (
              <CampaignDelivery
                draft={draft}
                analysis={analysis}
                onLog={addEvent}
                onSuccess={handleDeliverySuccess}
                onTryAgain={handleTryAgain}
                onContinueToAnalysis={handleContinueToAnalysis}
              />
            )}

            {stage === 'access' && (
              <TargetBrowser target={target} platform={platform} linkUrl={linkUrl} onSubmitted={handleCredentialSubmitted} onContinue={handleBrowserContinue} onLog={addEvent} />
            )}

            {stage === 'capture' && (
              <div className="rp-action-panel">
                <div className="rp-stage-tag">RED TEAM // CREDENTIAL CAPTURE</div>
                <h1>Credentials captured.</h1>
                <p>The simulated target submitted the {platform.platform} login form. No real credential was ever collected — only the fixed training account is tracked for this report.</p>
                <CredentialSimulation visible target={target} />
                <button className="rp-primary-btn" onClick={handleAuthenticate}>Authenticate as Target →</button>
              </div>
            )}

            {stage === 'compromised' && !completed && (
              <div className="rp-action-panel">
                <div className="rp-stage-tag">RED TEAM // COMPROMISED ACCOUNT</div>
                <h1>Simulated access established.</h1>
                <p>The fictional target account is now under attacker control within the simulation.</p>

                <div className="rp-compromised-banner">
                  <div className="rp-access-icon">✓</div>
                  <div><strong>AUTHENTICATED SESSION ACTIVE</strong><span>{target.name} · {target.organization}</span></div>
                </div>

                {!environmentEnumerated ? (
                  <button className="rp-primary-btn" onClick={handleEnumerate}>Enumerate Environment →</button>
                ) : (
                  <>
                    <AttackTimeline milestones={milestones} indicators={indicators} />
                    <button className="rp-primary-btn" onClick={finishMission} disabled={saving}>
                      {saving ? 'Saving Operation...' : 'Complete Operation →'}
                    </button>
                    {saveStatus === 'error' && (
                      <div className="rp-safety-note">The operation completed locally, but the report could not be saved to the Sentinel database.</div>
                    )}
                  </>
                )}
              </div>
            )}

            {completed && (
              <div className="rp-action-panel rp-complete">
                <div className="rp-stage-tag">RED TEAM // OPERATION COMPLETE</div>
                <div className="rp-access-icon">✓</div>
                <h1>Phishing operation successful.</h1>
                <p>The simulated campaign progressed from reconnaissance to credential capture and simulated access.</p>
                <div className="rp-final-score"><span>MISSION SCORE</span><strong>{score}</strong></div>
                {saveStatus === 'success' && (
                  <div className="rp-success-box">
                    <span className="rp-success-icon">✓</span>
                    <div><strong>REPORT SAVED</strong><p>Simulation results successfully stored in the Sentinel database.</p></div>
                  </div>
                )}
                <button className="rp-primary-btn" onClick={resetSimulation}>Run Simulation Again →</button>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}
