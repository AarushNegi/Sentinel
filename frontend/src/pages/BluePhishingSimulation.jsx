import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import BlueEvidenceCard from '../components/BlueEvidenceCard'
import ConfirmDialog from '../components/blue/ConfirmDialog'
import ActivityScreen from '../components/blue/mission/ActivityScreen'
import Debrief from '../components/blue/mission/Debrief'
import {
  AffectedScreen, CauseScreen, CloseScreen, DecideScreen, RespondScreen, VerifyScreen,
} from '../components/blue/mission/DecisionScreens'
import IncidentHeader from '../components/blue/mission/IncidentHeader'
import {
  AlertsScreen, AttachmentScreen, EmailScreen, IndicatorScreen, LinkScreen, SecurityScreen,
} from '../components/blue/mission/InvestigateScreens'
import Screen from '../components/blue/mission/Screen'
import Tray from '../components/blue/mission/Tray'
import { play } from '../components/blue/mission/sound'
import { buildSteps, isReady, resumeIndex } from '../components/blue/mission/steps'
import { FALLBACK_REASONS, callApi, prettify } from '../components/blue/blueApi'
import { GuideContext } from '../components/blue/guide/guideContext'
import { GlossaryDialog, Modal, ResultCard, TermDialog } from '../components/blue/guide/HelpUI'
import { NETWORK_ERROR, explainError, explainResult } from '../components/blue/guide/guidance'
import { loadNotes, saveNotes, useGuidePrefs } from '../components/blue/guide/prefs'
import './BlueGuided.css'
import './BlueMission.css'

const CLOSE_IMPACT = 'Closes the incident permanently and submits your classification, root cause, affected scope and supporting evidence for scoring. You cannot reopen it.'
const EMPTY_FORM = {
  classification: '', severity: '', root_cause: '', residual_risk: '', evidence_preserved: null,
  summary: '', users: [], assets: [],
}

export default function BluePhishingSimulation() {
  const navigate = useNavigate()
  const abortRef = useRef(null)
  const { prefs, markSeen } = useGuidePrefs()

  const [view, setView] = useState(null)
  const [seconds, setSeconds] = useState(0)
  const [loading, setLoading] = useState(true)
  const [canSkipAi, setCanSkipAi] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [stepId, setStepId] = useState(null)
  const [saved, setSaved] = useState({ verdicts: {}, pinned: [], stepId: null, form: null })
  const [verification, setVerification] = useState({})
  const [overlay, setOverlay] = useState(null)
  const [sound, setSound] = useState(false)
  const [newEvidence, setNewEvidence] = useState([])
  const [report, setReport] = useState(null)
  const [reportState, setReportState] = useState({ loading: false, error: '' })

  const completed = view?.status === 'completed'

  const updateSaved = useCallback((patch) => {
    setSaved((current) => {
      const next = { ...current, ...(typeof patch === 'function' ? patch(current) : patch) }
      saveNotes(view?.session_id, next)
      return next
    })
  }, [view?.session_id])

  const form = saved.form || { ...EMPTY_FORM, classification: view?.assessment?.classification || '', severity: view?.assessment?.severity || '' }
  const setForm = (next) => updateSaved({ form: next })

  /* ------------------------------ timer ------------------------------ */

  useEffect(() => {
    if (completed || !view) return undefined
    const timer = setInterval(() => setSeconds((v) => v + 1), 1000)
    return () => clearInterval(timer)
  }, [completed, view])

  // Routine confirmations fade by themselves; warnings and errors stay.
  useEffect(() => {
    if (!result || !['ok', 'info'].includes(result.kind)) return undefined
    const t = setTimeout(() => setResult(null), 9000)
    return () => clearTimeout(t)
  }, [result])

  /* ------------------------------ start ------------------------------ */

  const startSimulation = useCallback(async (generator = 'ai', restart = false) => {
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setCanSkipAi(false)
    setError('')
    const skipTimer = generator === 'ai' ? setTimeout(() => setCanSkipAi(true), 4000) : null
    try {
      const { ok, data } = await callApi('/api/blue-phishing/start', {
        body: { generator, restart },
        signal: controller.signal,
      })
      if (!ok) throw new Error(data.error || 'Unable to start Blue Team simulation.')
      const notes = loadNotes(data.session_id)
      const steps = buildSteps(data)
      const startForm = notes.form || { ...EMPTY_FORM, classification: data.assessment?.classification || '', severity: data.assessment?.severity || '' }
      const idx = steps.findIndex((s) => s.id === notes.stepId)
      setView(data)
      setSeconds(Number(data.elapsed_seconds || 0))
      setSaved(notes)
      setStepId(steps[idx >= 0 ? idx : resumeIndex(steps, data, startForm)].id)
      setVerification({})
      setOverlay(null)
      setReport(null)
      setReportState({ loading: false, error: '' })
      setResult(data.resumed
        ? { kind: 'info', title: 'Investigation resumed', body: 'Your earlier progress and clues are intact.' }
        : null)
      setLoading(false)
    } catch (e) {
      if (e.name === 'AbortError') return
      setError(e.message || 'Unable to start Blue Team simulation.')
      setLoading(false)
    } finally {
      if (skipTimer) clearTimeout(skipTimer)
    }
  }, [])

  useEffect(() => {
    startSimulation('ai')
    return () => abortRef.current?.abort()
  }, [startSimulation])

  const skipAi = () => {
    abortRef.current?.abort()
    startSimulation('template')
  }

  /* ------------------------------ report ------------------------------ */

  const loadReport = useCallback(async (sessionId) => {
    setReportState({ loading: true, error: '' })
    try {
      const complete = await callApi(`/api/blue-phishing/${sessionId}/complete`)
      if (!complete.ok) throw new Error(complete.data.error || 'Unable to complete the simulation.')
      const res = await callApi(`/api/blue-phishing/${sessionId}/report`, { method: 'GET' })
      if (!res.ok) throw new Error(res.data.error || 'Unable to load the incident report.')
      setReport(res.data.report)
      setReportState({ loading: false, error: '' })
    } catch (e) {
      setReportState({ loading: false, error: e.message || 'Unable to load the debrief.' })
    }
  }, [])

  useEffect(() => {
    if (completed && view && !report && !reportState.loading && !reportState.error) loadReport(view.session_id)
  }, [completed, view, report, reportState, loadReport])

  /* ------------------------------ actions ----------------------------- */

  const perform = async (action, target = null, params = null) => {
    if (!view || busy) return null
    setBusy(true)
    setError('')
    try {
      const body = { action }
      if (target) body.target = target
      if (params) body.params = params
      const { ok, status, data } = await callApi(`/api/blue-phishing/${view.session_id}/action`, { body })

      const next = data && data.incident ? data : view
      if (next !== view) {
        setView(data)
        setSeconds(Number(data.elapsed_seconds ?? seconds))
      }
      if (data.new_evidence?.length) setNewEvidence(data.new_evidence.map((e) => e.id))
      if (data.verification) setVerification((v) => ({ ...v, [data.verification.kind]: data.verification }))

      if (ok) {
        const card = explainResult(action, data, next)
        const extra = [...(data.feedback || []), ...(data.attacker_alerts || []).map((t) => `New activity: ${t}`)]
        if (extra.length) {
          card.extra = extra
          if (card.kind === 'ok') card.kind = 'warn'
        }
        setResult(card)
        if (sound) play((data.attacker_alerts || []).length ? 'alert' : card.kind)
      } else {
        const card = explainError(data, status)
        if (data.penalty_points) card.extra = [`Score penalty: −${data.penalty_points}. ${(data.feedback || []).join(' ')}`.trim()]
        if (data.restart_required) card.body = 'This session came from an older version of the simulation. Start a new incident to continue.'
        setResult(card)
        if (sound) play('warn')
      }
      return ok ? data : null
    } catch (e) {
      console.error('Blue phishing action error:', e)
      setResult(NETWORK_ERROR)
      return null
    } finally {
      setBusy(false)
    }
  }

  // Consequential actions, and closure, are confirmed before they are sent.
  const ask = (action, target, targetLabel, params = null) => {
    const info = view.available_actions.find((a) => a.action === action)
    if (!info?.confirm && action !== 'close_incident') return perform(action, target, params)
    setOverlay({
      kind: 'confirm', action, target, params, targetLabel,
      actionLabel: info?.label || prettify(action),
      impact: action === 'close_incident' ? CLOSE_IMPACT : info.impact,
    })
    return null
  }

  const confirmPending = async () => {
    const p = overlay
    if (!p || p.kind !== 'confirm') return
    const params = p.action === 'close_incident' ? p.params : { ...(p.params || {}), confirm: true }
    await perform(p.action, p.target, params)
    setOverlay(null)
  }

  const submitClosure = () => ask('close_incident', null, 'Close this case', {
    classification: form.classification, severity: form.severity, root_cause: form.root_cause,
    residual_risk: form.residual_risk, evidence_preserved: form.evidence_preserved, summary: form.summary,
    affected_user_ids: form.users, affected_asset_ids: form.assets, supporting_evidence_ids: saved.pinned,
  })

  /* ------------------------------ helpers ----------------------------- */

  const titleOf = (id) => view.evidence.find((e) => e.id === id)?.title || id
  const evidenceCard = (e) => (
    <BlueEvidenceCard
      key={e.id}
      evidence={e}
      busy={busy || completed}
      onPreserve={completed ? null : (id) => perform('preserve_evidence', id)}
      highlight={newEvidence.includes(e.id)}
      onSelectRelated={() => setOverlay({ kind: 'tray' })}
      titleOf={titleOf}
    />
  )
  const setVerdict = (id, value) => updateSaved((s) => ({ verdicts: { ...s.verdicts, [id]: value } }))
  const closeOverlay = () => setOverlay(null)
  const guide = { guided: true, advanced: false, seen: prefs.seen, markSeen, openTerm: (id) => setOverlay({ kind: 'term', id }) }
  const shell = (children) => (
    <GuideContext.Provider value={guide}><div className="bg-page">{children}</div></GuideContext.Provider>
  )

  /* ------------------------------ screens ----------------------------- */

  const simpleHeader = (subtitle) => (
    <header className="bg-topbar">
      <div className="bg-brand"><span className="bg-brand-mark" aria-hidden="true" /><strong>Sentinel</strong><span>Blue Team</span></div>
      <p className="bg-top-sub">{subtitle}</p>
    </header>
  )

  if (loading) {
    return shell(
      <>
        {simpleHeader('Preparing a new incident for you…')}
        <div className="bg-center" role="status">
          <div className="bg-spinner" aria-hidden="true" />
          <p>Generating a unique phishing incident with the local AI model…</p>
          <p className="bg-small">This usually takes a few seconds. If the model is slow or offline, a built-in scenario is used automatically.</p>
          {canSkipAi && <button type="button" className="bg-btn" onClick={skipAi}>Don't wait — use a built-in scenario</button>}
        </div>
      </>,
    )
  }

  if (!view) {
    return shell(
      <>
        {simpleHeader('The simulation could not be started.')}
        <div className="bg-center">
          <p role="alert" className="bg-error-text">{error || 'Unable to start Blue Team simulation.'}</p>
          <p className="bg-small">Your progress is safe. Check that the backend is running, then try again.</p>
          <div className="bg-row">
            <button type="button" className="bg-btn bg-primary" onClick={() => startSimulation('ai')}>Try again</button>
            <button type="button" className="bg-btn" onClick={() => startSimulation('template')}>Use a built-in scenario</button>
          </div>
        </div>
      </>,
    )
  }

  const steps = buildSteps(view)
  const idx = Math.max(0, steps.findIndex((s) => s.id === stepId))
  const step = steps[idx]
  const gen = view.generation || {}
  const goTo = (i) => {
    const target = steps[Math.min(Math.max(i, 0), steps.length - 1)]
    setStepId(target.id)
    updateSaved({ stepId: target.id })
    setResult(null)
    try { window.scrollTo({ top: 0 }) } catch { /* not available */ }
  }
  const goToId = (id) => { const i = steps.findIndex((s) => s.id === id); if (i >= 0) goTo(i) }
  const common = { view, busy, completed, run: perform, ask, evidenceCard, verdicts: saved.verdicts, setVerdict }

  const renderStep = () => {
    switch (step.id) {
      case 'alerts': return <AlertsScreen {...common} />
      case 'email': return <EmailScreen {...common} />
      case 'link': return <LinkScreen {...common} />
      case 'attachment': return <AttachmentScreen {...common} />
      case 'security': return <SecurityScreen {...common} />
      case 'indicator': return <IndicatorScreen {...common} titleOf={titleOf} onOpenTray={() => setOverlay({ kind: 'tray' })} />
      case 'activity': return <ActivityScreen {...common} />
      case 'decide': return <DecideScreen {...common} form={form} setForm={setForm} />
      case 'contain': return <RespondScreen mode="contain" {...common} />
      case 'fix': return <RespondScreen mode="fix" {...common} />
      case 'verify': return <VerifyScreen {...common} verification={verification} onFix={() => goToId('contain')} />
      case 'affected': return <AffectedScreen view={view} form={form} setForm={setForm} />
      case 'cause': return <CauseScreen view={view} form={form} setForm={setForm} />
      case 'close':
        return <CloseScreen view={view} busy={busy} form={form} setForm={setForm} pinned={saved.pinned}
          setPinned={(pinned) => updateSaved({ pinned })} onClose={submitClosure} />
      default: return null
    }
  }

  return shell(
    <>
      <IncidentHeader
        view={view} sound={sound}
        onSound={() => setSound(!sound)}
        onTray={() => setOverlay({ kind: 'tray' })}
        onHelp={() => setOverlay({ kind: 'help' })}
        onExit={() => setOverlay({ kind: 'exit' })}
      />

      {gen.source === 'ollama' && <div className="bg-banner ai">AI-generated scenario · model {gen.model}</div>}
      {gen.source === 'template' && gen.fallback && (
        <div className="bg-banner fallback" role="status">
          Sentinel is using its built-in scenario generator because {FALLBACK_REASONS[gen.fallback_reason] || 'AI generation was unavailable'}.
        </div>
      )}
      {gen.source === 'template' && !gen.fallback && <div className="bg-banner">Built-in scenario</div>}
      {error && <div className="bg-banner fallback" role="alert">{error}</div>}

      <main className="bg-stage">
        {completed ? (
          <Debrief view={view} report={report} loading={reportState.loading} error={reportState.error} seconds={seconds} busy={busy}
            onReplay={() => startSimulation('ai', true)}
            onReport={() => navigate('/outcome', { state: { reportId: report.report_id, report } })} />
        ) : (
          <Screen
            view={view} step={step} index={idx} total={steps.length}
            ready={isReady(step, view, form)}
            onBack={() => goTo(idx - 1)} onNext={() => goTo(idx + 1)}
            nextLabel={idx < steps.length - 1 ? `Next: ${steps[idx + 1].title} →` : null}
          >
            {renderStep()}
          </Screen>
        )}
      </main>

      {result && <div className="bg-toast"><ResultCard result={result} onDismiss={() => setResult(null)} /></div>}

      {overlay?.kind === 'confirm' && <ConfirmDialog pending={overlay} busy={busy} onConfirm={confirmPending} onCancel={closeOverlay} />}
      {overlay?.kind === 'term' && <TermDialog id={overlay.id} onClose={closeOverlay} />}
      {overlay?.kind === 'help' && <GlossaryDialog onClose={closeOverlay} />}
      {overlay?.kind === 'tray' && <Tray view={view} evidenceCard={evidenceCard} pinned={saved.pinned} onClose={closeOverlay} />}
      {overlay?.kind === 'exit' && (
        <Modal labelledBy="bg-exit-title" onClose={closeOverlay} size="sm" initialFocus=".bg-primary">
          <header className="bg-modal-head"><h2 id="bg-exit-title">Exit this investigation?</h2></header>
          <p>Your progress and clues are saved. You can resume this case later from the Blue Team page.</p>
          <div className="bg-modal-actions">
            <button type="button" className="bg-btn bg-primary" onClick={closeOverlay}>Stay</button>
            <button type="button" className="bg-btn bg-btn-danger" onClick={() => navigate('/dashboard')}>Exit Investigation</button>
          </div>
        </Modal>
      )}
    </>,
  )
}
