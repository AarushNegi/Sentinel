// pages/Simulation.jsx
import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { getScenario, startSimulation, submitChoice, completeSimulation } from '../services/api'
import NetworkBackground from '../components/NetworkBackground'
import './Simulation.css'

export default function Simulation() {
  const location = useLocation()
  const navigate = useNavigate()
  const { mode = 'red', attack = 'phishing' } = location.state || {}

  const [scenario, setScenario] = useState(null)
  const [sessionId, setSessionId] = useState(null)
  const [stageIdx, setStageIdx] = useState(0)
  const [logLines, setLogLines] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [feedback, setFeedback] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        const scenarioRes = await getScenario(mode, attack)
        const startRes = await startSimulation({ mode, attack })
        if (cancelled) return
        setScenario(scenarioRes.data)
        setSessionId(startRes.data.session_id)
        setLoading(false)
      } catch (err) {
        if (!cancelled) {
          setError(err.response?.data?.error || 'Failed to load simulation.')
          setLoading(false)
        }
      }
    }

    init()
    return () => { cancelled = true }
  }, [mode, attack])

  const handleSelect = (optionId) => {
    if (feedback) return
    setSelectedId(optionId)
  }

  const handleSubmit = async () => {
    if (!selectedId) return
    try {
      const res = await submitChoice(sessionId, selectedId)
      setFeedback(res.data)
      setLogLines((prev) => [...prev, res.data.log])
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to submit choice.')
    }
  }

  const handleContinue = async () => {
    if (feedback.ended) {
      await completeSimulation(sessionId)
      navigate('/outcome', { state: { sessionId, mode, attack } })
      return
    }
    setStageIdx(feedback.nextStageIdx)
    setSelectedId(null)
    setFeedback(null)
  }

  if (loading) {
    return (
      <div className={`sim-page sim-${mode}`}>
        <NetworkBackground variant={mode} />
        <p className="sim-loading">Loading simulation…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className={`sim-page sim-${mode}`}>
        <NetworkBackground variant={mode} />
        <p className="sim-error">{error}</p>
      </div>
    )
  }

  const stage = scenario.stages[stageIdx]

  return (
    <div className={`sim-page sim-${mode}`}>
      <NetworkBackground variant={mode} />

      {/* LEFT — Kill chain rail + live log */}
      <div className="sim-left">
        <div className="sim-stage-rail">
          {scenario.stages.map((s, i) => (
            <div
              key={s.stageId}
              className={`sim-rail-node ${i < stageIdx ? 'done' : i === stageIdx ? 'active' : 'pending'}`}
            >
              <span className="sim-rail-dot" />
              <span className="sim-rail-label">{s.name}</span>
            </div>
          ))}
        </div>

        <div className="sim-log-panel">
          <div className="sim-log-title">Live Log</div>
          <div className="sim-log-lines">
            {logLines.length === 0 && <span className="sim-log-empty">Awaiting first action…</span>}
            {logLines.map((line, i) => (
              <div key={i} className="sim-log-line">{line}</div>
            ))}
          </div>
        </div>
      </div>

      {/* RIGHT — Challenge */}
      <div className="sim-right">
        <div className="sim-stage-header">
          <span className="sim-mitre-tag">{stage.mitre}</span>
          <h1>{stage.name}</h1>
          {stage.narrative && <span className="sim-narrative-tag">{stage.narrative}</span>}
        </div>

        <p className="sim-prompt">{stage.challenge.prompt}</p>

        <div className="sim-options">
          {stage.challenge.options.map((opt) => (
            <button
              key={opt.id}
              className={`sim-option ${selectedId === opt.id ? 'selected' : ''} ${
                feedback && opt.id === selectedId ? `revealed-${feedback.outcome}` : ''
              }`}
              onClick={() => handleSelect(opt.id)}
              disabled={!!feedback}
            >
              {opt.text}
            </button>
          ))}
        </div>

        {!feedback && (
          <button className="sim-submit-btn" onClick={handleSubmit} disabled={!selectedId}>
            Confirm Choice
          </button>
        )}

        {feedback && (
          <div className={`sim-feedback sim-feedback-${feedback.outcome}`}>
            <div className="sim-feedback-top">
              <span className="sim-feedback-outcome">{feedback.outcome.toUpperCase()}</span>
              <span className="sim-feedback-points">+{feedback.points} pts</span>
            </div>
            <p>{feedback.feedback}</p>
            <button className="sim-continue-btn" onClick={handleContinue}>
              {feedback.ended ? 'View Outcome Report →' : 'Continue →'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}