import React from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { TRAINING_PASSWORD } from '../data/phishingSimulation'
import './Outcome.css'
import BlueReportDetails from '../components/BlueReportDetails'

/*
 * =========================================================
 * RED TEAM — PHISHING
 * =========================================================
 */

const RED_STAGE_LABELS = {
  recon: 'Reconnaissance',
  target: 'Target Selection',
  craft: 'Phishing Email Crafting',
  delivery: 'Campaign Delivery',
  access: 'Victim Interaction',
  capture: 'Credential Capture',
  compromised: 'Account Compromised',
}

const RED_STAGE_POINTS = {
  recon: 100,
  target: 100,
  craft: 150,
  delivery: 150,
  access: 150,
  capture: 200,
  compromised: 175,
}


/*
 * =========================================================
 * BLUE TEAM — PHISHING
 * =========================================================
 */

const BLUE_STAGE_LABELS = {
  alert: 'Alert Triage',
  email: 'Email Investigation',
  ioc: 'IOC / Domain Analysis',
  user: 'User & Session Investigation',
  containment: 'Containment',
  remediation: 'Remediation',
  closure: 'Incident Closure',
}

const BLUE_STAGE_POINTS = {
  alert: 0,
  email: 125,
  ioc: 100,
  user: 150,
  containment: 375,
  remediation: 175,
  closure: 80,
}


/*
 * =========================================================
 * HELPERS
 * =========================================================
 */

function formatDuration(seconds) {
  const totalSeconds = Number(seconds)

  if (!Number.isFinite(totalSeconds)) {
    return '—'
  }

  const mins = Math.floor(
    totalSeconds / 60
  )

  const secs = Math.floor(
    totalSeconds % 60
  )

  return `${mins}m ${secs}s`
}


function getStageName(
  stage,
  isBlue
) {
  if (!stage) {
    return 'Unknown Stage'
  }

  const labels = isBlue
    ? BLUE_STAGE_LABELS
    : RED_STAGE_LABELS

  return (
    labels[stage] ||
    String(stage)
      .replace(/_/g, ' ')
      .replace(
        /\b\w/g,
        (letter) =>
          letter.toUpperCase()
      )
  )
}


function getStagePoints(
  stage,
  isBlue
) {
  const points = isBlue
    ? BLUE_STAGE_POINTS
    : RED_STAGE_POINTS

  return points[stage] || 0
}


function normaliseEvents(events) {
  if (!Array.isArray(events)) {
    return []
  }

  return events
    .flat(Infinity)
    .filter(
      (event) =>
        typeof event === 'string' ||
        typeof event === 'number'
    )
    .map((event) =>
      String(event)
    )
    .filter(
      (event) =>
        event.trim() !== ''
    )
}


/*
 * =========================================================
 * CSV DOWNLOAD
 * =========================================================
 */

function downloadCSV(
  report,
  isBlue
) {
  const events = normaliseEvents(
    report?.log_lines ||
    report?.logLines ||
    []
  )

  const stages =
    report?.stages_completed ||
    report?.stagesCompletedList ||
    []

  const team = isBlue
    ? 'Blue Team'
    : 'Red Team'

  const attack =
    report?.attack ||
    'phishing'

  const rows = [
    [
      'Sentinel Simulation Report'
    ],

    [],

    [
      'Team',
      team
    ],

    [
      'Mode',
      report?.mode || (
        isBlue
          ? 'blue'
          : 'red'
      )
    ],

    [
      'Attack',
      attack
    ],

    [
      'Result',
      report?.result || 'success'
    ],

    [
      'Score',
      report?.score ?? 0
    ],

    [
      'Maximum Score',
      report?.max_score ??
      report?.maxScore ??
      (isBlue
        ? 1000
        : 1025)
    ],

    [
      'Duration Seconds',
      report?.duration_seconds ??
      report?.durationSeconds ??
      0
    ],

    [],

    [
      'Target'
    ],

    [
      'Name',
      report?.target?.name || ''
    ],

    [
      'Role',
      report?.target?.role || ''
    ],

    [
      'Department',
      report?.target?.department || ''
    ],

    [
      'Email',
      report?.target?.email || ''
    ],

    [],

    [
      'Completed Stages'
    ],

    ...stages.map(
      (stage) => [
        getStageName(
          stage,
          isBlue
        )
      ]
    ),

    [],

    [
      'Event Log'
    ],

    ...events.map(
      (event) => [event]
    ),
  ]

  const csv = rows
    .map((row) =>
      row
        .map((cell) => {
          const value =
            String(cell ?? '')

          return `"${value.replace(
            /"/g,
            '""'
          )}"`
        })
        .join(',')
    )
    .join('\n')

  const blob = new Blob(
    [csv],
    {
      type:
        'text/csv;charset=utf-8;',
    }
  )

  const url =
    URL.createObjectURL(
      blob
    )

  const link =
    document.createElement('a')

  link.href = url

  link.download =
    isBlue
      ? 'sentinel-blue-phishing-report.csv'
      : 'sentinel-red-phishing-report.csv'

  document.body.appendChild(
    link
  )

  link.click()

  document.body.removeChild(
    link
  )

  URL.revokeObjectURL(
    url
  )
}


/*
 * =========================================================
 * OUTCOME PAGE
 * =========================================================
 */

export default function Outcome() {

  const location =
    useLocation()

  const navigate =
    useNavigate()

  const report =
    location.state?.report || {}

  /*
   * Determine which phishing report
   * is being displayed.
   *
   * Red ransomware is NOT handled here.
   */

  const isBlue =
    report?.mode === 'blue' &&
    report?.attack === 'phishing'

  const isRed =
    report?.mode === 'red' &&
    report?.attack === 'phishing'


  /*
   * =======================================================
   * REPORT VALUES
   * =======================================================
   */

  const score =
    Number(
      report.score ?? 0
    )

  const maxScore =
    Number(
      report.max_score ??
      report.maxScore ??
      (
        isBlue
          ? 1000
          : 1025
      )
    )

  const durationSeconds =
    Number(
      report.duration_seconds ??
      report.durationSeconds ??
      0
    )

  const stages =
    report.stages_completed ||
    report.stagesCompletedList ||
    []

  const stageCount =
    Number(
      report.stagesCompleted ??
      stages.length ??
      0
    )

  const totalStages =
    Number(
      report.totalStages ??
      (
        isBlue
          ? 7
          : 7
      )
    )

  const events =
    normaliseEvents(
      report.log_lines ||
      report.logLines ||
      []
    )

  const percentage =
    maxScore > 0
      ? Math.round(
          (score / maxScore) * 100
        )
      : 0

  const isSuccess =
    report.result === 'success' ||
    report.result === 'completed' ||
    report.result === 'SUCCESS'

  const isPartial =
    !isSuccess &&
    report.result === 'partial'

  const target =
    report.target || {}


  /*
   * =======================================================
   * DISPLAY INFORMATION
   * =======================================================
   */

  const teamName =
    isBlue
      ? 'Blue Team'
      : 'Red Team'

  const reportTitle =
    isBlue
      ? 'Blue Team — Phishing — Incident Response Report'
      : 'Red Team — Phishing — Red Team Report'

  const targetHeading =
    isBlue
      ? 'Affected User'
      : 'Target Compromised'


  return (
    <div className="outcome-page">

      <div className="outcome-container">

        {/* =================================================
            RESULT HEADER
        ================================================== */}

        <section className="outcome-header">

          <div
            className={`result-badge ${
              isSuccess
                ? 'success'
                : isPartial
                ? 'partial'
                : 'failed'
            }`}
          >

            {isBlue && report.evaluation
              ? (isSuccess
                ? '✓ Incident Contained'
                : '✕ Incident Not Contained')
              : isSuccess
              ? '✓ Operation Successful'
              : isPartial
              ? '⚠ Partial Completion'
              : '✕ Simulation Failed'}

          </div>


          <h1>
            {reportTitle}
          </h1>


          <div className="summary-grid">

            {/* SCORE */}

            <div className="summary-card">

              <span>
                Score
              </span>

              <strong>
                {score} / {maxScore}
              </strong>

              <small>
                {percentage}%
              </small>

            </div>


            {/* STAGES */}

            <div className="summary-card">

              <span>
                Stages Completed
              </span>

              <strong>
                {stageCount} / {totalStages}
              </strong>

              <small>
                {stageCount === totalStages
                  ? 'Operation complete'
                  : 'Partial completion'}
              </small>

            </div>


            {/* TIME */}

            <div className="summary-card">

              <span>
                Time Taken
              </span>

              <strong>
                {formatDuration(
                  durationSeconds
                )}
              </strong>

              <small>
                Simulation duration
              </small>

            </div>

          </div>

        </section>


        {/* =================================================
            TARGET / AFFECTED USER
        ================================================== */}

        {target.name && (

          <section className="outcome-section">

            <h2>
              {targetHeading}
            </h2>


            <div className="target-report-card">

              <div className="target-main">

                <div className="target-avatar">

                  {target.name.charAt(0)}

                </div>


                <div>

                  <h3>
                    {target.name}
                  </h3>

                  <p>
                    {target.role}
                  </p>

                </div>

              </div>


              <div className="target-details">

                <div>

                  <span>
                    Department
                  </span>

                  <strong>
                    {target.department ||
                      '—'}
                  </strong>

                </div>


                <div>

                  <span>
                    Email
                  </span>

                  <strong>
                    {target.email ||
                      '—'}
                  </strong>

                </div>

              </div>

            </div>

          </section>

        )}


        {isBlue && report.evaluation && (
          <BlueReportDetails report={report} />
        )}


        {/* =================================================
            STAGES
        ================================================== */}

        {!(isBlue && report.score_breakdown) && (

        <section className="outcome-section">

          <h2>
            {isBlue
              ? 'Incident Investigation Breakdown'
              : 'Stage-by-Stage Breakdown'}
          </h2>


          <div className="stage-list">

            {stages.length > 0 ? (

              stages.map(
                (stage, index) => {

                  const points =
                    getStagePoints(
                      stage,
                      isBlue
                    )


                  return (

                    <div
                      className="stage-report-card"
                      key={`${stage}-${index}`}
                    >

                      <div className="stage-number">

                        {index + 1}

                      </div>


                      <div className="stage-info">

                        <strong>

                          {getStageName(
                            stage,
                            isBlue
                          )}

                        </strong>


                        <span>

                          {isBlue
                            ? 'Investigation stage completed successfully'
                            : 'Stage completed successfully'}

                        </span>

                      </div>


                      <div className="stage-points">

                        +{points} pts

                      </div>

                    </div>

                  )
                }
              )

            ) : (

              <div className="empty-state">

                No stage information available.

              </div>

            )}

          </div>

        </section>

        )}


        {/* =================================================
            RED PHISHING — CREDENTIAL CAPTURE
        ================================================== */}

        {isRed &&
          report.credential_capture && (

          <section className="outcome-section">

            <h2>
              Credential Capture
            </h2>


            <div className="credential-report-card">

              <div className="credential-status">

                <span className="status-dot"></span>

                Credentials captured in simulation

              </div>


              <div className="credential-row">

                <span>
                  Username
                </span>

                <code>
                  {
                    report
                      .credential_capture
                      .username ||
                    '—'
                  }
                </code>

              </div>


              <div className="credential-row">

                <span>
                  Password
                </span>

                <code>

                  {
                    report
                      .credential_capture
                      .credential_submission
                      ? TRAINING_PASSWORD
                      : '—'
                  }

                </code>

              </div>


              <div className="credential-row">

                <span>
                  Source
                </span>

                <code>

                  {
                    report
                      .credential_capture
                      .source ||
                    '—'
                  }

                </code>

              </div>

            </div>


            <p className="simulation-note">

              This credential capture occurred entirely inside
              Sentinel's fictional training environment. No real
              password was ever collected or stored — only a fixed
              training account is tracked.

            </p>

          </section>

        )}


        {/* =================================================
            RED PHISHING — CAMPAIGN ANALYSIS
        ================================================== */}

        {isRed && report.campaign_analysis && (

          <section className="outcome-section">
            <h2>Campaign Analysis</h2>
            <div className="summary-grid">
              {['relevance', 'credibility', 'urgency', 'suspicion'].map((key) => (
                <div className="summary-card" key={key}>
                  <span>{key.charAt(0).toUpperCase() + key.slice(1)}</span>
                  <strong>{report.campaign_analysis[key] ?? 0}%</strong>
                </div>
              ))}
            </div>
            {report.campaign && (
              <div className="target-report-card" style={{ marginTop: 16 }}>
                <div className="target-details">
                  <div><span>Sender</span><strong>{report.campaign.sender || '—'}</strong></div>
                  <div><span>Subject</span><strong>{report.campaign.subject || '—'}</strong></div>
                  <div><span>Call to Action</span><strong>{report.campaign.cta || '—'}</strong></div>
                  <div><span>Simulated URL</span><strong>{report.campaign.simulatedLink || '—'}</strong></div>
                </div>
              </div>
            )}
          </section>

        )}


        {/* =================================================
            RED PHISHING — LEARNING OUTCOMES
        ================================================== */}

        {isRed && report.learning_outcomes?.length > 0 && (

          <section className="outcome-section">
            <h2>Learning Outcomes</h2>
            <ul className="stage-list" style={{ listStyle: 'none', padding: 0 }}>
              {report.learning_outcomes.map((o) => (
                <li key={o} className="stage-report-card">
                  <div className="stage-info"><strong>✓ {o}</strong></div>
                </li>
              ))}
            </ul>
          </section>

        )}


        {/* =================================================
            RED PHISHING — DEFENDER INDICATORS
        ================================================== */}

        {isRed && report.defender_indicators?.length > 0 && (

          <section className="outcome-section">
            <h2>Defender Indicators</h2>
            <ul className="stage-list" style={{ listStyle: 'none', padding: 0 }}>
              {report.defender_indicators.map((ind) => (
                <li key={ind.type || ind.label} className="stage-report-card">
                  <div className="stage-info">
                    <strong>{ind.label}</strong>
                    <span>{ind.detail}</span>
                  </div>
                </li>
              ))}
            </ul>
          </section>

        )}


        {/* =================================================
            BLUE PHISHING — INCIDENT INFORMATION
        ================================================== */}

        {isBlue &&
          report.incident && (

          <section className="outcome-section">

            <h2>
              Incident Information
            </h2>


            <div className="target-report-card">

              <div className="target-details">

                <div>

                  <span>
                    Case
                  </span>

                  <strong>
                    {report.incident.id ||
                      'PHISH-2026-001'}
                  </strong>

                </div>


                <div>

                  <span>
                    Severity
                  </span>

                  <strong>
                    {report.incident.severity ||
                      'HIGH'}
                  </strong>

                </div>


                <div>

                  <span>
                    Type
                  </span>

                  <strong>
                    {report.incident.type ||
                      'Credential Phishing'}
                  </strong>

                </div>

              </div>

            </div>

          </section>

        )}


        {/* =================================================
            EVENT LOG
        ================================================== */}

        <section className="outcome-section">

          <h2>
            {isBlue
              ? 'SOC Investigation Log'
              : 'Event Log'}
          </h2>


          <div className="event-log">

            {events.length > 0 ? (

              events.map(
                (event, index) => (

                  <div
                    className="event-line"
                    key={index}
                  >

                    <span className="event-index">

                      {String(
                        index + 1
                      ).padStart(
                        2,
                        '0'
                      )}

                    </span>


                    <span className="event-text">

                      {event}

                    </span>

                  </div>

                )
              )

            ) : (

              <div className="empty-log">

                No events recorded.

              </div>

            )}

          </div>

        </section>


        {/* =================================================
            ACTIONS
        ================================================== */}

        <div className="outcome-actions">

          <button
            className="primary-action"
            onClick={() =>
              downloadCSV(
                report,
                isBlue
              )
            }
          >
            ↓ Download CSV
          </button>


          <button
            className="secondary-action"
            onClick={() =>
              navigate('/dashboard')
            }
          >
            Back to Dashboard
          </button>


          <button
            className="secondary-action"
            onClick={() =>
              navigate(
                isBlue
                  ? '/blue-phishing'
                  : '/red-phishing'
              )
            }
          >
            Run Another Simulation
          </button>

        </div>

      </div>

    </div>
  )
}