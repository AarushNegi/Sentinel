import React, { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './BluePhishingSimulation.css'

const API_BASE_URL = 'http://127.0.0.1:5000'

const STAGES = [
  { id: 'alert', label: 'ALERT' },
  { id: 'email', label: 'EMAIL INVESTIGATION' },
  { id: 'ioc', label: 'IOC ANALYSIS' },
  { id: 'user', label: 'USER INVESTIGATION' },
  { id: 'containment', label: 'CONTAINMENT' },
  { id: 'remediation', label: 'REMEDIATION' },
  { id: 'closure', label: 'CLOSURE' },
]

const MAX_SCORE = 1000

const INITIAL_EVENTS = [
  '[14:32:17] Email gateway generated phishing alert',
  '[14:32:18] Suspicious message delivered to Finance mailbox',
  '[14:32:21] URL reputation check returned suspicious',
]

const INITIAL_INCIDENT = {
  emailInspected: false,
  headersInspected: false,
  urlInspected: false,
  siemSearched: false,
  userInvestigated: false,
  endpointInvestigated: false,

  emailQuarantined: false,
  domainBlocked: false,
  sessionRevoked: false,
  endpointIsolated: false,

  accountReset: false,

  incidentClosed: false,
}

function formatTime(seconds) {
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60

  return `${String(mins).padStart(2, '0')}:${String(
    secs
  ).padStart(2, '0')}`
}

function nowTime() {
  return new Date().toLocaleTimeString([], {
    hour12: false,
  })
}

export default function BluePhishingSimulation() {
  const navigate = useNavigate()

  const [seconds, setSeconds] = useState(0)
  const [score, setScore] = useState(0)

  const [stage, setStage] = useState('alert')
  const [activeTab, setActiveTab] = useState('alert')

  const [incident, setIncident] =
    useState(INITIAL_INCIDENT)

  const [events, setEvents] =
    useState(INITIAL_EVENTS)

  const [completed, setCompleted] =
    useState(false)

  const [lastAction, setLastAction] =
    useState('')

  /*
   * =========================================================
   * BACKEND SESSION STATE
   * =========================================================
   */

  const [sessionId, setSessionId] =
    useState(null)

  const [loading, setLoading] =
    useState(true)

  const [actionLoading, setActionLoading] =
    useState(false)

  const [apiError, setApiError] =
    useState('')

  /*
   * =========================================================
   * TIMER
   * =========================================================
   */

  useEffect(() => {
    if (completed) return

    const timer = setInterval(() => {
      setSeconds((value) => value + 1)
    }, 1000)

    return () => clearInterval(timer)
  }, [completed])

  /*
   * =========================================================
   * INCIDENT DATA
   * =========================================================
   */

  const incidentData = useMemo(
    () => ({
      id: 'PHISH-2026-001',
      severity: 'HIGH',
      type: 'Credential Phishing',

      target: {
        name: 'Sarah Mitchell',
        role: 'Finance Manager',
        department: 'Finance',
        email: 'sarah.mitchell@acme.test',
        endpoint: 'FIN-WS-042',
      },

      email: {
        sender: 'billing@acme-vendor.test',
        recipient: 'sarah.mitchell@acme.test',
        subject: 'URGENT — Invoice Payment Required',
        attachment: 'Invoice_84721.zip',
        url: 'https://vendor-login.acme.test/verify',
      },

      ioc: {
        domain: 'vendor-login.acme.test',
        ip: '198.51.100.42',
        reputation: 'MALICIOUS',
      },
    }),
    []
  )

  /*
   * =========================================================
   * START / RESUME BLUE PHISHING SESSION
   * =========================================================
   */

  useEffect(() => {
    const startSimulation = async () => {
      const token =
        localStorage.getItem('token')

      if (!token) {
        setApiError(
          'Authentication required to start the simulation.'
        )

        setLoading(false)

        return
      }

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/blue-phishing/start`,
          {
            method: 'POST',

            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',
            },
          }
        )

        const data =
          await response.json()

        if (!response.ok) {
          throw new Error(
            data.error ||
            'Unable to start Blue Team simulation.'
          )
        }

        setSessionId(
          data.session_id
        )

        setScore(
          Number(data.score || 0)
        )

        setStage(
          data.stage || 'alert'
        )

        setActiveTab(
          data.stage || 'alert'
        )

        setIncident(
          data.state ||
          INITIAL_INCIDENT
        )

        setEvents(
          Array.isArray(data.events)
            ? data.events
            : INITIAL_EVENTS
        )

        setSeconds(
          Number(
            data.elapsed_seconds || 0
          )
        )

        setCompleted(
          data.status === 'completed'
        )

        setApiError('')

        if (data.resumed) {
          setLastAction(
            'Existing Blue Team session resumed'
          )
        }

      } catch (error) {
        console.error(
          'Blue phishing start error:',
          error
        )

        setApiError(
          error.message ||
          'Unable to start Blue Team simulation.'
        )

      } finally {
        setLoading(false)
      }
    }

    startSimulation()
  }, [])

  /*
   * =========================================================
   * BACKEND ACTION HANDLER
   * =========================================================
   */

  const performAction = async (
    action,
    successMessage
  ) => {
    if (!sessionId || actionLoading) {
      return
    }

    const token =
      localStorage.getItem('token')

    if (!token) {
      setApiError(
        'Authentication required.'
      )

      return
    }

    setActionLoading(true)
    setApiError('')

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/blue-phishing/${sessionId}/action`,
        {
          method: 'POST',

          headers: {
            Authorization:
              `Bearer ${token}`,

            'Content-Type':
              'application/json',
          },

          body: JSON.stringify({
            action,
          }),
        }
      )

      const data =
        await response.json()

      if (!response.ok) {
        throw new Error(
          data.error ||
          'Action could not be completed.'
        )
      }

      setScore(
        Number(data.score || 0)
      )

      setIncident(
        data.state ||
        INITIAL_INCIDENT
      )

      setStage(
        data.stage || stage
      )

      setActiveTab(
        data.stage || activeTab
      )

      setEvents(
        Array.isArray(data.events)
          ? data.events
          : events
      )

      if (
        data.status === 'completed'
      ) {
        setCompleted(true)
        setStage('closure')
        setActiveTab('closure')
      }

      setLastAction(
        successMessage ||
        `${action} completed`
      )

    } catch (error) {
      console.error(
        'Blue phishing action error:',
        error
      )

      setApiError(
        error.message ||
        'Action failed.'
      )

    } finally {
      setActionLoading(false)
    }
  }

  /*
   * =========================================================
   * EMAIL INVESTIGATION
   * =========================================================
   */

  const inspectEmail = () => {
    performAction(
      'inspect_email',
      'Email artifact inspected +50 points'
    )
  }

  const inspectHeaders = () => {
    performAction(
      'inspect_headers',
      'Suspicious header indicators identified +75 points'
    )
  }

  const inspectUrl = () => {
    performAction(
      'inspect_url',
      'Malicious IOC identified +100 points'
    )
  }

  /*
   * =========================================================
   * SIEM
   * =========================================================
   */

  const searchSIEM = () => {
    performAction(
      'search_siem',
      'SIEM correlation completed +100 points'
    )
  }

  /*
   * =========================================================
   * USER INVESTIGATION
   * =========================================================
   */

  const investigateUser = () => {
    performAction(
      'investigate_user',
      'User activity investigated +75 points'
    )
  }

  const investigateEndpoint = () => {
    performAction(
      'investigate_endpoint',
      'Endpoint telemetry investigated +75 points'
    )
  }

  const revokeSession = () => {
    performAction(
      'revoke_session',
      'Suspicious session revoked +100 points'
    )
  }

  /*
   * =========================================================
   * CONTAINMENT
   * =========================================================
   */

  const quarantineEmail = () => {
    performAction(
      'quarantine_email',
      'Phishing email contained +100 points'
    )
  }

  const blockDomain = () => {
    performAction(
      'block_domain',
      'Malicious domain blocked +100 points'
    )
  }

  const isolateEndpoint = () => {
    performAction(
      'isolate_endpoint',
      'Endpoint isolated +75 points'
    )
  }

  /*
   * =========================================================
   * REMEDIATION
   * =========================================================
   */

  const resetAccount = () => {
    performAction(
      'reset_account',
      'Account remediation completed +100 points'
    )
  }

  /*
   * =========================================================
   * CLOSE INCIDENT
   * =========================================================
   */

  const closeIncident = () => {
    performAction(
      'close_incident',
      'Incident successfully contained and closed +80 points'
    )
  }

  /*
   * =========================================================
   * STAGE PROGRESS
   * =========================================================
   */

  const stageIndex = STAGES.findIndex(
    (item) => item.id === stage
  )

  const progress =
    ((stageIndex + 1) / STAGES.length) * 100

  /*
   * =========================================================
   * REPORT
   * =========================================================
   */

  const openOutcome = async () => {
    if (!sessionId) {
      setApiError(
        'No active simulation session.'
      )

      return
    }

    if (!completed) {
      setApiError(
        'Complete the incident before opening the report.'
      )

      return
    }

    const token =
      localStorage.getItem('token')

    if (!token) {
      setApiError(
        'Authentication required.'
      )

      return
    }

    setActionLoading(true)
    setApiError('')

    try {
      /*
       * -------------------------------------------------------
       * Step 1 — Permanently complete the session.
       * -------------------------------------------------------
       */

      const completeResponse =
        await fetch(
          `${API_BASE_URL}/api/blue-phishing/${sessionId}/complete`,
          {
            method: 'POST',

            headers: {
              Authorization:
                `Bearer ${token}`,

              'Content-Type':
                'application/json',
            },
          }
        )

      const completeData =
        await completeResponse.json()

      if (!completeResponse.ok) {
        throw new Error(
          completeData.error ||
          'Unable to complete the simulation.'
        )
      }

      /*
       * -------------------------------------------------------
       * Step 2 — Retrieve the permanent MongoDB report.
       * -------------------------------------------------------
       */

      const reportResponse =
        await fetch(
          `${API_BASE_URL}/api/blue-phishing/${sessionId}/report`,
          {
            method: 'GET',

            headers: {
              Authorization:
                `Bearer ${token}`,
            },
          }
        )

      const reportData =
        await reportResponse.json()

      if (!reportResponse.ok) {
        throw new Error(
          reportData.error ||
          'Unable to load the incident report.'
        )
      }

      /*
       * -------------------------------------------------------
       * Step 3 — Pass the backend-generated report
       * to Outcome.
       * -------------------------------------------------------
       */

      navigate('/outcome', {
        state: {
          reportId:
            reportData.report.report_id ||
            completeData.report_id,

          report:
            reportData.report,
        },
      })

    } catch (error) {
      console.error(
        'Blue phishing report error:',
        error
      )

      setApiError(
        error.message ||
        'Unable to generate the incident report.'
      )

    } finally {
      setActionLoading(false)
    }
  }

  /*
   * =========================================================
   * ALERT
   * =========================================================
   */

  const renderAlert = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        SOC ALERT // PHISH-2026-001
      </div>

      <h2>
        Suspicious credential-phishing activity detected
      </h2>

      <p className="bt-muted">
        The email gateway has detected a suspicious
        message targeting a Finance employee.
        Investigate the incident and contain the threat.
      </p>

      <div className="bt-alert-grid">

        <div>
          <span>ALERT ID</span>

          <strong>
            PHISH-2026-001
          </strong>
        </div>

        <div>
          <span>SEVERITY</span>

          <strong className="bt-danger">
            HIGH
          </strong>
        </div>

        <div>
          <span>VECTOR</span>

          <strong>
            Credential Phishing
          </strong>
        </div>

        <div>
          <span>USER</span>

          <strong>
            {incidentData.target.name}
          </strong>
        </div>

      </div>

      <div className="bt-action-row">

        <button
          className="bt-primary"
          onClick={inspectEmail}
          disabled={
            loading ||
            actionLoading ||
            incident.emailInspected
          }
        >
          {incident.emailInspected
            ? 'Email Artifact Inspected ✓'
            : 'Open Email Artifact →'}
        </button>

      </div>

    </div>
  )

  /*
   * =========================================================
   * EMAIL INVESTIGATION
   * =========================================================
   */

  const renderEmail = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        EMAIL FORENSICS
      </div>

      <div className="bt-mail">

        <div className="bt-mail-toolbar">

          <span>
            ✉
          </span>

          <strong>
            MAILBOX // INBOX
          </strong>

        </div>

        <div className="bt-mail-meta">

          <div>

            <span>
              FROM
            </span>

            <strong>
              {incidentData.email.sender}
            </strong>

          </div>

          <div>

            <span>
              TO
            </span>

            <strong>
              {incidentData.email.recipient}
            </strong>

          </div>

          <div>

            <span>
              SUBJECT
            </span>

            <strong>
              {incidentData.email.subject}
            </strong>

          </div>

        </div>

        <div className="bt-mail-body">

          <p>
            Hello Sarah,
          </p>

          <p>
            Our accounting system detected an issue
            with your latest vendor invoice.
          </p>

          <p>
            Please review the invoice immediately
            to avoid payment interruption.
          </p>

          <button
            className="bt-sim-link"
            type="button"
          >
            Review Invoice
          </button>

          <p>
            Vendor Billing Team
          </p>

        </div>

      </div>

      <div className="bt-action-grid">

        <button
          className={
            incident.headersInspected
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={inspectHeaders}
          disabled={
            actionLoading ||
            incident.headersInspected
          }
        >
          <span>
            01
          </span>

          {incident.headersInspected
            ? 'Headers Inspected ✓'
            : 'Inspect Headers'}
        </button>

        <button
          className={
            incident.urlInspected
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={inspectUrl}
          disabled={
            actionLoading ||
            incident.urlInspected
          }
        >
          <span>
            02
          </span>

          {incident.urlInspected
            ? 'URL / IOC Extracted ✓'
            : 'Extract URL / IOC'}
        </button>

        <button
          className={
            incident.emailQuarantined
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={quarantineEmail}
          disabled={
            actionLoading ||
            incident.emailQuarantined
          }
        >
          <span>
            03
          </span>

          {incident.emailQuarantined
            ? 'Email Quarantined ✓'
            : 'Quarantine Email'}
        </button>

      </div>

    </div>
  )

  /*
   * =========================================================
   * IOC ANALYSIS
   * =========================================================
   */

  const renderIOC = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        IOC ANALYSIS
      </div>

      <h2>
        Suspicious infrastructure identified
      </h2>

      <div className="bt-ioc-card">

        <div className="bt-ioc-row">

          <span>
            DOMAIN
          </span>

          <strong>
            {incidentData.ioc.domain}
          </strong>

        </div>

        <div className="bt-ioc-row">

          <span>
            RESOLVED IP
          </span>

          <strong>
            {incidentData.ioc.ip}
          </strong>

        </div>

        <div className="bt-ioc-row">

          <span>
            REPUTATION
          </span>

          <strong className="bt-danger">
            {incidentData.ioc.reputation}
          </strong>

        </div>

      </div>

      <div className="bt-action-grid">

        <button
          className={
            incident.siemSearched
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={searchSIEM}
          disabled={
            actionLoading ||
            incident.siemSearched
          }
        >
          <span>
            01
          </span>

          {incident.siemSearched
            ? 'SIEM Correlation Complete ✓'
            : 'Correlate in SIEM'}
        </button>

        <button
          className={
            incident.domainBlocked
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={blockDomain}
          disabled={
            actionLoading ||
            incident.domainBlocked
          }
        >
          <span>
            02
          </span>

          {incident.domainBlocked
            ? 'Domain Blocked ✓'
            : 'Block Domain'}
        </button>

      </div>

    </div>
  )

  /*
   * =========================================================
   * USER / SESSION
   * =========================================================
   */

  const renderUser = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        USER / SESSION INVESTIGATION
      </div>

      <div className="bt-user-card">

        <div className="bt-avatar">
          SM
        </div>

        <div>

          <h3>
            {incidentData.target.name}
          </h3>

          <p>
            {incidentData.target.role}
          </p>

          <p>
            {incidentData.target.email}
          </p>

        </div>

      </div>

      <div className="bt-alert-box">

        <strong>
          SUSPICIOUS SESSION
        </strong>

        <span>
          Authentication activity occurred shortly
          after the phishing URL was accessed.
        </span>

      </div>

      <div className="bt-action-grid">

        <button
          className={
            incident.userInvestigated
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={investigateUser}
          disabled={
            actionLoading ||
            incident.userInvestigated
          }
        >
          <span>
            01
          </span>

          {incident.userInvestigated
            ? 'User Investigated ✓'
            : 'Investigate User'}
        </button>

        <button
          className={
            incident.endpointInvestigated
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={investigateEndpoint}
          disabled={
            actionLoading ||
            incident.endpointInvestigated
          }
        >
          <span>
            02
          </span>

          {incident.endpointInvestigated
            ? 'Endpoint Inspected ✓'
            : 'Inspect Endpoint'}
        </button>

        <button
          className={
            incident.sessionRevoked
              ? 'bt-action done'
              : 'bt-action'
          }
          onClick={revokeSession}
          disabled={
            actionLoading ||
            incident.sessionRevoked
          }
        >
          <span>
            03
          </span>

          {incident.sessionRevoked
            ? 'Session Revoked ✓'
            : 'Revoke Session'}
        </button>

      </div>

    </div>
  )

  /*
   * =========================================================
   * CONTAINMENT
   * =========================================================
   */

  const renderContainment = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        CONTAINMENT CONSOLE
      </div>

      <h2>
        Stop the phishing campaign
      </h2>

      <p className="bt-muted">
        Execute defensive actions against the
        compromised email, infrastructure and session.
      </p>

      <div className="bt-containment-grid">

        <button
          className={
            incident.emailQuarantined
              ? 'bt-contain done'
              : 'bt-contain'
          }
          onClick={quarantineEmail}
          disabled={
            actionLoading ||
            incident.emailQuarantined
          }
        >

          <strong>
            EMAIL
          </strong>

          <span>
            {incident.emailQuarantined
              ? 'QUARANTINED'
              : 'QUARANTINE MESSAGE'}
          </span>

        </button>

        <button
          className={
            incident.domainBlocked
              ? 'bt-contain done'
              : 'bt-contain'
          }
          onClick={blockDomain}
          disabled={
            actionLoading ||
            incident.domainBlocked
          }
        >

          <strong>
            DOMAIN
          </strong>

          <span>
            {incident.domainBlocked
              ? 'BLOCKED'
              : 'BLOCK MALICIOUS DOMAIN'}
          </span>

        </button>

        <button
          className={
            incident.sessionRevoked
              ? 'bt-contain done'
              : 'bt-contain'
          }
          onClick={revokeSession}
          disabled={
            actionLoading ||
            incident.sessionRevoked
          }
        >

          <strong>
            SESSION
          </strong>

          <span>
            {incident.sessionRevoked
              ? 'REVOKED'
              : 'REVOKE ACTIVE SESSION'}
          </span>

        </button>

        <button
          className={
            incident.endpointIsolated
              ? 'bt-contain done'
              : 'bt-contain'
          }
          onClick={isolateEndpoint}
          disabled={
            actionLoading ||
            incident.endpointIsolated
          }
        >

          <strong>
            ENDPOINT
          </strong>

          <span>
            {incident.endpointIsolated
              ? 'ISOLATED'
              : 'ISOLATE ENDPOINT'}
          </span>

        </button>

      </div>

    </div>
  )

  /*
   * =========================================================
   * REMEDIATION
   * =========================================================
   */

  const renderRemediation = () => (
    <div className="bt-card-content">

      <div className="bt-section-tag">
        REMEDIATION
      </div>

      <h2>
        Restore a trusted account state
      </h2>

      <div className="bt-remediation-card">

        <div>

          <span>
            ACCOUNT
          </span>

          <strong>
            {incidentData.target.email}
          </strong>

        </div>

        <div>

          <span>
            ENDPOINT
          </span>

          <strong>
            {incidentData.target.endpoint}
          </strong>

        </div>

        <div>

          <span>
            SESSION
          </span>

          <strong>
            {incident.sessionRevoked
              ? 'REVOKED'
              : 'ACTIVE'}
          </strong>

        </div>

      </div>

      <button
        className={
          incident.accountReset
            ? 'bt-primary complete'
            : 'bt-primary'
        }
        onClick={resetAccount}
        disabled={
          actionLoading ||
          incident.accountReset
        }
      >
        {incident.accountReset
          ? 'Account Remediated ✓'
          : 'Reset Account & Invalidate Tokens →'}
      </button>

      <button
        className="bt-close"
        onClick={closeIncident}
        disabled={
          actionLoading ||
          incident.incidentClosed
        }
      >
        Close Incident
      </button>

    </div>
  )

  /*
   * =========================================================
   * CLOSURE
   * =========================================================
   */

  const renderClosure = () => (
    <div className="bt-card-content bt-complete">

      <div className="bt-success-icon">
        ✓
      </div>

      <div className="bt-section-tag">
        INCIDENT CLOSED
      </div>

      <h2>
        Phishing incident successfully contained
      </h2>

      <p className="bt-muted">
        PHISH-2026-001 has been investigated,
        contained and remediated.
      </p>

      <div className="bt-final-stats">

        <div>

          <span>
            SCORE
          </span>

          <strong>
            {score} / {MAX_SCORE}
          </strong>

        </div>

        <div>

          <span>
            TIME
          </span>

          <strong>
            {formatTime(seconds)}
          </strong>

        </div>

        <div>

          <span>
            STATUS
          </span>

          <strong className="bt-success">
            CONTAINED
          </strong>

        </div>

      </div>

      <button
        className="bt-primary"
        onClick={openOutcome}
        disabled={
          actionLoading ||
          loading
        }
      >
        {actionLoading
          ? 'Generating Report...'
          : 'View Incident Report →'}
      </button>

    </div>
  )

  /*
   * =========================================================
   * WORKSPACE
   * =========================================================
   */

  const renderWorkspace = () => {

    if (activeTab === 'alert') {
      return renderAlert()
    }

    if (activeTab === 'email') {
      return renderEmail()
    }

    if (activeTab === 'ioc') {
      return renderIOC()
    }

    if (activeTab === 'user') {
      return renderUser()
    }

    if (activeTab === 'containment') {
      return renderContainment()
    }

    if (activeTab === 'remediation') {
      return renderRemediation()
    }

    return renderClosure()
  }

  /*
   * =========================================================
   * LOADING SCREEN
   * =========================================================
   */

  if (loading) {
    return (
      <div className="blue-phishing-page">

        <header className="bt-header">

          <div className="bt-brand">

            <div className="bt-brand-line">

              <span className="bt-brand-dot" />

              SENTINEL // BLUE TEAM

            </div>

            <h1>
              Phishing Incident Response
            </h1>

            <p>
              Initializing SOC investigation environment...
            </p>

          </div>

        </header>

      </div>
    )
  }

  /*
   * =========================================================
   * RENDER
   * =========================================================
   */

  return (
    <div className="blue-phishing-page">

      <header className="bt-header">

        <div className="bt-brand">

          <div className="bt-brand-line">

            <span className="bt-brand-dot" />

            SENTINEL // BLUE TEAM

          </div>

          <h1>
            Phishing Incident Response
          </h1>

          <p>
            Interactive SOC investigation environment
          </p>

        </div>

        <div className="bt-header-stats">

          <div className="bt-stat">

            <span>
              CASE
            </span>

            <strong>
              {incidentData.id}
            </strong>

          </div>

          <div className="bt-stat">

            <span>
              TIME
            </span>

            <strong>
              {formatTime(seconds)}
            </strong>

          </div>

          <div className="bt-stat">

            <span>
              SCORE
            </span>

            <strong>
              {score}
            </strong>

          </div>

          <div className="bt-stat">

            <span>
              SEVERITY
            </span>

            <strong className="bt-danger">
              {incidentData.severity}
            </strong>

          </div>

        </div>

      </header>


      {/* =====================================================
          STAGE PROGRESS
      ===================================================== */}

      <section className="bt-progress-section">

        <div className="bt-progress-track">

          <div
            className="bt-progress-fill"
            style={{
              width: `${progress}%`,
            }}
          />

        </div>

        <div className="bt-stage-list">

          {STAGES.map(
            (item, index) => {

              const currentIndex =
                STAGES.findIndex(
                  (stageItem) =>
                    stageItem.id === stage
                )

              let state = 'pending'

              if (
                index <
                currentIndex
              ) {
                state = 'finished'
              }

              if (
                item.id === stage
              ) {
                state = 'active'
              }

              if (completed) {
                state = 'finished'
              }

              return (
                <button
                  key={item.id}
                  type="button"
                  className={`bt-stage ${state}`}
                  onClick={() => {
                    if (
                      index <= currentIndex ||
                      completed
                    ) {
                      setActiveTab(
                        item.id
                      )
                    }
                  }}
                >

                  <span className="bt-stage-number">

                    {state === 'finished'
                      ? '✓'
                      : index + 1}

                  </span>

                  {item.label}

                </button>
              )
            }
          )}

        </div>

      </section>


      {/* =====================================================
          MAIN SOC WORKSPACE
      ===================================================== */}

      <main className="bt-layout">

        <section className="bt-main-panel">

          <div className="bt-panel-header">

            <div>

              <span>
                INCIDENT WORKSPACE
              </span>

              <strong>

                {activeTab === 'alert' &&
                  'Alert Details'}

                {activeTab === 'email' &&
                  'Email Investigation'}

                {activeTab === 'ioc' &&
                  'IOC Analysis'}

                {activeTab === 'user' &&
                  'User & Session'}

                {activeTab === 'containment' &&
                  'Containment Console'}

                {activeTab === 'remediation' &&
                  'Remediation'}

                {activeTab === 'closure' &&
                  'Incident Closure'}

              </strong>

            </div>

            <div className="bt-live">

              <span />

              LIVE

            </div>

          </div>


          {apiError && (

            <div
              className="bt-action-feedback"
              role="alert"
            >
              {apiError}
            </div>

          )}


          {renderWorkspace()}


          {lastAction && (

            <div
              className="bt-action-feedback"
              aria-live="polite"
            >
              {lastAction}
            </div>

          )}

        </section>


        {/* ===================================================
            RIGHT TELEMETRY
        =================================================== */}

        <aside className="bt-sidebar">


          {/* INCIDENT STATUS */}

          <div className="bt-side-card">

            <div className="bt-side-title">
              INCIDENT STATUS
            </div>

            <div className="bt-status-row">

              <span>
                CASE
              </span>

              <strong>
                {incidentData.id}
              </strong>

            </div>

            <div className="bt-status-row">

              <span>
                THREAT
              </span>

              <strong
                className={
                  completed
                    ? 'bt-success'
                    : 'bt-danger'
                }
              >
                {completed
                  ? 'CONTAINED'
                  : 'ACTIVE'}
              </strong>

            </div>

            <div className="bt-status-row">

              <span>
                USER
              </span>

              <strong>
                {incidentData.target.name}
              </strong>

            </div>

            <div className="bt-status-row">

              <span>
                ENDPOINT
              </span>

              <strong>
                {incidentData.target.endpoint}
              </strong>

            </div>

            <div className="bt-status-row">

              <span>
                STAGE
              </span>

              <strong>
                {STAGES[
                  Math.max(
                    0,
                    stageIndex
                  )
                ]?.label || 'ALERT'}
              </strong>

            </div>

          </div>


          {/* TELEMETRY */}

          <div className="bt-side-card">

            <div className="bt-side-title">
              LIVE TELEMETRY
            </div>

            <div className="bt-events">

              {events.map(
                (event, index) => (

                  <div
                    key={`${event}-${index}`}
                    className="bt-event"
                  >

                    <span className="bt-event-dot" />

                    <p>
                      {event}
                    </p>

                  </div>

                )
              )}

            </div>

          </div>


          {/* CHECKLIST */}

          <div className="bt-side-card">

            <div className="bt-side-title">
              RESPONSE CHECKLIST
            </div>

            <div className="bt-checklist">

              <div
                className={
                  incident.emailInspected
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.emailInspected
                    ? '✓'
                    : '○'}
                </span>
                Inspect email
              </div>

              <div
                className={
                  incident.headersInspected
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.headersInspected
                    ? '✓'
                    : '○'}
                </span>
                Inspect headers
              </div>

              <div
                className={
                  incident.urlInspected
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.urlInspected
                    ? '✓'
                    : '○'}
                </span>
                Analyze IOC
              </div>

              <div
                className={
                  incident.siemSearched
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.siemSearched
                    ? '✓'
                    : '○'}
                </span>
                Correlate SIEM
              </div>

              <div
                className={
                  incident.userInvestigated
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.userInvestigated
                    ? '✓'
                    : '○'}
                </span>
                Investigate user
              </div>

              <div
                className={
                  incident.endpointInvestigated
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.endpointInvestigated
                    ? '✓'
                    : '○'}
                </span>
                Inspect endpoint
              </div>

              <div
                className={
                  incident.emailQuarantined &&
                  incident.domainBlocked &&
                  incident.sessionRevoked &&
                  incident.endpointIsolated
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.emailQuarantined &&
                  incident.domainBlocked &&
                  incident.sessionRevoked &&
                  incident.endpointIsolated
                    ? '✓'
                    : '○'}
                </span>
                Containment complete
              </div>

              <div
                className={
                  incident.accountReset
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.accountReset
                    ? '✓'
                    : '○'}
                </span>
                Account remediated
              </div>

              <div
                className={
                  incident.incidentClosed
                    ? 'checked'
                    : ''
                }
              >
                <span>
                  {incident.incidentClosed
                    ? '✓'
                    : '○'}
                </span>
                Incident closed
              </div>

            </div>

          </div>

        </aside>

      </main>

    </div>
  )
}