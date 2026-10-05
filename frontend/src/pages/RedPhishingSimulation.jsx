import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './RedPhishingSimulation.css'

const API_BASE_URL = 'http://127.0.0.1:5000'

const TARGETS = [
  {
    id: 'sarah',
    name: 'Sarah Mitchell',
    role: 'Finance Manager',
    department: 'Finance',
    risk: 'HIGH',
    email: 'sarah.mitchell@acme.test',
    details: [
      'Handles vendor invoices',
      'Approves payment requests',
      'Frequently receives external documents',
    ],
  },
  {
    id: 'david',
    name: 'David Wilson',
    role: 'Accounts Payable Analyst',
    department: 'Finance',
    risk: 'MEDIUM',
    email: 'david.wilson@acme.test',
    details: [
      'Processes supplier invoices',
      'Works with external vendors',
      'Regular email communication',
    ],
  },
  {
    id: 'emily',
    name: 'Emily Carter',
    role: 'HR Operations',
    department: 'Human Resources',
    risk: 'LOW',
    email: 'emily.carter@acme.test',
    details: [
      'Receives employee documents',
      'Handles internal requests',
      'Lower financial access',
    ],
  },
]

const STAGES = [
  { id: 'recon', label: 'RECON' },
  { id: 'target', label: 'TARGET' },
  { id: 'craft', label: 'CRAFT' },
  { id: 'delivery', label: 'DELIVERY' },
  { id: 'access', label: 'ACCESS' },
  { id: 'capture', label: 'CAPTURE' },
  { id: 'compromised', label: 'COMPROMISED' },
]

const initialEvents = [
  '20:14:01  Operation initialized',
  '20:14:02  Reconnaissance environment ready',
]

export default function RedPhishingSimulation() {
  const navigate = useNavigate()

  const [stage, setStage] = useState('recon')
  const [target, setTarget] = useState(null)

  const [events, setEvents] = useState(initialEvents)
  const [score, setScore] = useState(0)
  const [seconds, setSeconds] = useState(0)

  const [subject, setSubject] = useState(
    'Invoice discrepancy — action required'
  )

  const [lure, setLure] = useState('invoice')
  const [urgency, setUrgency] = useState('medium')

  const [campaignDeployed, setCampaignDeployed] = useState(false)
  const [emailOpened, setEmailOpened] = useState(false)
  const [linkClicked, setLinkClicked] = useState(false)

  const [credentialsSubmitted, setCredentialsSubmitted] = useState(false)
  const [credentialRevealed, setCredentialRevealed] = useState(false)

  /*
   * This contains the dummy credentials entered inside
   * the fictional training portal.
   *
   * It is used for this Sentinel simulation report.
   */
  const [capturedCredential, setCapturedCredential] = useState(null)

  const [compromisedAccount, setCompromisedAccount] = useState(false)
  const [environmentEnumerated, setEnvironmentEnumerated] = useState(false)

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const [completed, setCompleted] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveStatus, setSaveStatus] = useState(null)

  /*
   * Operation timer
   */
  useEffect(() => {
    if (completed) return

    const timer = setInterval(() => {
      setSeconds((value) => value + 1)
    }, 1000)

    return () => clearInterval(timer)
  }, [completed])

  /*
   * Format timer as MM:SS
   */
  const time = useMemo(() => {
    const minutes = String(Math.floor(seconds / 60)).padStart(2, '0')
    const secs = String(seconds % 60).padStart(2, '0')

    return `${minutes}:${secs}`
  }, [seconds])

  /*
   * Add an event to the live telemetry console
   */
  const addEvent = (message) => {
    const timestamp = new Date().toLocaleTimeString([], {
      hour12: false,
    })

    setEvents((prev) => [
      ...prev,
      `${timestamp}  ${message}`,
    ])
  }

  /*
   * STAGE 1 — Select target
   */
  const selectTarget = (selectedTarget) => {
    setTarget(selectedTarget)

    addEvent(
      `Target selected: ${selectedTarget.name}`
    )

    setScore((value) => value + 50)

    setStage('target')
  }

  /*
   * STAGE 2 — Analyze target
   */
  const analyzeTarget = () => {
    if (!target) return

    addEvent(
      `Target profile analyzed: ${target.name}`
    )

    addEvent(
      'Business context identified'
    )

    setScore((value) => value + 75)

    setStage('craft')
  }

  /*
   * STAGE 3 — Prepare phishing campaign
   */
  const prepareCampaign = () => {
    addEvent(
      'Phishing email template generated'
    )

    addEvent(
      `Lure selected: ${lure}`
    )

    addEvent(
      `Urgency level: ${urgency}`
    )

    setScore((value) => value + 75)

    setStage('delivery')
  }

  /*
   * STAGE 4 — Deploy phishing email
   */
  const deployCampaign = () => {
    setCampaignDeployed(true)

    addEvent('Campaign initialized')
    addEvent('Target mailbox identified')
    addEvent('Message queued')

    setTimeout(() => {
      addEvent(
        'Message delivered to target mailbox'
      )
    }, 800)

    setScore((value) => value + 100)
  }

  /*
   * Target opens phishing email
   */
  const openEmail = () => {
    if (emailOpened) return

    setEmailOpened(true)

    addEvent(
      'Target opened phishing email'
    )

    addEvent(
      'Email subject inspected'
    )

    setScore((value) => value + 100)
  }

  /*
   * Target clicks phishing link
   */
  const clickLink = () => {
    if (linkClicked) return

    setLinkClicked(true)

    addEvent(
      'Target clicked simulated phishing link'
    )

    addEvent(
      'Credential collection page displayed'
    )

    setScore((value) => value + 125)

    setStage('access')
  }

  /*
   * STAGE 5 — Victim submits dummy credentials
   */
  const submitCredentials = (event) => {
    event.preventDefault()

    if (!email || !password) return

    /*
     * Store the dummy credentials for the current
     * Sentinel simulation.
     */
    const captured = {
      username: email,
      password: password,
      capturedAt: new Date().toLocaleTimeString([], {
        hour12: false,
      }),
      source: 'vendor-portal.acme.test',
    }

    setCapturedCredential(captured)
    setCredentialsSubmitted(true)

    addEvent(
      'Target submitted login form'
    )

    addEvent(
      'Authentication request intercepted'
    )

    addEvent(
      `Username captured: ${email}`
    )

    addEvent(
      'Password captured'
    )

    addEvent(
      'Credential transferred to attacker console'
    )

    setScore((value) => value + 250)

    setStage('capture')

    /*
     * Clear the victim-side password field.
     * The captured copy remains in the attacker console.
     */
    setPassword('')
  }

  /*
   * Reveal captured dummy password
   */
  const revealCredential = () => {
    if (!capturedCredential) return

    setCredentialRevealed(true)

    addEvent(
      'Captured credential revealed to operator'
    )
  }

  /*
   * STAGE 6 — Authenticate using captured credential
   */
  const obtainAccess = () => {
    if (!capturedCredential || !target) return

    setCompromisedAccount(true)

    addEvent(
      `Initial access established: ${target.name}`
    )

    addEvent(
      'Authenticated session simulated'
    )

    setScore((value) => value + 150)

    setStage('compromised')
  }

  /*
   * STAGE 7 — Enumerate compromised environment
   */
  const enumerateEnvironment = () => {
    setEnvironmentEnumerated(true)

    addEvent(
      'Compromised account environment enumerated'
    )

    addEvent(
      'Finance resources discovered'
    )

    setScore((value) => value + 100)
  }

  /*
   * Save the completed simulation to:
   *
   * React
   *   ↓
   * Flask
   *   ↓
   * MongoDB Atlas
   */
  const saveSimulation = async () => {
    if (!capturedCredential || !target) {
      return {
        success: false,
        reportId: null,
      }
    }

    setSaving(true)
    setSaveStatus(null)

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/red-phishing/complete`,
        {
          method: 'POST',

          headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`,
            },

          body: JSON.stringify({
            mode: 'red',

            attack: 'phishing',

            target: {
              id: target.id,
              name: target.name,
              role: target.role,
              department: target.department,
              email: target.email,
            },

            credential: {
              username: capturedCredential.username,
              password: capturedCredential.password,
              source: capturedCredential.source,
              capturedAt: capturedCredential.capturedAt,
            },

            score: score,

            durationSeconds: seconds,

            stagesCompleted: [
              'recon',
              'target',
              'craft',
              'delivery',
              'access',
              'capture',
              'compromised',
            ],

            choices: [
              {
                type: 'target',
                value: target.name,
              },

              {
                type: 'lure',
                value: lure,
              },

              {
                type: 'urgency',
                value: urgency,
              },
            ],

            logLines: events,
          }),
        }
      )

      const result = await response.json()

      if (!response.ok) {
        console.error(
          'Failed to save simulation:',
          result
        )

        setSaveStatus('error')

        return {
          success: false,
          reportId: null,
        }
      }

      console.log(
        'Simulation saved successfully:',
        result.report_id
      )

      setSaveStatus('success')

      return {
        success: true,
        reportId: result.report_id,
      }

    } catch (error) {
      console.error(
        'Simulation save error:',
        error
      )

      setSaveStatus('error')

      return {
        success: false,
        reportId: null,
      }

    } finally {
      setSaving(false)
    }
  }

  /*
   * Complete operation
   *
   * Saves to MongoDB first.
   * Then sends the user to Outcome page.
   */
  const finishMission = async () => {
    addEvent(
      'Phishing operation completed successfully'
    )

    const result = await saveSimulation()

    if (result.success) {
      addEvent(
        'Simulation report saved to Sentinel database'
      )

      setCompleted(true)

      /*
       * Send complete report data to Outcome page.
       *
       * reportId lets Outcome retrieve/use the MongoDB
       * report later.
       */
      navigate('/outcome', {
        state: {
          reportId: result.reportId,

          report: {
            mode: 'red',

            attack: 'phishing',

            guideTitle: 'Red Team — Phishing',

            target: target,

            credential_capture: capturedCredential,

            score: score,

            max_score: 1025,

            duration_seconds: seconds,

            stages_completed: [
              'recon',
              'target',
              'craft',
              'delivery',
              'access',
              'capture',
              'compromised',
            ],

            stagesCompleted: 7,

            failedAtStage: null,

            result: 'success',

            choices: [
              {
                type: 'target',
                value: target.name,
              },

              {
                type: 'lure',
                value: lure,
              },

              {
                type: 'urgency',
                value: urgency,
              },
            ],

            log_lines: events,

            logLines: events,

            report_id: result.reportId,
          },
        },
      })

    } else {
      addEvent(
        'Warning: simulation report could not be saved'
      )

      setCompleted(true)
    }
  }

  /*
   * Restart simulation
   */
  const resetSimulation = () => {
    window.location.reload()
  }

  return (
    <div className="red-phishing-page">

      <NetworkBackground variant="red" />

      {/* =========================================
          HEADER
      ========================================= */}

      <header className="rp-header">

        <div>

          <div className="rp-brand">

            <span className="rp-brand-dot" />

            SENTINEL // RED TEAM

          </div>

          <div className="rp-subtitle">
            PHISHING OPERATION
          </div>

        </div>

        <div className="rp-header-status">

          <div>

            <span>
              OPERATION TIME
            </span>

            <strong>
              {time}
            </strong>

          </div>

          <div>

            <span>
              THREAT
            </span>

            <strong className="rp-threat">
              {completed
                ? 'COMPLETE'
                : 'ACTIVE'}
            </strong>

          </div>

          <div>

            <span>
              SCORE
            </span>

            <strong>
              {score}
            </strong>

          </div>

        </div>

      </header>

      <main className="rp-main">

        {/* =========================================
            KILL CHAIN
        ========================================= */}

        <section className="rp-killchain">

          {STAGES.map((item, index) => {

            const currentIndex = STAGES.findIndex(
              (stageItem) => stageItem.id === stage
            )

            let state = 'pending'

            if (index < currentIndex) {
              state = 'complete'
            }

            if (item.id === stage) {
              state = 'active'
            }

            if (completed) {
              state = 'complete'
            }

            return (
              <div
                key={item.id}
                className={`rp-chain-item ${state}`}
              >

                <div className="rp-chain-dot">

                  {state === 'complete'
                    ? '✓'
                    : index + 1}

                </div>

                <span>
                  {item.label}
                </span>

                {index < STAGES.length - 1 && (
                  <div className="rp-chain-line" />
                )}

              </div>
            )
          })}

        </section>

        {/* =========================================
            MAIN GRID
        ========================================= */}

        <section className="rp-grid">

          {/* =========================================
              LEFT SIDE
          ========================================= */}

          <div className="rp-left">

            {/* TARGET INTELLIGENCE */}

            <div className="rp-panel">

              <div className="rp-panel-label">
                TARGET INTELLIGENCE
              </div>

              {!target ? (

                <>

                  <h2>
                    Select a target
                  </h2>

                  <p className="rp-muted">
                    Review the fictional organization and
                    identify a suitable campaign target.
                  </p>

                  <div className="rp-target-list">

                    {TARGETS.map((item) => (

                      <button
                        key={item.id}
                        className="rp-target"
                        onClick={() =>
                          selectTarget(item)
                        }
                      >

                        <div>

                          <strong>
                            {item.name}
                          </strong>

                          <span>
                            {item.role} · {item.department}
                          </span>

                        </div>

                        <span
                          className={`rp-risk rp-risk-${item.risk.toLowerCase()}`}
                        >
                          {item.risk}
                        </span>

                      </button>

                    ))}

                  </div>

                </>

              ) : (

                <>

                  <div className="rp-target-selected">

                    <div>

                      <span className="rp-small">
                        SELECTED TARGET
                      </span>

                      <h2>
                        {target.name}
                      </h2>

                      <p>
                        {target.role} · {target.department}
                      </p>

                    </div>

                    <span
                      className={`rp-risk rp-risk-${target.risk.toLowerCase()}`}
                    >
                      {target.risk}
                    </span>

                  </div>

                  <div className="rp-intel-list">

                    {target.details.map((detail) => (

                      <div key={detail}>

                        <span>
                          ›
                        </span>

                        {detail}

                      </div>

                    ))}

                  </div>

                </>

              )}

            </div>

            {/* LIVE TELEMETRY */}

            <div className="rp-panel rp-log-panel">

              <div className="rp-panel-label">
                LIVE ATTACK TELEMETRY
              </div>

              <div className="rp-log">

                {events.map((event, index) => (

                  <div
                    key={`${event}-${index}`}
                    className="rp-log-line"
                  >

                    <span className="rp-log-cursor">
                      ›
                    </span>

                    {event}

                  </div>

                ))}

              </div>

            </div>

          </div>

          {/* =========================================
              RIGHT SIDE
          ========================================= */}

          <div className="rp-right">

            {/* =========================================
                RECON
            ========================================= */}

            {stage === 'recon' && !target && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // RECONNAISSANCE
                </div>

                <h1>
                  Find the right target.
                </h1>

                <p>
                  Review the fictional organization intelligence
                  and identify a target suitable for the campaign.
                </p>

                <div className="rp-info-box">

                  <span>
                    ORGANIZATION
                  </span>

                  <strong>
                    ACME CORPORATION
                  </strong>

                  <div className="rp-info-grid">

                    <div>

                      <small>
                        EMPLOYEES
                      </small>

                      <b>
                        247
                      </b>

                    </div>

                    <div>

                      <small>
                        DEPARTMENTS
                      </small>

                      <b>
                        12
                      </b>

                    </div>

                    <div>

                      <small>
                        FINANCE USERS
                      </small>

                      <b>
                        18
                      </b>

                    </div>

                  </div>

                </div>

                <div className="rp-action-hint">
                  Select a target from the intelligence panel.
                </div>

              </div>
            )}

            {/* =========================================
                TARGET ANALYSIS
            ========================================= */}

            {stage === 'target' && target && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // TARGET ANALYSIS
                </div>

                <h1>
                  Analyze the target.
                </h1>

                <p>
                  Understand the target's fictional business
                  context before constructing the campaign.
                </p>

                <div className="rp-profile-card">

                  <div className="rp-profile-row">

                    <span>
                      NAME
                    </span>

                    <strong>
                      {target.name}
                    </strong>

                  </div>

                  <div className="rp-profile-row">

                    <span>
                      ROLE
                    </span>

                    <strong>
                      {target.role}
                    </strong>

                  </div>

                  <div className="rp-profile-row">

                    <span>
                      DEPARTMENT
                    </span>

                    <strong>
                      {target.department}
                    </strong>

                  </div>

                  <div className="rp-profile-row">

                    <span>
                      EMAIL
                    </span>

                    <strong>
                      {target.email}
                    </strong>

                  </div>

                  <div className="rp-profile-row">

                    <span>
                      OPPORTUNITY
                    </span>

                    <strong className="rp-red-text">
                      HIGH
                    </strong>

                  </div>

                </div>

                <button
                  className="rp-primary-btn"
                  onClick={analyzeTarget}
                >
                  Analyze Target →
                </button>

              </div>
            )}

            {/* =========================================
                CAMPAIGN BUILDER
            ========================================= */}

            {stage === 'craft' && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // CAMPAIGN BUILDER
                </div>

                <h1>
                  Craft the phishing campaign.
                </h1>

                <div className="rp-email-composer">

                  <div className="rp-email-field">

                    <span>
                      FROM
                    </span>

                    <strong>
                      billing@acme-vendor.test
                    </strong>

                  </div>

                  <div className="rp-email-field">

                    <span>
                      TO
                    </span>

                    <strong>
                      {target.email}
                    </strong>

                  </div>

                  <div className="rp-email-field">

                    <span>
                      SUBJECT
                    </span>

                    <input
                      value={subject}
                      onChange={(event) =>
                        setSubject(event.target.value)
                      }
                    />

                  </div>

                  <div className="rp-email-body">

                    <p>
                      Hello {target.name.split(' ')[0]},
                    </p>

                    <p>
                      Our accounting system detected a
                      discrepancy with your latest vendor invoice.
                    </p>

                    <p>
                      Please review the attached invoice summary
                      before the payment deadline.
                    </p>

                    <button
                      type="button"
                      className="rp-email-link"
                    >
                      Review Invoice
                    </button>

                    <p>
                      Regards,
                      <br />
                      Vendor Billing Team
                    </p>

                  </div>

                </div>

                <div className="rp-campaign-controls">

                  <label>

                    LURE TYPE

                    <select
                      value={lure}
                      onChange={(event) =>
                        setLure(event.target.value)
                      }
                    >

                      <option value="invoice">
                        Invoice
                      </option>

                      <option value="account">
                        Account notification
                      </option>

                      <option value="document">
                        Document sharing
                      </option>

                    </select>

                  </label>

                  <label>

                    URGENCY

                    <select
                      value={urgency}
                      onChange={(event) =>
                        setUrgency(event.target.value)
                      }
                    >

                      <option value="low">
                        Low
                      </option>

                      <option value="medium">
                        Medium
                      </option>

                      <option value="high">
                        High
                      </option>

                    </select>

                  </label>

                </div>

                <button
                  className="rp-primary-btn"
                  onClick={prepareCampaign}
                >
                  Prepare Campaign →
                </button>

              </div>
            )}

            {/* =========================================
                DELIVERY
            ========================================= */}

            {stage === 'delivery' && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // DELIVERY
                </div>

                <h1>
                  Deploy the campaign.
                </h1>

                {!campaignDeployed ? (

                  <>

                    <p>
                      The campaign is ready. Deploy it into
                      the simulated target environment.
                    </p>

                    <div className="rp-deployment-card">

                      <div>

                        <span>
                          RECIPIENT
                        </span>

                        <strong>
                          {target.name}
                        </strong>

                      </div>

                      <div>

                        <span>
                          SUBJECT
                        </span>

                        <strong>
                          {subject}
                        </strong>

                      </div>

                      <div>

                        <span>
                          STATUS
                        </span>

                        <strong className="rp-yellow">
                          READY
                        </strong>

                      </div>

                    </div>

                    <button
                      className="rp-primary-btn"
                      onClick={deployCampaign}
                    >
                      Deploy Campaign →
                    </button>

                  </>

                ) : (

                  <>

                    <div className="rp-success-box">

                      <span className="rp-success-icon">
                        ✓
                      </span>

                      <div>

                        <strong>
                          MESSAGE DELIVERED
                        </strong>

                        <p>
                          The simulated email has reached
                          the target mailbox.
                        </p>

                      </div>

                    </div>

                    <div className="rp-inbox">

                      <div className="rp-inbox-title">
                        TARGET MAILBOX
                      </div>

                      <button
                        className="rp-inbox-email"
                        onClick={openEmail}
                      >

                        <span className="rp-mail-icon">
                          ✉
                        </span>

                        <div>

                          <strong>
                            {subject}
                          </strong>

                          <span>
                            billing@acme-vendor.test
                          </span>

                        </div>

                        <span className="rp-unread">

                          {emailOpened
                            ? 'OPENED'
                            : 'NEW'}

                        </span>

                      </button>

                    </div>

                    {emailOpened && (

                      <div className="rp-email-preview">

                        <div className="rp-email-preview-header">

                          <span>
                            FROM
                          </span>

                          billing@acme-vendor.test

                        </div>

                        <div className="rp-email-preview-header">

                          <span>
                            TO
                          </span>

                          {target.email}

                        </div>

                        <div className="rp-email-preview-header">

                          <span>
                            SUBJECT
                          </span>

                          {subject}

                        </div>

                        <div className="rp-preview-body">

                          <p>
                            Hello {target.name.split(' ')[0]},
                          </p>

                          <p>
                            Our accounting system detected a
                            discrepancy with your latest vendor invoice.
                          </p>

                          <p>
                            Please review the invoice summary.
                          </p>

                          <button
                            type="button"
                            className="rp-phishing-link"
                            onClick={clickLink}
                          >
                            Review Invoice →
                          </button>

                          <p>
                            Vendor Billing Team
                          </p>

                        </div>

                      </div>

                    )}

                  </>

                )}

              </div>
            )}

            {/* =========================================
                FAKE VENDOR LOGIN
            ========================================= */}

            {stage === 'access' &&
              !credentialsSubmitted && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // INITIAL ACCESS
                </div>

                <h1>
                  Credential portal reached.
                </h1>

                <p>
                  The target has followed the simulated phishing
                  link. This fictional portal represents the
                  credential collection stage.
                </p>

                <div className="rp-browser">

                  <div className="rp-browser-bar">

                    <span>
                      ●
                    </span>

                    <span>
                      ●
                    </span>

                    <span>
                      ●
                    </span>

                    <div>
                      vendor-portal.acme.test
                    </div>

                  </div>

                  <div className="rp-login-page">

                    <div className="rp-portal-logo">
                      ACME
                    </div>

                    <h2>
                      Vendor Portal
                    </h2>

                    <p>
                      Invoice #7821 requires authentication.
                    </p>

                    <form
                      onSubmit={submitCredentials}
                    >

                      <input
                        type="email"
                        placeholder="Email address"
                        value={email}
                        onChange={(event) =>
                          setEmail(event.target.value)
                        }
                      />

                      <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(event) =>
                          setPassword(event.target.value)
                        }
                      />

                      <button type="submit">
                        Sign In
                      </button>

                    </form>

                    <small>
                      SIMULATION ENVIRONMENT — Use fictional
                      training credentials only.
                    </small>

                  </div>

                </div>

              </div>
            )}

            {/* =========================================
                CREDENTIAL CAPTURE
            ========================================= */}

            {stage === 'capture' &&
              capturedCredential && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // CREDENTIAL CAPTURE
                </div>

                <h1>
                  Credentials captured.
                </h1>

                <p>
                  The simulated victim submitted the login form.
                  The captured data is now visible to the attacker
                  inside the fictional operator console.
                </p>

                <div className="rp-capture-alert">

                  <div className="rp-capture-status">

                    <span className="rp-pulse" />

                    CREDENTIALS RECEIVED

                  </div>

                  <div className="rp-capture-card">

                    <div className="rp-capture-row">

                      <span>
                        TARGET
                      </span>

                      <strong>
                        {target.name}
                      </strong>

                    </div>

                    <div className="rp-capture-row">

                      <span>
                        SOURCE
                      </span>

                      <strong>
                        {capturedCredential.source}
                      </strong>

                    </div>

                    <div className="rp-capture-row">

                      <span>
                        CAPTURED AT
                      </span>

                      <strong className="rp-mono">
                        {capturedCredential.capturedAt}
                      </strong>

                    </div>

                    <div className="rp-capture-row">

                      <span>
                        USERNAME / EMAIL
                      </span>

                      <strong>
                        {capturedCredential.username}
                      </strong>

                    </div>

                    <div className="rp-capture-row">

                      <span>
                        PASSWORD
                      </span>

                      <strong className="rp-mono">

                        {credentialRevealed
                          ? capturedCredential.password
                          : '••••••••••••••••'}

                      </strong>

                    </div>

                    <div className="rp-capture-row">

                      <span>
                        CAPTURE STATUS
                      </span>

                      <strong className="rp-green">
                        SUCCESS
                      </strong>

                    </div>

                  </div>

                  <div className="rp-safety-note">
                    SIMULATION ENVIRONMENT — These are fictional
                    training credentials used for the Sentinel
                    cybersecurity simulation.
                  </div>

                </div>

                {!credentialRevealed && (

                  <button
                    className="rp-primary-btn"
                    onClick={revealCredential}
                  >
                    Reveal Captured Credential
                  </button>

                )}

                {credentialRevealed && (

                  <button
                    className="rp-primary-btn"
                    onClick={obtainAccess}
                  >
                    Authenticate as Target →
                  </button>

                )}

              </div>
            )}

            {/* =========================================
                COMPROMISED ACCOUNT
            ========================================= */}

            {stage === 'compromised' &&
              !completed &&
              compromisedAccount && (

              <div className="rp-action-panel">

                <div className="rp-stage-tag">
                  RED TEAM // COMPROMISED ACCOUNT
                </div>

                <h1>
                  Initial access established.
                </h1>

                <p>
                  The fictional target account is now under
                  attacker control within the simulation.
                </p>

                <div className="rp-compromised-banner">

                  <div className="rp-access-icon">
                    ✓
                  </div>

                  <div>

                    <strong>
                      AUTHENTICATED SESSION ACTIVE
                    </strong>

                    <span>
                      {target.name} · {target.department}
                    </span>

                  </div>

                </div>

                <div className="rp-account-card">

                  <div className="rp-account-header">
                    COMPROMISED ACCOUNT
                  </div>

                  <div className="rp-account-row">

                    <span>
                      USER
                    </span>

                    <strong>
                      {target.name}
                    </strong>

                  </div>

                  <div className="rp-account-row">

                    <span>
                      EMAIL
                    </span>

                    <strong>
                      {capturedCredential?.username}
                    </strong>

                  </div>

                  <div className="rp-account-row">

                    <span>
                      ROLE
                    </span>

                    <strong>
                      {target.role}
                    </strong>

                  </div>

                  <div className="rp-account-row">

                    <span>
                      DEPARTMENT
                    </span>

                    <strong>
                      {target.department}
                    </strong>

                  </div>

                  <div className="rp-account-row">

                    <span>
                      ACCESS
                    </span>

                    <strong className="rp-green">
                      INITIAL ACCESS
                    </strong>

                  </div>

                </div>

                {!environmentEnumerated ? (

                  <button
                    className="rp-primary-btn"
                    onClick={enumerateEnvironment}
                  >
                    Enumerate Environment →
                  </button>

                ) : (

                  <>

                    <div className="rp-resource-card">

                      <div className="rp-account-header">
                        DISCOVERED RESOURCES
                      </div>

                      <div>
                        ✓ Vendor invoices
                      </div>

                      <div>
                        ✓ Payment dashboard
                      </div>

                      <div>
                        ✓ Internal finance documents
                      </div>

                      <div>
                        ✓ Supplier records
                      </div>

                      <div className="rp-disabled">
                        ✕ Administrator controls
                      </div>

                    </div>

                    <button
                      className="rp-primary-btn"
                      onClick={finishMission}
                      disabled={saving}
                    >

                      {saving
                        ? 'Saving Operation...'
                        : 'Complete Operation →'}

                    </button>

                    {saveStatus === 'error' && (

                      <div className="rp-safety-note">

                        The operation completed locally,
                        but the report could not be saved
                        to the Sentinel database.

                      </div>

                    )}

                  </>

                )}

              </div>
            )}

            {/* =========================================
                FALLBACK COMPLETE SCREEN
            ========================================= */}

            {completed && (

              <div className="rp-action-panel rp-complete">

                <div className="rp-stage-tag">
                  RED TEAM // OPERATION COMPLETE
                </div>

                <div className="rp-access-icon">
                  ✓
                </div>

                <h1>
                  Phishing operation successful.
                </h1>

                <p>
                  The simulated campaign progressed from
                  reconnaissance to credential capture and
                  initial access.
                </p>

                <div className="rp-result-grid">

                  <div>

                    <span>
                      TARGET
                    </span>

                    <strong>
                      {target?.name}
                    </strong>

                  </div>

                  <div>

                    <span>
                      EMAIL
                    </span>

                    <strong>
                      OPENED
                    </strong>

                  </div>

                  <div>

                    <span>
                      LINK
                    </span>

                    <strong>
                      CLICKED
                    </strong>

                  </div>

                  <div>

                    <span>
                      CREDENTIAL
                    </span>

                    <strong>
                      CAPTURED
                    </strong>

                  </div>

                  <div>

                    <span>
                      ACCESS
                    </span>

                    <strong>
                      OBTAINED
                    </strong>

                  </div>

                </div>

                <div className="rp-final-score">

                  <span>
                    MISSION SCORE
                  </span>

                  <strong>
                    {score}
                  </strong>

                </div>

                {saveStatus === 'success' && (

                  <div className="rp-success-box">

                    <span className="rp-success-icon">
                      ✓
                    </span>

                    <div>

                      <strong>
                        REPORT SAVED
                      </strong>

                      <p>
                        Simulation results successfully stored
                        in the Sentinel database.
                      </p>

                    </div>

                  </div>

                )}

                <button
                  className="rp-primary-btn"
                  onClick={resetSimulation}
                >
                  Run Simulation Again →
                </button>

              </div>
            )}

          </div>

        </section>

      </main>

    </div>
  )
}