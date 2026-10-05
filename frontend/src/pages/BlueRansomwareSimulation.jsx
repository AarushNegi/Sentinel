import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './BlueRansomwareSimulation.css'

const STAGES = [
  { id: 'alert', label: 'ALERT', title: 'Alert Triage' },
  { id: 'investigate', label: 'INVESTIGATE', title: 'Investigation' },
  { id: 'contain', label: 'CONTAIN', title: 'Containment' },
  { id: 'eradicate', label: 'ERADICATE', title: 'Eradication' },
  { id: 'recover', label: 'RECOVER', title: 'Recovery' },
  { id: 'closure', label: 'CLOSURE', title: 'Incident Closure' },
]

const INITIAL_HOSTS = [
  {
    id: 'PC-014',
    ip: '10.10.20.14',
    name: 'PC-014',
    user: 'Finance User',
    department: 'Finance',
    os: 'Windows 10 Enterprise',
    state: 'encrypted',
    isolated: false,
    clean: false,
    evidence: {
      processes: [
        'svchost.exe',
        'explorer.exe',
        'sentinel-sim.exe',
        'unknown-process.exe',
      ],
      connections: [
        '10.10.20.25:445',
        '198.51.100.77:443',
      ],
      files: [
        'Budget_2026.xlsx',
        'Payroll_Report.xlsx',
        'Invoices.zip',
        'Finance_Backup.db',
      ],
    },
  },
  {
    id: 'FILE-SRV-01',
    ip: '10.10.20.25',
    name: 'FILE-SRV-01',
    user: 'SYSTEM',
    department: 'Infrastructure',
    os: 'Windows Server 2019',
    state: 'encrypted',
    isolated: false,
    clean: false,
    evidence: {
      processes: [
        'services.exe',
        'svchost.exe',
        'sentinel-sim.exe',
        'unknown-process.exe',
      ],
      connections: [
        '10.10.20.14:445',
        '10.10.20.22:445',
      ],
      files: [
        'Company_Shared',
        'Department_Data',
        'Employee_Records',
        'Server_Backups',
      ],
    },
  },
  {
    id: 'HR-022',
    ip: '10.10.20.22',
    name: 'HR-022',
    user: 'HR User',
    department: 'Human Resources',
    os: 'Windows 10 Enterprise',
    state: 'suspicious',
    isolated: false,
    clean: false,
    evidence: {
      processes: [
        'explorer.exe',
        'chrome.exe',
        'sentinel-sim.exe',
        'unknown-process.exe',
      ],
      connections: [
        '10.10.20.25:445',
        '198.51.100.77:443',
      ],
      files: [
        'Employee_List.xlsx',
        'HR_Records.docx',
      ],
    },
  },
  {
    id: 'BACKUP-01',
    ip: '10.10.20.30',
    name: 'BACKUP-01',
    user: 'SYSTEM',
    department: 'Infrastructure',
    os: 'Windows Server 2019',
    state: 'healthy',
    isolated: false,
    clean: true,
    evidence: {
      processes: [
        'services.exe',
        'backup-agent.exe',
      ],
      connections: [
        '10.10.20.25:445',
      ],
      files: [
        'Daily_Snapshot.bak',
        'Weekly_Backup.bak',
        'System_Image.wim',
      ],
    },
  },
]

const INITIAL_TIMELINE = [
  {
    time: '09:12:03',
    type: 'danger',
    text: 'EDR detected abnormal file modification activity.',
  },
  {
    time: '09:12:08',
    type: 'danger',
    text: 'Multiple files changed to simulated encrypted state.',
  },
  {
    time: '09:12:16',
    type: 'warning',
    text: 'Suspicious outbound connection detected.',
  },
]

function BlueRansomwareSimulation() {
  const navigate = useNavigate()

  const [stage, setStage] = useState('alert')
  const [hosts, setHosts] = useState(INITIAL_HOSTS)
  const [selectedHostId, setSelectedHostId] = useState('PC-014')
  const [activeTab, setActiveTab] = useState('overview')

  const [score, setScore] = useState(0)
  const [timeline, setTimeline] = useState(INITIAL_TIMELINE)

  const [evidence, setEvidence] = useState({
    alertReviewed: false,
    hostInspected: false,
    processInvestigated: false,
    networkInvestigated: false,
    containmentDone: false,
    eradicationDone: false,
    recoveryDone: false,
  })

  const [toast, setToast] = useState('')

  const selectedHost = useMemo(
    () =>
      hosts.find(
        (host) => host.id === selectedHostId
      ),
    [hosts, selectedHostId]
  )

  const compromisedHosts = hosts.filter(
    (host) =>
      host.state === 'encrypted' ||
      host.state === 'suspicious'
  )

  const isolatedHosts = hosts.filter(
    (host) => host.isolated
  )

  const addTimeline = (text, type = 'info') => {
    const now = new Date()

    setTimeline((previous) => [
      ...previous,
      {
        time: now.toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        type,
        text,
      },
    ])
  }

  const notify = (message) => {
    setToast(message)

    setTimeout(() => {
      setToast('')
    }, 2500)
  }

  const updateHost = (id, changes) => {
    setHosts((previous) =>
      previous.map((host) =>
        host.id === id
          ? { ...host, ...changes }
          : host
      )
    )
  }

  const reviewAlert = () => {
    if (evidence.alertReviewed) return

    setEvidence((previous) => ({
      ...previous,
      alertReviewed: true,
    }))

    setScore((previous) => previous + 100)

    addTimeline(
      'Analyst reviewed the ransomware alert.',
      'success'
    )

    notify('Alert triage completed.')

    setTimeout(() => {
      setStage('investigate')
    }, 500)
  }

  const inspectHost = () => {
    if (!selectedHost) return

    if (!evidence.hostInspected) {
      setEvidence((previous) => ({
        ...previous,
        hostInspected: true,
      }))

      setScore((previous) => previous + 100)

      addTimeline(
        `${selectedHost.name} investigated by SOC analyst.`,
        'info'
      )

      notify(
        `${selectedHost.name} evidence loaded.`
      )
    }
  }

  const investigateProcesses = () => {
    if (!selectedHost) return

    if (!evidence.processInvestigated) {
      setEvidence((previous) => ({
        ...previous,
        processInvestigated: true,
      }))

      setScore((previous) => previous + 125)

      addTimeline(
        `Suspicious process identified on ${selectedHost.name}.`,
        'warning'
      )

      notify(
        'Suspicious process evidence identified.'
      )
    }

    setActiveTab('processes')
  }

  const investigateNetwork = () => {
    if (!selectedHost) return

    if (!evidence.networkInvestigated) {
      setEvidence((previous) => ({
        ...previous,
        networkInvestigated: true,
      }))

      setScore((previous) => previous + 125)

      addTimeline(
        `Suspicious network connection traced from ${selectedHost.name}.`,
        'warning'
      )

      notify(
        'Network indicator correlated.'
      )
    }

    setActiveTab('network')
  }

  const beginContainment = () => {
    if (evidence.containmentDone) return

    const targets = compromisedHosts.filter(
      (host) => !host.isolated
    )

    targets.forEach((host) => {
      updateHost(host.id, {
        isolated: true,
      })
    })

    setEvidence((previous) => ({
      ...previous,
      containmentDone: true,
    }))

    setScore((previous) => previous + 250)

    addTimeline(
      `${targets.length} affected systems isolated from the simulated network.`,
      'success'
    )

    notify('Containment completed.')

    setTimeout(() => {
      setStage('eradicate')
    }, 500)
  }

  const eradicateThreat = () => {
    if (evidence.eradicationDone) return

    setHosts((previous) =>
      previous.map((host) => {
        if (host.isolated) {
          return {
            ...host,
            clean: true,
          }
        }

        return host
      })
    )

    setEvidence((previous) => ({
      ...previous,
      eradicationDone: true,
    }))

    setScore((previous) => previous + 175)

    addTimeline(
      'Simulated malicious process removed from isolated systems.',
      'success'
    )

    notify('Eradication completed.')

    setTimeout(() => {
      setStage('recover')
    }, 500)
  }

  const recoverSystems = () => {
    if (evidence.recoveryDone) return

    setHosts((previous) =>
      previous.map((host) => ({
        ...host,
        state:
          host.clean && host.state === 'encrypted'
            ? 'recovering'
            : host.state,
      }))
    )

    setEvidence((previous) => ({
      ...previous,
      recoveryDone: true,
    }))

    setScore((previous) => previous + 150)

    addTimeline(
      'Recovery process initiated using available simulated backups.',
      'success'
    )

    notify('Recovery initiated.')

    setTimeout(() => {
      setStage('closure')
    }, 500)
  }

  const closeIncident = () => {
    setScore((previous) =>
      Math.min(previous + 75, 1000)
    )

    addTimeline(
      'Incident response workflow completed.',
      'success'
    )

    notify('Incident closed.')

    setTimeout(() => {
      navigate('/blue-ransomware-report', {
        state: {
          report: {
            mode: 'blue',
            attack: 'ransomware',
            incident: {
              id: 'RANSOM-2026-001',
              name: 'Northbridge Health Network Ransomware',
              severity: 'CRITICAL',
            },
            score: Math.min(score + 75, 1000),
            hosts,
            timeline,
            evidence,
          },
        },
      })
    }, 600)
  }

  const stageIndex = STAGES.findIndex(
    (item) => item.id === stage
  )

  const progress =
    ((stageIndex + 1) / STAGES.length) * 100

  return (
    <div className="br-page">
      <NetworkBackground />

      <div className="br-shell">

        {/* HEADER */}
        <header className="br-header">

          <div className="br-brand">
            <div className="br-logo">
              S
            </div>

            <div>
              <div className="br-brand-title">
                SENTINEL
              </div>

              <div className="br-brand-subtitle">
                BLUE TEAM / RANSOMWARE INCIDENT RESPONSE
              </div>
            </div>
          </div>

          <div className="br-incident">

            <span>ACTIVE INCIDENT</span>

            <strong>
              RANSOM-2026-001
            </strong>

            <small>
              NORTHBRIDGE HEALTH NETWORK
            </small>

          </div>

          <div className="br-score">

            <span>SOC SCORE</span>

            <strong>
              {score}
              <small>/1000</small>
            </strong>

          </div>

        </header>

        {/* PROGRESS */}
        <div className="br-progress">

          <div
            className="br-progress-fill"
            style={{
              width: `${progress}%`,
            }}
          />

        </div>

        {/* STAGES */}
        <div className="br-stagebar">

          {STAGES.map((item, index) => (

            <div
              key={item.id}
              className={`br-stage ${
                item.id === stage
                  ? 'active'
                  : ''
              } ${
                index < stageIndex
                  ? 'complete'
                  : ''
              }`}
            >

              <div className="br-stage-number">

                {index < stageIndex
                  ? '✓'
                  : index + 1}

              </div>

              <span>
                {item.label}
              </span>

            </div>

          ))}

        </div>

        {toast && (
          <div className="br-toast">
            {toast}
          </div>
        )}

        {/* MAIN */}
        <main className="br-workspace">

          {/* LEFT */}
          <aside className="br-panel br-host-panel">

            <div className="br-panel-header">

              <div>
                <span>
                  SOC ENVIRONMENT
                </span>

                <h2>
                  AFFECTED SYSTEMS
                </h2>
              </div>

              <div className="br-count">
                {compromisedHosts.length}
              </div>

            </div>

            <div className="br-host-list">

              {hosts.map((host) => (

                <button
                  key={host.id}
                  className={`br-host ${
                    selectedHostId === host.id
                      ? 'selected'
                      : ''
                  }`}
                  onClick={() =>
                    setSelectedHostId(host.id)
                  }
                >

                  <div
                    className={`br-host-dot ${
                      host.isolated
                        ? 'isolated'
                        : host.state
                    }`}
                  />

                  <div className="br-host-info">

                    <strong>
                      {host.name}
                    </strong>

                    <small>
                      {host.ip}
                    </small>

                    <em>
                      {host.department}
                    </em>

                  </div>

                  <div className="br-host-status">

                    {host.isolated
                      ? 'ISOLATED'
                      : host.state === 'encrypted'
                        ? 'ENCRYPTED'
                        : host.state === 'suspicious'
                          ? 'SUSPICIOUS'
                          : 'HEALTHY'}

                  </div>

                </button>

              ))}

            </div>

            <div className="br-host-summary">

              <div>
                <span>
                  ISOLATED
                </span>

                <strong>
                  {isolatedHosts.length}
                </strong>
              </div>

              <div>
                <span>
                  HEALTHY
                </span>

                <strong>
                  {
                    hosts.filter(
                      (host) =>
                        host.state ===
                        'healthy'
                    ).length
                  }
                </strong>
              </div>

            </div>

          </aside>

          {/* CENTER */}
          <section className="br-panel br-main-panel">

            <div className="br-main-header">

              <div>

                <span>
                  BLUE TEAM / ACTIVE INVESTIGATION
                </span>

                <h1>
                  {STAGES[stageIndex].title}
                </h1>

              </div>

              <div className="br-severity">
                <span />
                CRITICAL
              </div>

            </div>

            {/* ALERT */}
            {stage === 'alert' && (

              <div className="br-alert-view">

                <div className="br-alert-banner">

                  <div className="br-alert-icon">
                    !
                  </div>

                  <div>

                    <span>
                      HIGH PRIORITY EDR ALERT
                    </span>

                    <strong>
                      Ransomware-like file activity detected
                    </strong>

                  </div>

                </div>

                <div className="br-evidence-grid">

                  <div className="br-evidence-card">

                    <span>
                      ALERT SOURCE
                    </span>

                    <strong>
                      Sentinel EDR
                    </strong>

                  </div>

                  <div className="br-evidence-card">

                    <span>
                      AFFECTED HOSTS
                    </span>

                    <strong>
                      3
                    </strong>

                  </div>

                  <div className="br-evidence-card">

                    <span>
                      FILE EVENTS
                    </span>

                    <strong>
                      4,821
                    </strong>

                  </div>

                  <div className="br-evidence-card">

                    <span>
                      OUTBOUND IOC
                    </span>

                    <strong>
                      198.51.100.77
                    </strong>

                  </div>

                </div>

                <div className="br-alert-details">

                  <span className="br-kicker">
                    ALERT DETAILS
                  </span>

                  <p>
                    Sentinel EDR has detected rapid
                    modification of multiple files,
                    suspicious process execution and
                    unusual network activity across
                    several Northbridge systems.
                  </p>

                  <p>
                    The SOC must determine the scope
                    of the simulated incident and
                    contain affected systems.
                  </p>

                </div>

                <button
                  className="br-primary-button"
                  onClick={reviewAlert}
                >
                  REVIEW INCIDENT ALERT →
                </button>

              </div>

            )}

            {/* INVESTIGATION */}
            {stage === 'investigate' && selectedHost && (

              <div className="br-investigation">

                <div className="br-machine-header">

                  <div>

                    <span>
                      SELECTED HOST
                    </span>

                    <strong>
                      {selectedHost.name}
                    </strong>

                    <small>
                      {selectedHost.ip}
                    </small>

                  </div>

                  <div
                    className={`br-machine-state ${
                      selectedHost.isolated
                        ? 'isolated'
                        : selectedHost.state
                    }`}
                  >
                    {selectedHost.isolated
                      ? 'ISOLATED'
                      : selectedHost.state.toUpperCase()}
                  </div>

                </div>

                <div className="br-tabs">

                  {[
                    ['overview', 'OVERVIEW'],
                    ['processes', 'PROCESSES'],
                    ['network', 'NETWORK'],
                    ['files', 'FILES'],
                  ].map(([id, label]) => (

                    <button
                      key={id}
                      className={
                        activeTab === id
                          ? 'active'
                          : ''
                      }
                      onClick={() =>
                        setActiveTab(id)
                      }
                    >
                      {label}
                    </button>

                  ))}

                </div>

                <div className="br-investigation-body">

                  {activeTab === 'overview' && (

                    <div className="br-overview">

                      <div className="br-system-card">

                        <span>
                          OPERATING SYSTEM
                        </span>

                        <strong>
                          {selectedHost.os}
                        </strong>

                      </div>

                      <div className="br-system-card">

                        <span>
                          USER
                        </span>

                        <strong>
                          {selectedHost.user}
                        </strong>

                      </div>

                      <div className="br-system-card">

                        <span>
                          DEPARTMENT
                        </span>

                        <strong>
                          {selectedHost.department}
                        </strong>

                      </div>

                      <div className="br-system-card">

                        <span>
                          HOST STATE
                        </span>

                        <strong>
                          {selectedHost.state.toUpperCase()}
                        </strong>

                      </div>

                      <div className="br-investigation-actions">

                        <button
                          onClick={inspectHost}
                          className={
                            evidence.hostInspected
                              ? 'done'
                              : ''
                          }
                        >
                          {evidence.hostInspected
                            ? '✓ HOST INSPECTED'
                            : 'INSPECT HOST'}
                        </button>

                        <button
                          onClick={
                            investigateProcesses
                          }
                          className={
                            evidence.processInvestigated
                              ? 'done'
                              : ''
                          }
                        >
                          {evidence.processInvestigated
                            ? '✓ PROCESS ANALYSIS'
                            : 'ANALYZE PROCESSES'}
                        </button>

                        <button
                          onClick={
                            investigateNetwork
                          }
                          className={
                            evidence.networkInvestigated
                              ? 'done'
                              : ''
                          }
                        >
                          {evidence.networkInvestigated
                            ? '✓ NETWORK ANALYSIS'
                            : 'TRACE NETWORK'}
                        </button>

                      </div>

                    </div>

                  )}

                  {activeTab === 'processes' && (

                    <div className="br-list-view">

                      <div className="br-list-title">
                        RUNNING PROCESSES
                      </div>

                      {selectedHost.evidence.processes.map(
                        (process) => (

                          <div
                            key={process}
                            className={`br-process ${
                              process ===
                              'unknown-process.exe'
                                ? 'suspicious'
                                : ''
                            }`}
                          >

                            <span>
                              {process ===
                              'unknown-process.exe'
                                ? '!'
                                : '•'}
                            </span>

                            <strong>
                              {process}
                            </strong>

                            <small>
                              {process ===
                              'unknown-process.exe'
                                ? 'SUSPICIOUS'
                                : 'NORMAL'}
                            </small>

                          </div>

                        )
                      )}

                    </div>

                  )}

                  {activeTab === 'network' && (

                    <div className="br-list-view">

                      <div className="br-list-title">
                        NETWORK CONNECTIONS
                      </div>

                      {selectedHost.evidence.connections.map(
                        (connection) => (

                          <div
                            key={connection}
                            className={`br-process ${
                              connection.includes(
                                '198.51.100.77'
                              )
                                ? 'suspicious'
                                : ''
                            }`}
                          >

                            <span>
                              {connection.includes(
                                '198.51.100.77'
                              )
                                ? '!'
                                : '•'}
                            </span>

                            <strong>
                              {connection}
                            </strong>

                            <small>
                              {connection.includes(
                                '198.51.100.77'
                              )
                                ? 'SUSPICIOUS IOC'
                                : 'INTERNAL'}
                            </small>

                          </div>

                        )
                      )}

                    </div>

                  )}

                  {activeTab === 'files' && (

                    <div className="br-list-view">

                      <div className="br-list-title">
                        FILE ACTIVITY
                      </div>

                      {selectedHost.evidence.files.map(
                        (file) => (

                          <div
                            key={file}
                            className={`br-process ${
                              selectedHost.state ===
                              'encrypted'
                                ? 'suspicious'
                                : ''
                            }`}
                          >

                            <span>
                              {selectedHost.state ===
                              'encrypted'
                                ? '🔒'
                                : '□'}
                            </span>

                            <strong>
                              {file}
                            </strong>

                            <small>
                              {selectedHost.state ===
                              'encrypted'
                                ? 'ENCRYPTED'
                                : 'AVAILABLE'}
                            </small>

                          </div>

                        )
                      )}

                    </div>

                  )}

                </div>

                <div className="br-investigation-footer">

                  <button
                    className="br-primary-button"
                    disabled={
                      !evidence.hostInspected ||
                      !evidence.processInvestigated ||
                      !evidence.networkInvestigated
                    }
                    onClick={() =>
                      setStage('contain')
                    }
                  >
                    CONFIRM INCIDENT SCOPE →
                  </button>

                </div>

              </div>

            )}

            {/* CONTAINMENT */}
            {stage === 'contain' && (

              <div className="br-action-stage">

                <div className="br-stage-intro">

                  <div className="br-large-icon danger">
                    !
                  </div>

                  <div>

                    <span>
                      RESPONSE REQUIRED
                    </span>

                    <h2>
                      CONTAIN THE INCIDENT
                    </h2>

                    <p>
                      Multiple systems show signs of
                      ransomware activity. Isolate the
                      affected systems before the
                      simulated activity spreads further.
                    </p>

                  </div>

                </div>

                <div className="br-containment-grid">

                  {compromisedHosts.map((host) => (

                    <div
                      key={host.id}
                      className="br-contain-card"
                    >

                      <div>

                        <strong>
                          {host.name}
                        </strong>

                        <span>
                          {host.ip}
                        </span>

                      </div>

                      <em>
                        {host.isolated
                          ? 'ISOLATED'
                          : 'REQUIRES ISOLATION'}
                      </em>

                    </div>

                  ))}

                </div>

                <button
                  className="br-primary-button"
                  onClick={beginContainment}
                >
                  ISOLATE AFFECTED SYSTEMS
                </button>

              </div>

            )}

            {/* ERADICATE */}
            {stage === 'eradicate' && (

              <div className="br-action-stage">

                <div className="br-stage-intro">

                  <div className="br-large-icon">
                    ✓
                  </div>

                  <div>

                    <span>
                      CONTAINMENT SUCCESSFUL
                    </span>

                    <h2>
                      ERADICATE THREAT
                    </h2>

                    <p>
                      The affected systems are isolated.
                      Remove the simulated malicious
                      process and prepare the environment
                      for recovery.
                    </p>

                  </div>

                </div>

                <div className="br-eradication-console">

                  <div>
                    <span>
                      EDR ACTION
                    </span>

                    <strong>
                      Remove simulated malicious process
                    </strong>
                  </div>

                  <div>
                    <span>
                      TARGETS
                    </span>

                    <strong>
                      {isolatedHosts.length} isolated systems
                    </strong>
                  </div>

                  <div>
                    <span>
                      STATUS
                    </span>

                    <strong>
                      {evidence.eradicationDone
                        ? 'COMPLETED'
                        : 'READY'}
                    </strong>
                  </div>

                </div>

                <button
                  className="br-primary-button"
                  onClick={eradicateThreat}
                >
                  {evidence.eradicationDone
                    ? '✓ THREAT ERADICATED'
                    : 'ERADICATE SIMULATED THREAT'}
                </button>

              </div>

            )}

            {/* RECOVERY */}
            {stage === 'recover' && (

              <div className="br-action-stage">

                <div className="br-stage-intro">

                  <div className="br-large-icon">
                    ↻
                  </div>

                  <div>

                    <span>
                      SYSTEMS CLEAN
                    </span>

                    <h2>
                      RECOVER OPERATIONS
                    </h2>

                    <p>
                      Restore affected services using
                      the simulated recovery environment
                      and available backups.
                    </p>

                  </div>

                </div>

                <div className="br-recovery-grid">

                  <div className="br-recovery-card">

                    <span>
                      BACKUP-01
                    </span>

                    <strong>
                      AVAILABLE
                    </strong>

                    <small>
                      Latest snapshot: 08:00
                    </small>

                  </div>

                  <div className="br-recovery-card">

                    <span>
                      FILE-SRV-01
                    </span>

                    <strong>
                      READY FOR RECOVERY
                    </strong>

                    <small>
                      Backup integrity: VERIFIED
                    </small>

                  </div>

                  <div className="br-recovery-card">

                    <span>
                      PC-014
                    </span>

                    <strong>
                      READY FOR RECOVERY
                    </strong>

                    <small>
                      User files: RESTORABLE
                    </small>

                  </div>

                </div>

                <button
                  className="br-primary-button"
                  onClick={recoverSystems}
                >
                  RESTORE FROM SIMULATED BACKUP
                </button>

              </div>

            )}

            {/* CLOSURE */}
            {stage === 'closure' && (

              <div className="br-action-stage closure">

                <div className="br-success-mark">
                  ✓
                </div>

                <span>
                  RESPONSE WORKFLOW COMPLETE
                </span>

                <h2>
                  CLOSE INCIDENT
                </h2>

                <p>
                  The ransomware incident has been
                  contained, eradicated and recovered
                  within the simulated environment.
                </p>

                <div className="br-final-stats">

                  <div>
                    <span>
                      SCORE
                    </span>

                    <strong>
                      {score}
                    </strong>
                  </div>

                  <div>
                    <span>
                      HOSTS ISOLATED
                    </span>

                    <strong>
                      {isolatedHosts.length}
                    </strong>
                  </div>

                  <div>
                    <span>
                      EVIDENCE ITEMS
                    </span>

                    <strong>
                      7
                    </strong>
                  </div>

                </div>

                <button
                  className="br-primary-button"
                  onClick={closeIncident}
                >
                  CLOSE INCIDENT & VIEW REPORT →
                </button>

              </div>

            )}

          </section>

          {/* RIGHT */}
          <aside className="br-panel br-timeline-panel">

            <div className="br-panel-header">

              <div>
                <span>
                  SOC ACTIVITY
                </span>

                <h2>
                  INCIDENT TIMELINE
                </h2>
              </div>

              <div className="br-live">
                LIVE
              </div>

            </div>

            <div className="br-objective">

              <span>
                CURRENT OBJECTIVE
              </span>

              <strong>
                {STAGES[stageIndex].title}
              </strong>

              <p>
                {getObjective(stage)}
              </p>

            </div>

            <div className="br-timeline">

              {timeline
                .slice()
                .reverse()
                .map((event, index) => (

                  <div
                    key={`${event.time}-${index}`}
                    className={`br-event ${event.type}`}
                  >

                    <div className="br-event-line">
                      <span />
                    </div>

                    <div>

                      <small>
                        {event.time}
                      </small>

                      <p>
                        {event.text}
                      </p>

                    </div>

                  </div>

                ))}

            </div>

          </aside>

        </main>

        <footer className="br-footer">

          <div>
            <span className="br-online-dot" />
            BLUE TEAM SOC ACTIVE
          </div>

          <div>
            INCIDENT:
            <strong>
              RANSOM-2026-001
            </strong>
          </div>

          <div>
            STAGE {stageIndex + 1}/{STAGES.length}
          </div>

        </footer>

      </div>
    </div>
  )
}

function getObjective(stage) {
  switch (stage) {
    case 'alert':
      return 'Review the alert and determine whether the activity represents a ransomware incident.'

    case 'investigate':
      return 'Investigate affected systems, processes and network indicators to determine the scope.'

    case 'contain':
      return 'Isolate affected systems to prevent further simulated spread.'

    case 'eradicate':
      return 'Remove the simulated malicious process from contained systems.'

    case 'recover':
      return 'Restore affected services using the available simulated backup infrastructure.'

    case 'closure':
      return 'Review the response and close the incident.'

    default:
      return ''
  }
}

export default BlueRansomwareSimulation