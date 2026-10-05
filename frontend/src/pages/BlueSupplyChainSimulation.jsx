import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './BlueSupplyChainSimulation.css'

const STAGES = [
  {
    id: 'alert',
    label: 'ALERT',
    title: 'Alert Triage',
  },
  {
    id: 'supplier',
    label: 'SUPPLIER',
    title: 'Supplier Investigation',
  },
  {
    id: 'ioc',
    label: 'IOC',
    title: 'IOC Analysis',
  },
  {
    id: 'contain',
    label: 'CONTAIN',
    title: 'Containment',
  },
  {
    id: 'vendor',
    label: 'VENDOR',
    title: 'Vendor Response',
  },
  {
    id: 'recover',
    label: 'RECOVER',
    title: 'Recovery',
  },
  {
    id: 'closure',
    label: 'CLOSURE',
    title: 'Incident Closure',
  },
]

const INITIAL_SUPPLIERS = [
  {
    id: 'northstar',
    name: 'Northstar Software',
    type: 'Software Vendor',
    status: 'compromised',
    connection: 'TRUSTED',
    package: 'Northstar Update Service',
    version: '4.8.2',
    lastUpdate: '09:02',
    risk: 'CRITICAL',
    evidence: {
      components: [
        'Northstar Update Service',
        'Telemetry Module',
        'Update Manager',
      ],
      hashes: [
        'SIM-8A42-91D0',
        'SIM-4F21-7B93',
      ],
      connections: [
        '10.20.10.15:443',
        '203.0.113.45:443',
      ],
    },
  },
  {
    id: 'cloudmesh',
    name: 'CloudMesh Systems',
    type: 'Cloud Provider',
    status: 'healthy',
    connection: 'TRUSTED',
    package: 'CloudMesh Agent',
    version: '7.2.1',
    lastUpdate: '08:15',
    risk: 'LOW',
    evidence: {
      components: [
        'CloudMesh Agent',
        'Cloud Connector',
      ],
      hashes: [
        'SIM-9D21-5A10',
      ],
      connections: [
        '10.20.10.20:443',
      ],
    },
  },
  {
    id: 'secureprint',
    name: 'SecurePrint Ltd.',
    type: 'Enterprise Software',
    status: 'investigating',
    connection: 'TRUSTED',
    package: 'SecurePrint Agent',
    version: '3.4.9',
    lastUpdate: '07:52',
    risk: 'MEDIUM',
    evidence: {
      components: [
        'SecurePrint Agent',
        'Printer Controller',
      ],
      hashes: [
        'SIM-7A11-2D81',
      ],
      connections: [
        '10.20.10.30:443',
      ],
    },
  },
  {
    id: 'datavault',
    name: 'DataVault Services',
    type: 'Backup Provider',
    status: 'healthy',
    connection: 'TRUSTED',
    package: 'DataVault Connector',
    version: '5.1.0',
    lastUpdate: '06:40',
    risk: 'LOW',
    evidence: {
      components: [
        'DataVault Connector',
        'Backup Scheduler',
      ],
      hashes: [
        'SIM-2F11-AB83',
      ],
      connections: [
        '10.20.10.40:443',
      ],
    },
  },
]

const INITIAL_SYSTEMS = [
  {
    id: 'APP-01',
    name: 'ERP-APP-01',
    ip: '10.20.10.15',
    department: 'Finance',
    state: 'suspicious',
    isolated: false,
  },
  {
    id: 'APP-02',
    name: 'ERP-APP-02',
    ip: '10.20.10.16',
    department: 'Operations',
    state: 'suspicious',
    isolated: false,
  },
  {
    id: 'WS-22',
    name: 'FIN-WS-22',
    ip: '10.20.10.50',
    department: 'Finance',
    state: 'healthy',
    isolated: false,
  },
  {
    id: 'WS-31',
    name: 'OPS-WS-31',
    ip: '10.20.10.51',
    department: 'Operations',
    state: 'healthy',
    isolated: false,
  },
]

const INITIAL_TIMELINE = [
  {
    time: '09:12:03',
    type: 'danger',
    text: 'EDR detected suspicious activity on ERP application servers.',
  },
  {
    time: '09:12:11',
    type: 'warning',
    text: 'Recently updated third-party software component identified.',
  },
  {
    time: '09:12:19',
    type: 'danger',
    text: 'ERP servers established outbound connections to an unknown external endpoint.',
  },
]

function BlueSupplyChainSimulation() {
  const navigate = useNavigate()

  const [stage, setStage] = useState('alert')
  const [suppliers, setSuppliers] = useState(
    INITIAL_SUPPLIERS
  )
  const [systems, setSystems] = useState(
    INITIAL_SYSTEMS
  )

  const [selectedSupplierId, setSelectedSupplierId] =
    useState('northstar')

  const [selectedSystemId, setSelectedSystemId] =
    useState('APP-01')

  const [activeTab, setActiveTab] =
    useState('overview')

  const [score, setScore] = useState(0)

  const [timeline, setTimeline] =
    useState(INITIAL_TIMELINE)

  const [evidence, setEvidence] = useState({
    alertReviewed: false,
    supplierInspected: false,
    packageVerified: false,
    iocIdentified: false,
    systemsCorrelated: false,
    systemsContained: false,
    vendorNotified: false,
    updateBlocked: false,
    recoveryComplete: false,
  })

  const [toast, setToast] = useState('')

  const selectedSupplier = useMemo(
    () =>
      suppliers.find(
        (supplier) =>
          supplier.id === selectedSupplierId
      ),
    [suppliers, selectedSupplierId]
  )

  const selectedSystem = useMemo(
    () =>
      systems.find(
        (system) =>
          system.id === selectedSystemId
      ),
    [systems, selectedSystemId]
  )

  const compromisedSuppliers =
    suppliers.filter(
      (supplier) =>
        supplier.status === 'compromised'
    )

  const isolatedSystems =
    systems.filter(
      (system) => system.isolated
    )

  const stageIndex = STAGES.findIndex(
    (item) => item.id === stage
  )

  const progress =
    ((stageIndex + 1) / STAGES.length) * 100

  const addTimeline = (
    text,
    type = 'info'
  ) => {
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
    }, 2400)
  }

  const reviewAlert = () => {
    if (evidence.alertReviewed) return

    setEvidence((previous) => ({
      ...previous,
      alertReviewed: true,
    }))

    setScore((previous) => previous + 100)

    addTimeline(
      'SOC analyst reviewed the supply-chain security alert.',
      'success'
    )

    notify('Alert triage completed.')

    setTimeout(() => {
      setStage('supplier')
    }, 500)
  }

  const inspectSupplier = () => {
    if (!selectedSupplier) return

    if (!evidence.supplierInspected) {
      setEvidence((previous) => ({
        ...previous,
        supplierInspected: true,
      }))

      setScore((previous) => previous + 100)

      addTimeline(
        `${selectedSupplier.name} supplier record investigated.`,
        'info'
      )

      notify(
        `${selectedSupplier.name} investigation loaded.`
      )
    }

    setActiveTab('overview')
  }

  const verifyPackage = () => {
    if (!selectedSupplier) return

    if (!evidence.packageVerified) {
      setEvidence((previous) => ({
        ...previous,
        packageVerified: true,
      }))

      setScore((previous) => previous + 125)

      addTimeline(
        `Suspicious ${selectedSupplier.package} version identified.`,
        'warning'
      )

      notify(
        'Third-party component evidence identified.'
      )
    }

    setActiveTab('package')
  }

  const investigateHashes = () => {
    if (!selectedSupplier) return

    if (!evidence.iocIdentified) {
      setEvidence((previous) => ({
        ...previous,
        iocIdentified: true,
      }))

      setScore((previous) => previous + 125)

      addTimeline(
        'Suspicious package hash correlated with the incident.',
        'warning'
      )

      notify(
        'Simulated IOC identified.'
      )
    }

    setActiveTab('hashes')
  }

  const correlateSystems = () => {
    if (!evidence.systemsCorrelated) {
      setEvidence((previous) => ({
        ...previous,
        systemsCorrelated: true,
      }))

      setScore((previous) => previous + 125)

      addTimeline(
        'ERP-APP-01 and ERP-APP-02 correlated with supplier activity.',
        'danger'
      )

      notify(
        'Affected systems correlated.'
      )
    }

    setActiveTab('systems')
  }

  const moveToContainment = () => {
    if (
      evidence.supplierInspected &&
      evidence.packageVerified &&
      evidence.iocIdentified &&
      evidence.systemsCorrelated
    ) {
      setStage('contain')
    } else {
      notify(
        'Complete the investigation before containment.'
      )
    }
  }

  const containSystems = () => {
    if (evidence.systemsContained) return

    setSystems((previous) =>
      previous.map((system) =>
        system.state === 'suspicious'
          ? {
              ...system,
              isolated: true,
            }
          : system
      )
    )

    setEvidence((previous) => ({
      ...previous,
      systemsContained: true,
    }))

    setScore((previous) => previous + 225)

    addTimeline(
      'Affected ERP systems isolated from the simulated network.',
      'success'
    )

    notify(
      'Affected systems contained.'
    )

    setTimeout(() => {
      setStage('vendor')
    }, 500)
  }

  const notifyVendor = () => {
    if (evidence.vendorNotified) return

    setEvidence((previous) => ({
      ...previous,
      vendorNotified: true,
    }))

    setScore((previous) => previous + 75)

    addTimeline(
      'Northstar Software notified of the simulated supply-chain incident.',
      'info'
    )

    notify(
      'Supplier notification sent.'
    )
  }

  const blockUpdate = () => {
    if (evidence.updateBlocked) return

    setEvidence((previous) => ({
      ...previous,
      updateBlocked: true,
    }))

    setSuppliers((previous) =>
      previous.map((supplier) =>
        supplier.id === 'northstar'
          ? {
              ...supplier,
              connection: 'BLOCKED',
            }
          : supplier
      )
    )

    setScore((previous) => previous + 125)

    addTimeline(
      'Northstar software update channel blocked in the simulated environment.',
      'success'
    )

    notify(
      'Supplier update channel blocked.'
    )
  }

  const moveToRecovery = () => {
    if (
      evidence.vendorNotified &&
      evidence.updateBlocked
    ) {
      setStage('recover')
    } else {
      notify(
        'Notify the supplier and block the update channel first.'
      )
    }
  }

  const recoverSystems = () => {
    if (evidence.recoveryComplete) return

    setSystems((previous) =>
      previous.map((system) =>
        system.isolated
          ? {
              ...system,
              state: 'recovering',
            }
          : system
      )
    )

    setEvidence((previous) => ({
      ...previous,
      recoveryComplete: true,
    }))

    setScore((previous) => previous + 150)

    addTimeline(
      'ERP services restored using a verified clean software package.',
      'success'
    )

    notify(
      'Recovery completed.'
    )

    setTimeout(() => {
      setStage('closure')
    }, 600)
  }

  const closeIncident = () => {
    const finalScore = Math.min(
      score + 75,
      1000
    )

    addTimeline(
      'Supply-chain incident response workflow completed.',
      'success'
    )

    notify(
      'Incident closed.'
    )

    setTimeout(() => {
      navigate(
        '/blue-supply-chain-report',
        {
          state: {
            report: {
              mode: 'blue',
              attack: 'supply-chain',
              incident: {
                id: 'SC-2026-001',
                name:
                  'Northbridge Software Supply-Chain Incident',
                severity: 'CRITICAL',
              },
              score: finalScore,
              suppliers,
              systems,
              timeline,
              evidence,
            },
          },
        }
      )
    }, 600)
  }

  return (
    <div className="bsc-page">

      <NetworkBackground />

      <div className="bsc-shell">

        {/* HEADER */}

        <header className="bsc-header">

          <div className="bsc-brand">

            <div className="bsc-logo">
              S
            </div>

            <div>
              <div className="bsc-brand-title">
                SENTINEL
              </div>

              <div className="bsc-brand-subtitle">
                BLUE TEAM / SUPPLY CHAIN INCIDENT RESPONSE
              </div>
            </div>

          </div>

          <div className="bsc-incident">

            <span>
              ACTIVE INCIDENT
            </span>

            <strong>
              SC-2026-001
            </strong>

            <small>
              NORTHBRIDGE HEALTH NETWORK
            </small>

          </div>

          <div className="bsc-score">

            <span>
              SOC SCORE
            </span>

            <strong>
              {score}
              <small>/1000</small>
            </strong>

          </div>

        </header>

        {/* PROGRESS */}

        <div className="bsc-progress">

          <div
            className="bsc-progress-fill"
            style={{
              width: `${progress}%`,
            }}
          />

        </div>

        {/* STAGES */}

        <div className="bsc-stagebar">

          {STAGES.map(
            (item, index) => (

              <div
                key={item.id}
                className={`bsc-stage ${
                  item.id === stage
                    ? 'active'
                    : ''
                } ${
                  index < stageIndex
                    ? 'complete'
                    : ''
                }`}
              >

                <div className="bsc-stage-number">

                  {index < stageIndex
                    ? '✓'
                    : index + 1}

                </div>

                <span>
                  {item.label}
                </span>

              </div>

            )
          )}

        </div>

        {toast && (
          <div className="bsc-toast">
            {toast}
          </div>
        )}

        {/* WORKSPACE */}

        <main className="bsc-workspace">

          {/* SUPPLIERS */}

          <aside className="bsc-panel bsc-supplier-panel">

            <div className="bsc-panel-header">

              <div>
                <span>
                  TRUSTED ECOSYSTEM
                </span>

                <h2>
                  SUPPLIERS
                </h2>
              </div>

              <div className="bsc-count">
                {compromisedSuppliers.length}
              </div>

            </div>

            <div className="bsc-supplier-list">

              {suppliers.map(
                (supplier) => (

                  <button
                    key={supplier.id}
                    className={`bsc-supplier ${
                      selectedSupplierId ===
                      supplier.id
                        ? 'selected'
                        : ''
                    }`}
                    onClick={() =>
                      setSelectedSupplierId(
                        supplier.id
                      )
                    }
                  >

                    <div
                      className={`bsc-supplier-dot ${
                        supplier.status
                      }`}
                    />

                    <div className="bsc-supplier-info">

                      <strong>
                        {supplier.name}
                      </strong>

                      <small>
                        {supplier.type}
                      </small>

                      <em>
                        {supplier.package}
                      </em>

                    </div>

                    <div
                      className={`bsc-supplier-state ${
                        supplier.connection ===
                        'BLOCKED'
                          ? 'blocked'
                          : supplier.status
                      }`}
                    >
                      {supplier.connection ===
                      'BLOCKED'
                        ? 'BLOCKED'
                        : supplier.risk}
                    </div>

                  </button>

                )
              )}

            </div>

            <div className="bsc-supplier-footer">

              <div>
                <span>
                  TRUSTED
                </span>

                <strong>
                  {
                    suppliers.filter(
                      (supplier) =>
                        supplier.connection ===
                        'TRUSTED'
                    ).length
                  }
                </strong>
              </div>

              <div>
                <span>
                  BLOCKED
                </span>

                <strong>
                  {
                    suppliers.filter(
                      (supplier) =>
                        supplier.connection ===
                        'BLOCKED'
                    ).length
                  }
                </strong>
              </div>

            </div>

          </aside>

          {/* CENTER */}

          <section className="bsc-panel bsc-main-panel">

            <div className="bsc-main-header">

              <div>

                <span>
                  BLUE TEAM / ACTIVE INVESTIGATION
                </span>

                <h1>
                  {
                    STAGES.find(
                      (item) =>
                        item.id === stage
                    )?.title
                  }
                </h1>

              </div>

              <div className="bsc-severity">
                <span />
                CRITICAL
              </div>

            </div>

            {/* ALERT */}

            {stage === 'alert' && (

              <div className="bsc-alert-view">

                <div className="bsc-alert-banner">

                  <div className="bsc-alert-icon">
                    !
                  </div>

                  <div>

                    <span>
                      SUPPLY CHAIN SECURITY ALERT
                    </span>

                    <strong>
                      Suspicious trusted-software activity detected
                    </strong>

                  </div>

                </div>

                <div className="bsc-evidence-grid">

                  <div className="bsc-evidence-card">
                    <span>
                      ALERT SOURCE
                    </span>

                    <strong>
                      Sentinel EDR
                    </strong>
                  </div>

                  <div className="bsc-evidence-card">
                    <span>
                      AFFECTED SERVERS
                    </span>

                    <strong>
                      2
                    </strong>
                  </div>

                  <div className="bsc-evidence-card">
                    <span>
                      SUPPLIER
                    </span>

                    <strong>
                      Northstar
                    </strong>
                  </div>

                  <div className="bsc-evidence-card">
                    <span>
                      EXTERNAL IOC
                    </span>

                    <strong>
                      203.0.113.45
                    </strong>
                  </div>

                </div>

                <div className="bsc-alert-details">

                  <span>
                    INCIDENT DETAILS
                  </span>

                  <p>
                    Sentinel has detected suspicious
                    activity on ERP application servers
                    shortly after a trusted third-party
                    software update was installed.
                  </p>

                  <p>
                    The SOC must determine whether the
                    supplier software is responsible and
                    contain the affected systems.
                  </p>

                </div>

                <button
                  className="bsc-primary-button"
                  onClick={reviewAlert}
                >
                  REVIEW SUPPLY CHAIN ALERT →
                </button>

              </div>

            )}

            {/* SUPPLIER */}

            {stage === 'supplier' &&
              selectedSupplier && (

                <div className="bsc-investigation">

                  <div className="bsc-selected-header">

                    <div>

                      <span>
                        SELECTED SUPPLIER
                      </span>

                      <strong>
                        {selectedSupplier.name}
                      </strong>

                      <small>
                        {selectedSupplier.type}
                      </small>

                    </div>

                    <div
                      className={`bsc-risk ${
                        selectedSupplier.risk
                      }`}
                    >
                      {
                        selectedSupplier.risk
                      }
                    </div>

                  </div>

                  <div className="bsc-tabs">

                    {[
                      [
                        'overview',
                        'OVERVIEW',
                      ],
                      [
                        'package',
                        'PACKAGE',
                      ],
                      [
                        'hashes',
                        'HASHES',
                      ],
                      [
                        'systems',
                        'SYSTEMS',
                      ],
                    ].map(
                      ([id, label]) => (

                        <button
                          key={id}
                          className={
                            activeTab ===
                            id
                              ? 'active'
                              : ''
                          }
                          onClick={() =>
                            setActiveTab(
                              id
                            )
                          }
                        >
                          {label}
                        </button>

                      )
                    )}

                  </div>

                  <div className="bsc-investigation-body">

                    {activeTab ===
                      'overview' && (

                      <div className="bsc-overview">

                        <div className="bsc-info-card">

                          <span>
                            SOFTWARE
                          </span>

                          <strong>
                            {
                              selectedSupplier.package
                            }
                          </strong>

                        </div>

                        <div className="bsc-info-card">

                          <span>
                            VERSION
                          </span>

                          <strong>
                            {
                              selectedSupplier.version
                            }
                          </strong>

                        </div>

                        <div className="bsc-info-card">

                          <span>
                            LAST UPDATE
                          </span>

                          <strong>
                            {
                              selectedSupplier.lastUpdate
                            }
                          </strong>

                        </div>

                        <div className="bsc-info-card">

                          <span>
                            TRUST STATE
                          </span>

                          <strong>
                            {
                              selectedSupplier.connection
                            }
                          </strong>

                        </div>

                        <div className="bsc-action-row">

                          <button
                            className={
                              evidence.supplierInspected
                                ? 'done'
                                : ''
                            }
                            onClick={
                              inspectSupplier
                            }
                          >
                            {evidence.supplierInspected
                              ? '✓ SUPPLIER INSPECTED'
                              : 'INSPECT SUPPLIER'}
                          </button>

                          <button
                            className={
                              evidence.packageVerified
                                ? 'done'
                                : ''
                            }
                            onClick={
                              verifyPackage
                            }
                          >
                            {evidence.packageVerified
                              ? '✓ PACKAGE VERIFIED'
                              : 'VERIFY PACKAGE'}
                          </button>

                          <button
                            className={
                              evidence.iocIdentified
                                ? 'done'
                                : ''
                            }
                            onClick={
                              investigateHashes
                            }
                          >
                            {evidence.iocIdentified
                              ? '✓ IOC IDENTIFIED'
                              : 'ANALYZE HASHES'}
                          </button>

                          <button
                            className={
                              evidence.systemsCorrelated
                                ? 'done'
                                : ''
                            }
                            onClick={
                              correlateSystems
                            }
                          >
                            {evidence.systemsCorrelated
                              ? '✓ SYSTEMS CORRELATED'
                              : 'CORRELATE SYSTEMS'}
                          </button>

                        </div>

                      </div>

                    )}

                    {activeTab ===
                      'package' && (

                      <div className="bsc-data-view">

                        <div className="bsc-data-title">
                          INSTALLED COMPONENTS
                        </div>

                        {
                          selectedSupplier
                            .evidence
                            .components
                            .map(
                              (
                                component
                              ) => (

                                <div
                                  className="bsc-data-row"
                                  key={
                                    component
                                  }
                                >

                                  <span>
                                    ◈
                                  </span>

                                  <strong>
                                    {
                                      component
                                    }
                                  </strong>

                                  <small>
                                    {
                                      component ===
                                      selectedSupplier.package
                                        ? 'SUSPICIOUS'
                                        : 'NORMAL'
                                    }
                                  </small>

                                </div>

                              )
                            )
                        }

                      </div>

                    )}

                    {activeTab ===
                      'hashes' && (

                      <div className="bsc-data-view">

                        <div className="bsc-data-title">
                          PACKAGE HASH EVIDENCE
                        </div>

                        {
                          selectedSupplier
                            .evidence
                            .hashes
                            .map(
                              (hash) => (

                                <div
                                  className="bsc-hash-row"
                                  key={hash}
                                >

                                  <span>
                                    HASH
                                  </span>

                                  <code>
                                    {hash}
                                  </code>

                                  <strong>
                                    {
                                      hash ===
                                      'SIM-8A42-91D0'
                                        ? 'SUSPICIOUS'
                                        : 'REFERENCE'
                                    }
                                  </strong>

                                </div>

                              )
                            )
                        }

                        <div className="bsc-ioc-box">

                          <span>
                            EXTERNAL IOC
                          </span>

                          <strong>
                            203.0.113.45
                          </strong>

                          <small>
                            Simulated malicious infrastructure
                          </small>

                        </div>

                      </div>

                    )}

                    {activeTab ===
                      'systems' && (

                      <div className="bsc-system-list">

                        {systems.map(
                          (system) => (

                            <button
                              key={system.id}
                              className={`bsc-system ${
                                selectedSystemId ===
                                system.id
                                  ? 'selected'
                                  : ''
                              }`}
                              onClick={() =>
                                setSelectedSystemId(
                                  system.id
                                )
                              }
                            >

                              <div
                                className={`bsc-system-dot ${
                                  system.isolated
                                    ? 'isolated'
                                    : system.state
                                }`}
                              />

                              <div>

                                <strong>
                                  {system.name}
                                </strong>

                                <small>
                                  {system.ip}
                                </small>

                              </div>

                              <span>
                                {system.isolated
                                  ? 'ISOLATED'
                                  : system.state.toUpperCase()}
                              </span>

                            </button>

                          )
                        )}

                      </div>

                    )}

                  </div>

                  <div className="bsc-investigation-footer">

                    <button
                      className="bsc-primary-button"
                      disabled={
                        !evidence.supplierInspected ||
                        !evidence.packageVerified ||
                        !evidence.iocIdentified ||
                        !evidence.systemsCorrelated
                      }
                      onClick={
                        moveToContainment
                      }
                    >
                      CONFIRM SUPPLY CHAIN SCOPE →
                    </button>

                  </div>

                </div>

              )}

            {/* IOC */}

            {stage === 'ioc' && (

              <div className="bsc-action-stage">

                <div className="bsc-stage-intro">

                  <div className="bsc-large-icon">
                    #
                  </div>

                  <div>

                    <span>
                      THREAT CORRELATION
                    </span>

                    <h2>
                      ANALYZE SUPPLY CHAIN IOCS
                    </h2>

                    <p>
                      Correlate the suspicious supplier
                      package with the external indicator
                      and affected enterprise systems.
                    </p>

                  </div>

                </div>

                <div className="bsc-ioc-grid">

                  <div>
                    <span>
                      SUPPLIER
                    </span>

                    <strong>
                      Northstar Software
                    </strong>
                  </div>

                  <div>
                    <span>
                      PACKAGE
                    </span>

                    <strong>
                      Northstar Update Service
                    </strong>
                  </div>

                  <div>
                    <span>
                      VERSION
                    </span>

                    <strong>
                      4.8.2
                    </strong>
                  </div>

                  <div>
                    <span>
                      EXTERNAL IOC
                    </span>

                    <strong>
                      203.0.113.45
                    </strong>
                  </div>

                </div>

                <button
                  className="bsc-primary-button"
                  onClick={() =>
                    setStage('contain')
                  }
                >
                  CONFIRM IOC CORRELATION →
                </button>

              </div>

            )}

            {/* CONTAIN */}

            {stage === 'contain' && (

              <div className="bsc-action-stage">

                <div className="bsc-stage-intro">

                  <div className="bsc-large-icon danger">
                    !
                  </div>

                  <div>

                    <span>
                      RESPONSE REQUIRED
                    </span>

                    <h2>
                      CONTAIN AFFECTED SYSTEMS
                    </h2>

                    <p>
                      Isolate the affected application
                      servers and stop further trust
                      propagation from the simulated
                      compromised supplier.
                    </p>

                  </div>

                </div>

                <div className="bsc-containment-list">

                  {systems
                    .filter(
                      (system) =>
                        system.state ===
                          'suspicious' ||
                        system.isolated
                    )
                    .map(
                      (system) => (

                        <div
                          className="bsc-containment-card"
                          key={system.id}
                        >

                          <div>

                            <strong>
                              {system.name}
                            </strong>

                            <span>
                              {system.ip}
                            </span>

                          </div>

                          <em>
                            {system.isolated
                              ? 'ISOLATED'
                              : 'REQUIRES ISOLATION'}
                          </em>

                        </div>

                      )
                    )}

                </div>

                <button
                  className="bsc-primary-button"
                  onClick={
                    containSystems
                  }
                >
                  ISOLATE AFFECTED SYSTEMS
                </button>

              </div>

            )}

            {/* VENDOR */}

            {stage === 'vendor' && (

              <div className="bsc-action-stage">

                <div className="bsc-stage-intro">

                  <div className="bsc-large-icon">
                    V
                  </div>

                  <div>

                    <span>
                      SUPPLIER RESPONSE
                    </span>

                    <h2>
                      SECURE THE TRUST RELATIONSHIP
                    </h2>

                    <p>
                      Notify the supplier and block the
                      affected update channel until a
                      verified clean package is available.
                    </p>

                  </div>

                </div>

                <div className="bsc-vendor-actions">

                  <div className="bsc-vendor-card">

                    <div className="bsc-vendor-card-top">

                      <span>
                        SUPPLIER NOTIFICATION
                      </span>

                      <strong>
                        {evidence.vendorNotified
                          ? 'SENT'
                          : 'PENDING'}
                      </strong>

                    </div>

                    <p>
                      Notify Northstar Software that
                      its update channel has been
                      associated with the simulated
                      incident.
                    </p>

                    <button
                      onClick={
                        notifyVendor
                      }
                      className={
                        evidence.vendorNotified
                          ? 'done'
                          : ''
                      }
                    >
                      {evidence.vendorNotified
                        ? '✓ VENDOR NOTIFIED'
                        : 'NOTIFY SUPPLIER'}
                    </button>

                  </div>

                  <div className="bsc-vendor-card">

                    <div className="bsc-vendor-card-top">

                      <span>
                        UPDATE CHANNEL
                      </span>

                      <strong>
                        {evidence.updateBlocked
                          ? 'BLOCKED'
                          : 'ACTIVE'}
                      </strong>

                    </div>

                    <p>
                      Temporarily prevent the
                      suspicious supplier update from
                      reaching enterprise systems.
                    </p>

                    <button
                      onClick={
                        blockUpdate
                      }
                      className={
                        evidence.updateBlocked
                          ? 'done'
                          : ''
                      }
                    >
                      {evidence.updateBlocked
                        ? '✓ UPDATE BLOCKED'
                        : 'BLOCK UPDATE CHANNEL'}
                    </button>

                  </div>

                </div>

                <button
                  className="bsc-primary-button"
                  disabled={
                    !evidence.vendorNotified ||
                    !evidence.updateBlocked
                  }
                  onClick={
                    moveToRecovery
                  }
                >
                  PREPARE RECOVERY →
                </button>

              </div>

            )}

            {/* RECOVERY */}

            {stage === 'recover' && (

              <div className="bsc-action-stage">

                <div className="bsc-stage-intro">

                  <div className="bsc-large-icon">
                    ↻
                  </div>

                  <div>

                    <span>
                      CLEAN SOFTWARE AVAILABLE
                    </span>

                    <h2>
                      RECOVER ENTERPRISE SYSTEMS
                    </h2>

                    <p>
                      Restore affected services using
                      a verified clean supplier package.
                    </p>

                  </div>

                </div>

                <div className="bsc-recovery-grid">

                  <div className="bsc-recovery-card">

                    <span>
                      PACKAGE
                    </span>

                    <strong>
                      Northstar Update Service
                    </strong>

                    <small>
                      Verified clean release: 4.8.3
                    </small>

                  </div>

                  <div className="bsc-recovery-card">

                    <span>
                      SIGNATURE
                    </span>

                    <strong>
                      VERIFIED
                    </strong>

                    <small>
                      Supplier signature validated
                    </small>

                  </div>

                  <div className="bsc-recovery-card">

                    <span>
                      AFFECTED SYSTEMS
                    </span>

                    <strong>
                      {isolatedSystems.length}
                    </strong>

                    <small>
                      Ready for simulated recovery
                    </small>

                  </div>

                </div>

                <button
                  className="bsc-primary-button"
                  onClick={
                    recoverSystems
                  }
                >
                  RESTORE USING VERIFIED PACKAGE →
                </button>

              </div>

            )}

            {/* CLOSURE */}

            {stage === 'closure' && (

              <div className="bsc-action-stage bsc-closure">

                <div className="bsc-success-mark">
                  ✓
                </div>

                <span>
                  RESPONSE WORKFLOW COMPLETE
                </span>

                <h2>
                  CLOSE SUPPLY CHAIN INCIDENT
                </h2>

                <p>
                  The supplier relationship was
                  investigated, affected systems were
                  contained, the update channel was
                  blocked and services were recovered.
                </p>

                <div className="bsc-final-stats">

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
                      SYSTEMS ISOLATED
                    </span>

                    <strong>
                      {isolatedSystems.length}
                    </strong>
                  </div>

                  <div>
                    <span>
                      SUPPLIERS BLOCKED
                    </span>

                    <strong>
                      {
                        suppliers.filter(
                          (supplier) =>
                            supplier.connection ===
                            'BLOCKED'
                        ).length
                      }
                    </strong>
                  </div>

                </div>

                <button
                  className="bsc-primary-button"
                  onClick={
                    closeIncident
                  }
                >
                  CLOSE INCIDENT & VIEW REPORT →
                </button>

              </div>

            )}

          </section>

          {/* TIMELINE */}

          <aside className="bsc-panel bsc-timeline-panel">

            <div className="bsc-panel-header">

              <div>
                <span>
                  SOC ACTIVITY
                </span>

                <h2>
                  INCIDENT TIMELINE
                </h2>
              </div>

              <div className="bsc-live">
                LIVE
              </div>

            </div>

            <div className="bsc-objective">

              <span>
                CURRENT OBJECTIVE
              </span>

              <strong>
                {
                  STAGES[stageIndex].title
                }
              </strong>

              <p>
                {getObjective(stage)}
              </p>

            </div>

            <div className="bsc-timeline">

              {timeline
                .slice()
                .reverse()
                .map(
                  (event, index) => (

                    <div
                      className={`bsc-event ${
                        event.type
                      }`}
                      key={`${event.time}-${index}`}
                    >

                      <div className="bsc-event-line">
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

                  )
                )}

            </div>

          </aside>

        </main>

        <footer className="bsc-footer">

          <div>
            <span className="bsc-online-dot" />
            BLUE TEAM SOC ACTIVE
          </div>

          <div>
            INCIDENT:
            <strong>
              SC-2026-001
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
      return 'Review the alert and determine whether trusted third-party software may be involved.'

    case 'supplier':
      return 'Investigate the supplier, package version, hashes and affected systems.'

    case 'ioc':
      return 'Correlate the suspicious software package with the external indicator.'

    case 'contain':
      return 'Isolate affected systems and stop further simulated propagation.'

    case 'vendor':
      return 'Notify the supplier and block the suspicious update channel.'

    case 'recover':
      return 'Restore affected systems using a verified clean software package.'

    case 'closure':
      return 'Review the response and close the supply-chain incident.'

    default:
      return ''
  }
}

export default BlueSupplyChainSimulation