import React, { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './RedSupplyChainSimulation.css'

const SUPPLIERS = [
  {
    id: 'northstar',
    name: 'Northstar Software',
    type: 'ERP Software Vendor',
    status: 'COMPROMISED',
    risk: 'CRITICAL',
    package: 'Northstar Update Service v4.8.2',
    description:
      'Primary software supplier used by the organization. A simulated compromise has been detected in its update channel.',
    systems: ['ERP-APP-01', 'ERP-APP-02'],
  },
  {
    id: 'cloudmesh',
    name: 'CloudMesh Systems',
    type: 'Cloud Infrastructure',
    status: 'HEALTHY',
    risk: 'LOW',
    package: 'CloudMesh Connector v3.2.1',
    description:
      'Cloud infrastructure supplier. No suspicious activity detected.',
    systems: [],
  },
  {
    id: 'secureprint',
    name: 'SecurePrint Ltd.',
    type: 'Managed Print Services',
    status: 'INVESTIGATING',
    risk: 'MEDIUM',
    package: 'SecurePrint Agent v7.1.0',
    description:
      'Supplier is under investigation because its software is installed on several workstations.',
    systems: ['FIN-WS-22'],
  },
  {
    id: 'datavault',
    name: 'DataVault Services',
    type: 'Backup Services',
    status: 'HEALTHY',
    risk: 'LOW',
    package: 'DataVault Backup Agent v5.4.0',
    description:
      'Backup provider. No suspicious indicators have been identified.',
    systems: [],
  },
]

const SYSTEMS = [
  {
    id: 'ERP-APP-01',
    ip: '10.20.10.15',
    department: 'Finance',
    supplier: 'Northstar Software',
    status: 'SUSPICIOUS',
    process: 'northstar-update.exe',
    hash: 'SIM-8A42-91D0',
  },
  {
    id: 'ERP-APP-02',
    ip: '10.20.10.16',
    department: 'Operations',
    supplier: 'Northstar Software',
    status: 'SUSPICIOUS',
    process: 'northstar-update.exe',
    hash: 'SIM-4F21-7B93',
  },
  {
    id: 'FIN-WS-22',
    ip: '10.20.10.50',
    department: 'Finance',
    supplier: 'SecurePrint Ltd.',
    status: 'HEALTHY',
    process: 'secureprint-agent.exe',
    hash: 'SIM-2B11-65AA',
  },
  {
    id: 'OPS-WS-31',
    ip: '10.20.10.51',
    department: 'Operations',
    supplier: 'CloudMesh Systems',
    status: 'HEALTHY',
    process: 'cloudmesh-agent.exe',
    hash: 'SIM-9C31-22F1',
  },
]

const IOCS = [
  {
    type: 'IP ADDRESS',
    value: '203.0.113.45',
    description: 'Simulated external command server associated with the compromised update.',
  },
  {
    type: 'PACKAGE',
    value: 'Northstar Update Service v4.8.2',
    description: 'Simulated malicious package version distributed through the vendor channel.',
  },
  {
    type: 'HASH',
    value: 'SIM-8A42-91D0',
    description: 'Simulated package hash observed on ERP-APP-01.',
  },
  {
    type: 'HASH',
    value: 'SIM-4F21-7B93',
    description: 'Simulated package hash observed on ERP-APP-02.',
  },
]

const INITIAL_EVENTS = [
  {
    time: '09:12',
    text: 'Supplier monitoring detected an abnormal Northstar update.',
    type: 'alert',
  },
]

function RedSupplyChainSimulation() {
  const navigate = useNavigate()

  const [stage, setStage] = useState('recon')
  const [selectedSupplier, setSelectedSupplier] = useState(SUPPLIERS[0])
  const [selectedSystem, setSelectedSystem] = useState(SYSTEMS[0])
  const [activeTab, setActiveTab] = useState('overview')
  const [events, setEvents] = useState(INITIAL_EVENTS)
  const [score, setScore] = useState(0)
  const [discovered, setDiscovered] = useState(false)
  const [supplierAccess, setSupplierAccess] = useState(false)
  const [updateChannel, setUpdateChannel] = useState(false)
  const [packageTampered, setPackageTampered] = useState(false)
  const [systemsCompromised, setSystemsCompromised] = useState([])
  const [impactTriggered, setImpactTriggered] = useState(false)

  const addEvent = (text, type = 'action') => {
    setEvents((prev) => [
      ...prev,
      {
        time: new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
        text,
        type,
      },
    ])
  }

  const addScore = (points) => {
    setScore((prev) => Math.min(prev + points, 1000))
  }

  const investigateSupplier = () => {
    if (!discovered) {
      setDiscovered(true)
      addScore(100)
      addEvent(
        'Northstar Software identified as the primary suspicious supplier.',
        'success'
      )
    }

    setStage('supplier')
    setSelectedSupplier(SUPPLIERS[0])
  }

  const inspectPackage = () => {
    setActiveTab('package')

    if (!packageTampered) {
      setPackageTampered(true)
      addScore(125)
      addEvent(
        'Compromised Northstar update package identified: v4.8.2.',
        'success'
      )
    }
  }

  const establishAccess = () => {
    if (!supplierAccess) {
      setSupplierAccess(true)
      addScore(150)
      addEvent(
        'Simulated supplier-side access established through the compromised update channel.',
        'warning'
      )
    }

    setStage('access')
  }

  const compromiseSystem = (system) => {
    setSelectedSystem(system)

    if (!systemsCompromised.includes(system.id)) {
      setSystemsCompromised((prev) => [...prev, system.id])
      addScore(125)
      addEvent(
        `Simulated access established on ${system.id} (${system.ip}).`,
        'warning'
      )
    }

    setStage('propagation')
  }

  const tamperUpdate = () => {
    if (!updateChannel) {
      setUpdateChannel(true)
      addScore(150)
      addEvent(
        'Simulated update channel manipulation completed.',
        'warning'
      )
    }

    setStage('impact')
  }

  const triggerImpact = () => {
    if (!impactTriggered) {
      setImpactTriggered(true)
      addScore(150)
      addEvent(
        'Simulated downstream systems affected by the compromised supplier update.',
        'danger'
      )
    }

    setStage('complete')
  }

  const progress = useMemo(() => {
    const stages = [
      'recon',
      'supplier',
      'access',
      'propagation',
      'impact',
      'complete',
    ]

    return Math.round(
      (stages.indexOf(stage) / (stages.length - 1)) * 100
    )
  }, [stage])

  const finishSimulation = () => {
    navigate('/red-supply-chain-report', {
      state: {
        score,
        stage,
        events,
        systemsCompromised,
        supplierAccess,
        updateChannel,
        packageTampered,
        impactTriggered,
      },
    })
  }

  return (
    <div className="red-sc-page">
      <header className="red-sc-header">
        <div>
          <div className="red-sc-eyebrow">RED TEAM / SUPPLY CHAIN</div>
          <h1>Supplier Compromise Simulation</h1>
          <p>
            Simulate an attacker abusing a compromised software supplier and
            its trusted update channel.
          </p>
        </div>

        <div className="red-sc-score">
          <span>SCORE</span>
          <strong>{score}</strong>
          <small>/ 1000</small>
        </div>
      </header>

      <div className="red-sc-progress">
        <div
          className="red-sc-progress-fill"
          style={{ width: `${progress}%` }}
        />
      </div>

      <div className="red-sc-stagebar">
        {[
          ['recon', 'RECON'],
          ['supplier', 'SUPPLIER'],
          ['access', 'ACCESS'],
          ['propagation', 'PROPAGATION'],
          ['impact', 'IMPACT'],
          ['complete', 'COMPLETE'],
        ].map(([id, label]) => (
          <div
            key={id}
            className={`red-sc-stage ${
              stage === id ? 'active' : ''
            } ${
              ['recon', 'supplier', 'access', 'propagation', 'impact'].indexOf(
                id
              ) <
              ['recon', 'supplier', 'access', 'propagation', 'impact'].indexOf(
                stage
              )
                ? 'done'
                : ''
            }`}
          >
            {label}
          </div>
        ))}
      </div>

      <main className="red-sc-layout">
        {/* NETWORK / SUPPLIERS */}
        <section className="red-sc-panel red-sc-network">
          <div className="red-sc-panel-title">
            <span>SUPPLIER NETWORK</span>
            <span className="red-sc-live">● LIVE</span>
          </div>

          <div className="red-sc-supplier-list">
            {SUPPLIERS.map((supplier) => (
              <button
                key={supplier.id}
                className={`red-sc-supplier ${
                  selectedSupplier.id === supplier.id ? 'selected' : ''
                }`}
                onClick={() => setSelectedSupplier(supplier)}
              >
                <div className="red-sc-supplier-top">
                  <strong>{supplier.name}</strong>
                  <span
                    className={`red-sc-status ${supplier.status.toLowerCase()}`}
                  >
                    {supplier.status}
                  </span>
                </div>

                <small>{supplier.type}</small>

                <div className="red-sc-supplier-risk">
                  Risk: <b>{supplier.risk}</b>
                </div>
              </button>
            ))}
          </div>
        </section>

        {/* ACTIVE SYSTEM */}
        <section className="red-sc-panel red-sc-center">
          <div className="red-sc-panel-title">
            <span>ACTIVE TARGET</span>
            <span className="red-sc-target-dot">TARGET</span>
          </div>

          {stage === 'recon' ? (
            <div className="red-sc-empty-state">
              <div className="red-sc-big-icon">◎</div>
              <h2>Supplier Intelligence</h2>
              <p>
                Begin by identifying which software supplier represents the
                most valuable attack path.
              </p>

              <button
                className="red-sc-primary"
                onClick={investigateSupplier}
              >
                INVESTIGATE SUPPLIER NETWORK
              </button>
            </div>
          ) : (
            <>
              <div className="red-sc-target-card">
                <div>
                  <span className="red-sc-label">SUPPLIER</span>
                  <h2>{selectedSupplier.name}</h2>
                  <p>{selectedSupplier.description}</p>
                </div>

                <div className="red-sc-risk-box">
                  <span>RISK</span>
                  <strong>{selectedSupplier.risk}</strong>
                </div>
              </div>

              <div className="red-sc-tabs">
                {[
                  ['overview', 'OVERVIEW'],
                  ['package', 'PACKAGE'],
                  ['systems', 'SYSTEMS'],
                  ['ioc', 'IOCs'],
                ].map(([id, label]) => (
                  <button
                    key={id}
                    className={activeTab === id ? 'active' : ''}
                    onClick={() => setActiveTab(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="red-sc-inspector">
                {activeTab === 'overview' && (
                  <>
                    <div className="red-sc-info-row">
                      <span>Supplier</span>
                      <b>{selectedSupplier.name}</b>
                    </div>

                    <div className="red-sc-info-row">
                      <span>Update Package</span>
                      <b>{selectedSupplier.package}</b>
                    </div>

                    <div className="red-sc-info-row">
                      <span>Trust Relationship</span>
                      <b>ACTIVE</b>
                    </div>

                    <div className="red-sc-info-row">
                      <span>Downstream Systems</span>
                      <b>{selectedSupplier.systems.length}</b>
                    </div>

                    {stage === 'supplier' && (
                      <button
                        className="red-sc-primary"
                        onClick={inspectPackage}
                      >
                        INSPECT UPDATE PACKAGE
                      </button>
                    )}
                  </>
                )}

                {activeTab === 'package' && (
                  <div className="red-sc-package">
                    <div className="red-sc-code-block">
                      <span>PACKAGE</span>
                      <strong>Northstar Update Service v4.8.2</strong>
                    </div>

                    <div className="red-sc-code-block">
                      <span>HASH</span>
                      <strong>SIM-8A42-91D0</strong>
                    </div>

                    <div className="red-sc-code-block">
                      <span>CHANNEL</span>
                      <strong>TRUSTED UPDATE</strong>
                    </div>

                    <div className="red-sc-alert-box">
                      <b>SIMULATED FINDING</b>
                      <p>
                        Package metadata differs from the expected supplier
                        baseline. The update channel is considered compromised.
                      </p>
                    </div>

                    {stage === 'supplier' && (
                      <button
                        className="red-sc-primary"
                        onClick={establishAccess}
                      >
                        ESTABLISH SIMULATED ACCESS
                      </button>
                    )}
                  </div>
                )}

                {activeTab === 'systems' && (
                  <div className="red-sc-system-list">
                    {SYSTEMS.map((system) => (
                      <button
                        key={system.id}
                        className={`red-sc-system ${
                          selectedSystem.id === system.id ? 'selected' : ''
                        }`}
                        onClick={() => setSelectedSystem(system)}
                      >
                        <div>
                          <strong>{system.id}</strong>
                          <small>{system.ip}</small>
                        </div>

                        <span
                          className={`red-sc-status ${system.status.toLowerCase()}`}
                        >
                          {systemsCompromised.includes(system.id)
                            ? 'COMPROMISED'
                            : system.status}
                        </span>
                      </button>
                    ))}

                    {stage === 'access' && supplierAccess && (
                      <button
                        className="red-sc-primary"
                        onClick={() => compromiseSystem(selectedSystem)}
                      >
                        TARGET SELECTED SYSTEM
                      </button>
                    )}
                  </div>
                )}

                {activeTab === 'ioc' && (
                  <div className="red-sc-ioc-list">
                    {IOCS.map((ioc) => (
                      <div className="red-sc-ioc" key={ioc.value}>
                        <span>{ioc.type}</span>
                        <strong>{ioc.value}</strong>
                        <p>{ioc.description}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </section>

        {/* TIMELINE */}
        <section className="red-sc-panel red-sc-timeline">
          <div className="red-sc-panel-title">
            <span>ATTACK TIMELINE</span>
            <span>{progress}%</span>
          </div>

          <div className="red-sc-events">
            {events.map((event, index) => (
              <div className="red-sc-event" key={index}>
                <div className={`red-sc-event-dot ${event.type}`} />
                <div>
                  <span>{event.time}</span>
                  <p>{event.text}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="red-sc-objectives">
            <span>OBJECTIVES</span>

            <div className={discovered ? 'complete' : ''}>
              <i>{discovered ? '✓' : '1'}</i>
              Identify compromised supplier
            </div>

            <div className={packageTampered ? 'complete' : ''}>
              <i>{packageTampered ? '✓' : '2'}</i>
              Inspect trusted package
            </div>

            <div className={supplierAccess ? 'complete' : ''}>
              <i>{supplierAccess ? '✓' : '3'}</i>
              Establish supplier access
            </div>

            <div className={systemsCompromised.length ? 'complete' : ''}>
              <i>{systemsCompromised.length ? '✓' : '4'}</i>
              Compromise downstream system
            </div>

            <div className={updateChannel ? 'complete' : ''}>
              <i>{updateChannel ? '✓' : '5'}</i>
              Manipulate update channel
            </div>

            <div className={impactTriggered ? 'complete' : ''}>
              <i>{impactTriggered ? '✓' : '6'}</i>
              Trigger simulated impact
            </div>
          </div>
        </section>
      </main>

      {/* ACTION CONSOLE */}
      <section className="red-sc-console">
        <div className="red-sc-console-header">
          <span>ATTACK CONSOLE</span>
          <span>SIMULATION ENVIRONMENT</span>
        </div>

        <div className="red-sc-console-content">
          {stage === 'recon' && (
            <>
              <span className="prompt">$</span>
              <span>network.discover_suppliers()</span>
              <span className="console-result">
                → 4 supplier relationships discovered
              </span>
            </>
          )}

          {stage === 'supplier' && (
            <>
              <span className="prompt">$</span>
              <span>supplier.inspect("Northstar Software")</span>
              <span className="console-result">
                → suspicious update package detected
              </span>
            </>
          )}

          {stage === 'access' && (
            <>
              <span className="prompt">$</span>
              <span>channel.access("trusted-update")</span>
              <span className="console-result">
                → simulated access established
              </span>
            </>
          )}

          {stage === 'propagation' && (
            <>
              <span className="prompt">$</span>
              <span>systems.target("{selectedSystem.id}")</span>
              <span className="console-result">
                → downstream system access available
              </span>

              <button
                className="red-sc-console-action"
                onClick={tamperUpdate}
              >
                MANIPULATE UPDATE CHANNEL
              </button>
            </>
          )}

          {stage === 'impact' && (
            <>
              <span className="prompt">$</span>
              <span>impact.simulate()</span>
              <span className="console-result">
                → downstream systems affected
              </span>

              <button
                className="red-sc-console-action danger"
                onClick={triggerImpact}
              >
                TRIGGER SIMULATED IMPACT
              </button>
            </>
          )}

          {stage === 'complete' && (
            <div className="red-sc-complete">
              <div>
                <span className="red-sc-label">SIMULATION COMPLETE</span>
                <h2>Supply Chain Attack Executed</h2>
                <p>
                  The simulated supplier compromise propagated through a
                  trusted software update relationship.
                </p>
              </div>

              <div className="red-sc-final-score">
                <span>FINAL SCORE</span>
                <strong>{score}</strong>
                <small>/ 1000</small>
              </div>

              <button
                className="red-sc-primary"
                onClick={finishSimulation}
              >
                VIEW ATTACK REPORT
              </button>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

export default RedSupplyChainSimulation