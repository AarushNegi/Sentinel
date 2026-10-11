import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import './VASimulation.css'

const ASSETS = [
  { id: 'A-001', name: 'Customer Portal', hostname: 'portal.northbridge.local', ip: '10.10.1.10', env: 'Production', owner: 'Web Team', criticality: 'Critical', external: true },
  { id: 'A-002', name: 'Internal File Server', hostname: 'file-srv-01.northbridge.local', ip: '10.10.20.50', env: 'Production', owner: 'IT Ops', criticality: 'High', external: false },
  { id: 'A-003', name: 'HR Workstation Fleet', hostname: 'hr-*.northbridge.local', ip: '10.10.20.22', env: 'Production', owner: 'HR', criticality: 'Medium', external: false },
  { id: 'A-004', name: 'Dev Build Agent', hostname: 'build-01.dev.northbridge.local', ip: '10.10.30.5', env: 'Development', owner: 'Engineering', criticality: 'Medium', external: false },
  { id: 'A-005', name: 'Domain Controller', hostname: 'dc-01.northbridge.local', ip: '10.10.20.1', env: 'Production', owner: 'IT Ops', criticality: 'Critical', external: false },
]

const RAW_FINDINGS = [
  { id: 'F-001', assetId: 'A-001', title: 'Apache Log4Shell (CVE-2021-44228)', cve: 'CVE-2021-44228', severity: 'Critical', desc: 'Remote code execution via JNDI injection in Log4j 2.x. Widely exploited in the wild.', status: 'open', dueDate: '2026-07-01' },
  { id: 'F-002', assetId: 'A-002', title: 'EternalBlue SMB RCE (CVE-2017-0144)', cve: 'CVE-2017-0144', severity: 'Critical', desc: 'SMBv1 remote code execution exploited by WannaCry and NotPetya ransomware families.', status: 'open', dueDate: '2026-07-05' },
  { id: 'F-003', assetId: 'A-003', title: 'PrintNightmare (CVE-2021-34527)', cve: 'CVE-2021-34527', severity: 'High', desc: 'Windows Print Spooler RCE/LPE — allows SYSTEM-level access from standard user context.', status: 'open', dueDate: '2026-07-10' },
  { id: 'F-004', assetId: 'A-005', title: 'Zerologon (CVE-2020-1472)', cve: 'CVE-2020-1472', severity: 'Critical', desc: 'Netlogon elevation of privilege — allows domain takeover with no credentials required.', status: 'open', dueDate: '2026-06-20' },
  { id: 'F-005', assetId: 'A-004', title: 'Outdated OpenSSL (CVE-2022-0778)', cve: 'CVE-2022-0778', severity: 'High', desc: 'Infinite loop in BN_mod_sqrt() causes DoS when parsing malicious certificates.', status: 'open', dueDate: '2026-07-15' },
  { id: 'F-006', assetId: 'A-001', title: 'Missing HSTS Header', cve: null, severity: 'Medium', desc: 'HTTP Strict Transport Security not enforced — allows protocol downgrade attacks.', status: 'open', dueDate: '2026-07-20' },
  { id: 'F-007', assetId: 'A-003', title: 'Weak SMB Signing Policy', cve: null, severity: 'Medium', desc: 'SMB signing not required — enables relay attacks from MITM position.', status: 'open', dueDate: '2026-07-18' },
]

const SEVERITY_SCORE = { Critical: 80, High: 60, Medium: 35, Low: 15 }
const CRITICALITY_BONUS = { Critical: 15, High: 10, Medium: 5, Low: 0 }

function calcRiskScore(finding, asset) {
  let score = SEVERITY_SCORE[finding.severity] || 0
  score += CRITICALITY_BONUS[asset?.criticality] || 0
  if (asset?.external) score += 10
  if (finding.dueDate && new Date(finding.dueDate) < new Date()) score += 10
  return Math.min(score, 100)
}

const STAGES = ['Discover', 'Assess', 'Prioritize', 'Remediate', 'Verify']

const SEVERITY_COLOR = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' }

export default function VASimulation() {
  const navigate = useNavigate()
  const [stage, setStage] = useState(0)
  const [discoveredAssets, setDiscoveredAssets] = useState([])
  const [findings, setFindings] = useState([])
  const [tasks, setTasks] = useState({})
  const [verified, setVerified] = useState({})
  const [score, setScore] = useState(0)
  const [log, setLog] = useState([])

  const addLog = (msg) => setLog((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`])

  const discoverAssets = () => {
    setDiscoveredAssets(ASSETS)
    setScore((s) => s + 100)
    addLog(`Asset discovery complete — ${ASSETS.length} hosts identified in scope`)
    setTimeout(() => setStage(1), 600)
  }

  const assessFindings = () => {
    const scored = RAW_FINDINGS.map((f) => {
      const asset = ASSETS.find((a) => a.id === f.assetId)
      return { ...f, riskScore: calcRiskScore(f, asset) }
    })
    setFindings(scored)
    setScore((s) => s + 150)
    addLog(`Vulnerability assessment complete — ${scored.length} findings recorded`)
    setTimeout(() => setStage(2), 600)
  }

  const prioritize = () => {
    setFindings((prev) => [...prev].sort((a, b) => b.riskScore - a.riskScore))
    setScore((s) => s + 100)
    addLog('Findings sorted by risk score — critical/overdue items surfaced to top')
    setTimeout(() => setStage(3), 600)
  }

  const assignTask = (findingId, action) => {
    setTasks((prev) => ({ ...prev, [findingId]: { action, status: 'assigned', assignee: 'analyst@northbridge.local' } }))
    setScore((s) => s + 50)
    addLog(`Remediation task assigned for ${findingId}: ${action}`)
  }

  const verifyFinding = (findingId) => {
    setVerified((prev) => ({ ...prev, [findingId]: true }))
    setFindings((prev) => prev.map((f) => f.id === findingId ? { ...f, status: 'remediated' } : f))
    setScore((s) => s + 75)
    addLog(`${findingId} verified as remediated and closed`)
  }

  const allTasksAssigned = findings.length > 0 && findings.every((f) => tasks[f.id])
  const allVerified = findings.length > 0 && findings.every((f) => verified[f.id])

  const assetMap = Object.fromEntries(ASSETS.map((a) => [a.id, a]))

  return (
    <div className="va-page">
      <NetworkBackground variant="blue" />

      <header className="va-topbar">
        <button className="va-back" onClick={() => navigate('/attack-select', { state: { mode: 'blue' } })}>← Back</button>
        <div className="va-title-block">
          <span className="va-eyebrow">BLUE TEAM // TVM SIMULATION</span>
          <span className="va-title">Vulnerability Assessment</span>
        </div>
        <div className="va-score-pill">Score: <strong>{score}</strong></div>
      </header>

      <div className="va-stage-rail">
        {STAGES.map((s, i) => (
          <div key={s} className={`va-rail-step ${i < stage ? 'done' : i === stage ? 'active' : 'pending'}`}>
            <span className="va-rail-dot" />
            <span>{s}</span>
          </div>
        ))}
      </div>

      <div className="va-layout">
        <main className="va-main">

          {stage === 0 && (
            <div className="va-panel">
              <h2>Stage 1 — Asset Discovery</h2>
              <p className="va-desc">Before assessing vulnerabilities, you need to know what's in scope. Run discovery to enumerate all assets in the Northbridge Health Network environment.</p>
              <button className="va-action-btn" onClick={discoverAssets}>Run Asset Discovery</button>
            </div>
          )}

          {stage >= 1 && stage <= 4 && (
            <>
              {stage === 1 && (
                <div className="va-panel">
                  <h2>Stage 2 — Vulnerability Assessment</h2>
                  <p className="va-desc">Assets discovered. Now ingest scanner results and record findings against each asset.</p>
                  <div className="va-asset-table">
                    <div className="va-table-head">
                      <span>ID</span><span>Name</span><span>Environment</span><span>Criticality</span><span>External</span>
                    </div>
                    {discoveredAssets.map((a) => (
                      <div key={a.id} className="va-table-row">
                        <span className="va-mono">{a.id}</span>
                        <span>{a.name}</span>
                        <span>{a.env}</span>
                        <span style={{ color: SEVERITY_COLOR[a.criticality] }}>{a.criticality}</span>
                        <span>{a.external ? '🌐 Yes' : '🔒 No'}</span>
                      </div>
                    ))}
                  </div>
                  <button className="va-action-btn" onClick={assessFindings}>Import Scanner Results</button>
                </div>
              )}

              {stage === 2 && (
                <div className="va-panel">
                  <h2>Stage 3 — Prioritize Risk</h2>
                  <p className="va-desc">Review findings and sort by risk score before assigning remediation work.</p>
                  <div className="va-finding-list">
                    {findings.map((f) => (
                      <div key={f.id} className="va-finding-card">
                        <div className="va-finding-top">
                          <span className="va-mono va-finding-id">{f.id}</span>
                          <span style={{ color: SEVERITY_COLOR[f.severity] }} className="va-sev-tag">{f.severity}</span>
                          {f.cve && <span className="va-cve-tag">{f.cve}</span>}
                          <span className="va-risk-score">Risk: {f.riskScore}/100</span>
                        </div>
                        <div className="va-finding-title">{f.title}</div>
                        <div className="va-finding-asset">Asset: {assetMap[f.assetId]?.name} ({f.assetId})</div>
                        <div className="va-finding-desc">{f.desc}</div>
                      </div>
                    ))}
                  </div>
                  <button className="va-action-btn" onClick={prioritize}>Sort by Risk Score</button>
                </div>
              )}

              {stage === 3 && (
                <div className="va-panel">
                  <h2>Stage 4 — Assign Remediation Tasks</h2>
                  <p className="va-desc">Assign a remediation action to every finding. Prioritized queue is shown highest risk first.</p>
                  <div className="va-finding-list">
                    {findings.map((f) => (
                      <div key={f.id} className={`va-finding-card ${tasks[f.id] ? 'va-finding-assigned' : ''}`}>
                        <div className="va-finding-top">
                          <span className="va-mono va-finding-id">{f.id}</span>
                          <span style={{ color: SEVERITY_COLOR[f.severity] }} className="va-sev-tag">{f.severity}</span>
                          {f.cve && <span className="va-cve-tag">{f.cve}</span>}
                          <span className="va-risk-score">Risk: {f.riskScore}/100</span>
                        </div>
                        <div className="va-finding-title">{f.title}</div>
                        {tasks[f.id] ? (
                          <div className="va-task-assigned">✓ Task assigned — {tasks[f.id].action}</div>
                        ) : (
                          <div className="va-task-actions">
                            <button onClick={() => assignTask(f.id, 'Apply vendor patch immediately')}>Patch</button>
                            <button onClick={() => assignTask(f.id, 'Apply compensating control + schedule patch')}>Compensating Control</button>
                            <button onClick={() => assignTask(f.id, 'Accept risk — document exception')}>Accept Risk</button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  {allTasksAssigned && (
                    <button className="va-action-btn" onClick={() => { setScore((s) => s + 100); setStage(4); addLog('All tasks assigned — moving to verification') }}>
                      Proceed to Verify
                    </button>
                  )}
                </div>
              )}

              {stage === 4 && (
                <div className="va-panel">
                  <h2>Stage 5 — Verify & Close</h2>
                  <p className="va-desc">Confirm each finding has been remediated or accepted. Mark as verified to close.</p>
                  <div className="va-finding-list">
                    {findings.map((f) => (
                      <div key={f.id} className={`va-finding-card ${verified[f.id] ? 'va-finding-verified' : ''}`}>
                        <div className="va-finding-top">
                          <span className="va-mono va-finding-id">{f.id}</span>
                          <span style={{ color: SEVERITY_COLOR[f.severity] }} className="va-sev-tag">{f.severity}</span>
                          <span className="va-risk-score">Risk: {f.riskScore}/100</span>
                        </div>
                        <div className="va-finding-title">{f.title}</div>
                        <div className="va-task-assigned">Action: {tasks[f.id]?.action}</div>
                        {verified[f.id] ? (
                          <div className="va-verified-badge">✓ Verified & Closed</div>
                        ) : (
                          <button className="va-verify-btn" onClick={() => verifyFinding(f.id)}>Mark as Verified</button>
                        )}
                      </div>
                    ))}
                  </div>
                  {allVerified && (
                    <button className="va-action-btn va-complete-btn" onClick={() => navigate('/dashboard')}>
                      Complete Assessment → Dashboard
                    </button>
                  )}
                </div>
              )}
            </>
          )}
        </main>

        <aside className="va-log-panel">
          <div className="va-log-title">Activity Log</div>
          <div className="va-log-lines">
            {log.length === 0 && <span className="va-log-empty">Awaiting first action…</span>}
            {log.map((l, i) => <div key={i} className="va-log-line">{l}</div>)}
          </div>
        </aside>
      </div>
    </div>
  )
}