import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import NetworkBackground from '../components/NetworkBackground'
import API from '../services/api'
import './RedRansomwareSimulation.css'

const MAX_SCORE = 1000

const STAGES = [
  { id: 'recon', label: 'Reconnaissance', short: 'RECON' },
  { id: 'vulnerability', label: 'Vulnerability', short: 'VULN' },
  { id: 'execution', label: 'Execution', short: 'EXEC' },
  { id: 'propagation', label: 'Propagation', short: 'MOVE' },
  { id: 'compromise', label: 'Compromise', short: 'COMP' },
  { id: 'encryption', label: 'Encryption', short: 'CRYPT' },
  { id: 'impact', label: 'Impact', short: 'IMPACT' },
]

const HOSTS = [
  {
    id: 'pc-014',
    name: 'PC-014',
    ip: '10.10.20.14',
    type: 'Workstation',
    user: 'Finance User',
    os: 'Windows 10 Enterprise',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '445', name: 'SMB', state: 'LISTENING' },
        { port: '3389', name: 'RDP', state: 'LISTENING' },
        { port: '135', name: 'RPC', state: 'LISTENING' },
      ],
      shares: ['Finance', 'Users', 'Public'],
      users: ['finance.user', 'administrator'],
      files: [
        { name: 'Budget_2026.xlsx', size: '2.4 MB' },
        { name: 'Payroll_Report.xlsx', size: '1.8 MB' },
        { name: 'Invoices.zip', size: '48 MB' },
        { name: 'Finance_Backup.db', size: '620 MB' },
      ],
    },
  },
  {
    id: 'lab-008',
    name: 'LAB-008',
    ip: '10.10.20.18',
    type: 'Workstation',
    user: 'Research User',
    os: 'Windows 10 Enterprise',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '445', name: 'SMB', state: 'LISTENING' },
        { port: '135', name: 'RPC', state: 'LISTENING' },
      ],
      shares: ['Research', 'Users'],
      users: ['research.user'],
      files: [
        { name: 'Research_Data.csv', size: '92 MB' },
        { name: 'Experiment_Results.docx', size: '4.8 MB' },
        { name: 'Research_Archive.zip', size: '380 MB' },
      ],
    },
  },
  {
    id: 'file-01',
    name: 'FILE-SRV-01',
    ip: '10.10.20.25',
    type: 'File Server',
    user: 'SYSTEM',
    os: 'Windows Server 2019',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '445', name: 'SMB', state: 'LISTENING' },
        { port: '135', name: 'RPC', state: 'LISTENING' },
        { port: '3389', name: 'RDP', state: 'LISTENING' },
      ],
      shares: ['Shared', 'Department', 'Backups'],
      users: ['administrator', 'svc-files'],
      files: [
        { name: 'Company_Shared', size: '1.8 GB' },
        { name: 'Department_Data', size: '4.2 GB' },
        { name: 'Employee_Records', size: '860 MB' },
        { name: 'Server_Backups', size: '12.4 GB' },
      ],
    },
  },
  {
    id: 'backup-01',
    name: 'BACKUP-01',
    ip: '10.10.20.30',
    type: 'Backup Server',
    user: 'SYSTEM',
    os: 'Windows Server 2019',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '445', name: 'SMB', state: 'LISTENING' },
        { port: '135', name: 'RPC', state: 'LISTENING' },
      ],
      shares: ['BackupVault', 'Snapshots'],
      users: ['backup.service'],
      files: [
        { name: 'Daily_Snapshot.bak', size: '8.2 GB' },
        { name: 'Weekly_Backup.bak', size: '21.5 GB' },
        { name: 'System_Image.wim', size: '14.7 GB' },
      ],
    },
  },
  {
    id: 'dc-01',
    name: 'DC-01',
    ip: '10.10.20.5',
    type: 'Domain Controller',
    user: 'SYSTEM',
    os: 'Windows Server 2019',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '53', name: 'DNS', state: 'LISTENING' },
        { port: '88', name: 'Kerberos', state: 'LISTENING' },
        { port: '389', name: 'LDAP', state: 'LISTENING' },
        { port: '445', name: 'SMB', state: 'LISTENING' },
      ],
      shares: ['SYSVOL', 'NETLOGON'],
      users: ['administrator', 'domain.admin'],
      files: [
        { name: 'SYSVOL', size: '220 MB' },
        { name: 'Domain_Config', size: '84 MB' },
      ],
    },
  },
  {
    id: 'hr-022',
    name: 'HR-022',
    ip: '10.10.20.22',
    type: 'Workstation',
    user: 'HR User',
    os: 'Windows 10 Enterprise',
    status: 'online',
    discovered: false,
    compromised: false,
    encrypted: false,
    details: {
      services: [
        { port: '445', name: 'SMB', state: 'LISTENING' },
        { port: '135', name: 'RPC', state: 'LISTENING' },
      ],
      shares: ['HR', 'Users'],
      users: ['hr.user'],
      files: [
        { name: 'Employee_List.xlsx', size: '1.1 MB' },
        { name: 'HR_Records.docx', size: '12 MB' },
      ],
    },
  },
]

const INITIAL_HOST_STATE = Object.fromEntries(
  HOSTS.map((host) => [
    host.id,
    {
      discovered: false,
      inspected: false,
      compromised: false,
      encrypted: false,
    },
  ])
)

const COMMANDS = {
  recon: [
    {
      command: 'discover',
      label: 'discover network',
      description: 'Discover systems in the fictional network.',
    },
    {
      command: 'inspect',
      label: 'inspect host',
      description: 'Inspect the currently selected system.',
      requiresHost: true,
    },
    {
      command: 'services',
      label: 'enumerate services',
      description: 'Display services exposed by the selected system.',
      requiresHost: true,
    },
    {
      command: 'shares',
      label: 'enumerate shares',
      description: 'Display simulated network shares.',
      requiresHost: true,
    },
  ],
  vulnerability: [
    {
      command: 'services',
      label: 'enumerate services',
      description: 'Review exposed services.',
      requiresHost: true,
    },
    {
      command: 'patch-status',
      label: 'check patch status',
      description: 'Check the fictional vulnerability state.',
      requiresHost: true,
    },
    {
      command: 'users',
      label: 'enumerate users',
      description: 'Review users configured on the selected host.',
      requiresHost: true,
    },
  ],
  execution: [
    {
      command: 'access',
      label: 'establish simulated access',
      description: 'Create a safe simulated access state.',
      requiresHost: true,
    },
    {
      command: 'inspect',
      label: 'inspect host',
      description: 'Review the compromised system.',
      requiresHost: true,
    },
  ],
  propagation: [
    {
      command: 'move',
      label: 'simulate lateral movement',
      description: 'Simulate movement to another discovered system.',
      requiresHost: true,
    },
    {
      command: 'services',
      label: 'review services',
      description: 'Review the target services.',
      requiresHost: true,
    },
  ],
  compromise: [
    {
      command: 'compromise',
      label: 'mark host compromised',
      description: 'Change the selected fictional host to compromised.',
      requiresHost: true,
    },
    {
      command: 'shares',
      label: 'review shares',
      description: 'Review accessible simulated shares.',
      requiresHost: true,
    },
  ],
  encryption: [
    {
      command: 'files',
      label: 'list files',
      description: 'Display files on the selected system.',
      requiresHost: true,
    },
    {
      command: 'encrypt',
      label: 'simulate encryption',
      description: 'Run the safe simulated encryption sequence.',
      requiresHost: true,
    },
  ],
  impact: [
    {
      command: 'impact',
      label: 'assess operational impact',
      description: 'Calculate the simulated incident impact.',
    },
  ],
}

function getStageIndex(stage) {
  return STAGES.findIndex((item) => item.id === stage)
}

function formatTime(date = new Date()) {
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function RedRansomwareSimulation() {
  const navigate = useNavigate()

  const [sessionId, setSessionId] = useState(null)
  const [stage, setStage] = useState('recon')
  const [score, setScore] = useState(0)
  const [selectedHostId, setSelectedHostId] = useState(null)

  const [hostState, setHostState] = useState(INITIAL_HOST_STATE)

  const [activeTab, setActiveTab] = useState('system')
  const [terminalHistory, setTerminalHistory] = useState([
    {
      type: 'system',
      text: 'Sentinel Red Team Simulation Console',
    },
    {
      type: 'system',
      text: 'Environment: Northbridge Health Network',
    },
    {
      type: 'system',
      text: 'All systems shown are fictional and simulated.',
    },
    {
      type: 'system',
      text: 'Type a command using the action buttons below.',
    },
  ])

  const [timeline, setTimeline] = useState([
    {
      id: 1,
      time: formatTime(),
      type: 'system',
      text: 'Simulation initialized.',
    },
  ])

  const [completedActions, setCompletedActions] = useState({})
  const [encryptionProgress, setEncryptionProgress] = useState({})
  const [impact, setImpact] = useState(null)

  const [loading, setLoading] = useState(false)
  const [starting, setStarting] = useState(true)
  const [error, setError] = useState('')

  const selectedHost = useMemo(
    () => HOSTS.find((host) => host.id === selectedHostId) || null,
    [selectedHostId]
  )

  const discoveredHosts = useMemo(
    () =>
      HOSTS.filter((host) => hostState[host.id]?.discovered),
    [hostState]
  )

  const compromisedHosts = useMemo(
    () =>
      HOSTS.filter((host) => hostState[host.id]?.compromised),
    [hostState]
  )

  const currentCommands = COMMANDS[stage] || []

  const stageIndex = getStageIndex(stage)
  const progressPercent =
    ((stageIndex + 1) / STAGES.length) * 100

  useEffect(() => {
    startSimulation()
  }, [])

  const addTimeline = (text, type = 'action') => {
    setTimeline((previous) => [
      ...previous,
      {
        id: Date.now() + Math.random(),
        time: formatTime(),
        type,
        text,
      },
    ])
  }

  const addTerminal = (text, type = 'output') => {
    setTerminalHistory((previous) => [
      ...previous,
      {
        type,
        text,
      },
    ])
  }

  const updateHost = (hostId, changes) => {
    setHostState((previous) => ({
      ...previous,
      [hostId]: {
        ...previous[hostId],
        ...changes,
      },
    }))
  }

  const startSimulation = async () => {
    try {
      setStarting(true)
      setError('')

      const response = await API.post('/api/red-ransomware/start')

      const returnedSession =
        response.data?.session_id ||
        response.data?.sessionId ||
        response.data?.session?.id

      if (returnedSession) {
        setSessionId(returnedSession)
      }

      if (response.data?.score !== undefined) {
        setScore(response.data.score)
      }

      addTerminal('Session established successfully.', 'success')
      addTimeline('Red ransomware simulation started.', 'success')
    } catch (err) {
      console.error(err)
      setError(
        err.response?.data?.message ||
          'Unable to start the ransomware simulation.'
      )
    } finally {
      setStarting(false)
    }
  }

  const performAction = async (action, extra = {}) => {
    if (!sessionId) {
      addTerminal(
        'No active simulation session is available.',
        'error'
      )
      return null
    }

    try {
      setLoading(true)
      setError('')

      const response = await API.post(
        `/api/red-ransomware/${sessionId}/action`,
        {
          action,
          stage,
          ...extra,
        }
      )

      const data = response.data || {}

      if (typeof data.score === 'number') {
        setScore(data.score)
      }

      if (data.stage) {
        setStage(data.stage)
      }

      if (data.next_stage) {
        setStage(data.next_stage)
      }

      return data
    } catch (err) {
      console.error(err)

      setError(
        err.response?.data?.message ||
          err.response?.data?.error ||
          'Simulation action failed.'
      )

      addTerminal(
        err.response?.data?.message ||
          'The simulated action could not be completed.',
        'error'
      )

      return null
    } finally {
      setLoading(false)
    }
  }

  const discoverNetwork = async () => {
    addTerminal('$ discover', 'command')
    addTerminal('Scanning fictional 10.10.20.0/24 network...')

    const data = await performAction('scan_network')

    if (data === null) return

    const discoveredIds =
      data.discovered_hosts ||
      HOSTS.map((host) => host.id)

    setHostState((previous) => {
      const next = { ...previous }

      discoveredIds.forEach((id) => {
        if (next[id]) {
          next[id] = {
            ...next[id],
            discovered: true,
          }
        }
      })

      return next
    })

    const hostsToShow =
      HOSTS.filter((host) => discoveredIds.includes(host.id))

    addTerminal(
      `${hostsToShow.length} systems discovered in the simulated network.`,
      'success'
    )

    hostsToShow.forEach((host) => {
      addTerminal(
        `${host.name}  ${host.ip}  ${host.type}`,
        'output'
      )
    })

    addTimeline(
      `Network discovery completed: ${hostsToShow.length} systems identified.`,
      'success'
    )

    setCompletedActions((previous) => ({
      ...previous,
      discover: true,
    }))

    if (!selectedHostId && hostsToShow.length > 0) {
      setSelectedHostId(hostsToShow[0].id)
    }
  }

  const inspectHost = async () => {
    if (!selectedHost) {
      addTerminal('Select a discovered host first.', 'error')
      return
    }

    addTerminal(`$ inspect ${selectedHost.name}`, 'command')

    const data = await performAction('inspect_host', {
      host_id: selectedHost.id,
    })

    if (data === null) return

    updateHost(selectedHost.id, {
      inspected: true,
    })

    setActiveTab('system')

    addTerminal(
      `Host: ${selectedHost.name}`,
      'success'
    )
    addTerminal(`IP: ${selectedHost.ip}`)
    addTerminal(`OS: ${selectedHost.os}`)
    addTerminal(`Type: ${selectedHost.type}`)
    addTerminal(`User: ${selectedHost.user}`)

    addTimeline(
      `${selectedHost.name} inspected.`,
      'action'
    )

    setCompletedActions((previous) => ({
      ...previous,
      inspect: true,
    }))
  }

  const showServices = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ services ${selectedHost.name}`,
      'command'
    )

    const data = await performAction('inspect_host', {
      host_id: selectedHost.id,
      detail: 'services',
    })

    if (data === null) return

    setActiveTab('services')

    selectedHost.details.services.forEach((service) => {
      addTerminal(
        `${service.port}/tcp  ${service.name}  ${service.state}`
      )
    })

    addTimeline(
      `Service enumeration completed on ${selectedHost.name}.`
    )

    setCompletedActions((previous) => ({
      ...previous,
      services: true,
    }))
  }

  const showShares = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ shares ${selectedHost.name}`,
      'command'
    )

    const data = await performAction('inspect_host', {
      host_id: selectedHost.id,
      detail: 'shares',
    })

    if (data === null) return

    setActiveTab('shares')

    selectedHost.details.shares.forEach((share) => {
      addTerminal(`\\\\${selectedHost.name}\\${share}`)
    })

    addTimeline(
      `Share enumeration completed on ${selectedHost.name}.`
    )

    setCompletedActions((previous) => ({
      ...previous,
      shares: true,
    }))
  }

  const showUsers = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ users ${selectedHost.name}`,
      'command'
    )

    const data = await performAction('inspect_host', {
      host_id: selectedHost.id,
      detail: 'users',
    })

    if (data === null) return

    setActiveTab('users')

    selectedHost.details.users.forEach((user) => {
      addTerminal(user)
    })

    addTimeline(
      `User enumeration completed on ${selectedHost.name}.`
    )

    setCompletedActions((previous) => ({
      ...previous,
      users: true,
    }))
  }

  const checkPatchStatus = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ patch-status ${selectedHost.name}`,
      'command'
    )

    const data = await performAction(
      'identify_vulnerability',
      {
        host_id: selectedHost.id,
      }
    )

    if (data === null) return

    addTerminal(
      'Patch state: OUTDATED',
      'warning'
    )
    addTerminal(
      'Simulated SMB vulnerability condition detected.',
      'warning'
    )
    addTerminal(
      'This environment contains no real exploit or malware.',
      'system'
    )

    addTimeline(
      `Simulated vulnerability identified on ${selectedHost.name}.`,
      'warning'
    )

    setCompletedActions((previous) => ({
      ...previous,
      'patch-status': true,
      vulnerability: true,
    }))
  }

  const establishAccess = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ access ${selectedHost.name}`,
      'command'
    )

    const data = await performAction(
      'simulate_execution',
      {
        host_id: selectedHost.id,
      }
    )

    if (data === null) return

    updateHost(selectedHost.id, {
      compromised: true,
    })

    addTerminal(
      `Simulated access established on ${selectedHost.name}.`,
      'success'
    )

    addTerminal(
      'No real system access was performed.',
      'system'
    )

    addTimeline(
      `Simulated access established on ${selectedHost.name}.`,
      'success'
    )

    setCompletedActions((previous) => ({
      ...previous,
      access: true,
      execution: true,
    }))
  }

  const simulateMovement = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ move ${selectedHost.name}`,
      'command'
    )

    const data = await performAction(
      'start_propagation',
      {
        host_id: selectedHost.id,
      }
    )

    if (data === null) return

    addTerminal(
      'Simulated lateral movement initiated.',
      'success'
    )

    addTerminal(
      'Potential reachable systems updated in the network map.'
    )

    addTimeline(
      `Simulated lateral movement from ${selectedHost.name}.`,
      'action'
    )

    setCompletedActions((previous) => ({
      ...previous,
      move: true,
      propagation: true,
    }))
  }

  const markCompromised = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ compromise ${selectedHost.name}`,
      'command'
    )

    const data = await performAction(
      'compromise_hosts',
      {
        host_id: selectedHost.id,
      }
    )

    if (data === null) return

    updateHost(selectedHost.id, {
      compromised: true,
    })

    addTerminal(
      `${selectedHost.name} marked as compromised.`,
      'success'
    )

    addTimeline(
      `${selectedHost.name} is now compromised.`,
      'danger'
    )

    setCompletedActions((previous) => ({
      ...previous,
      compromise: true,
    }))
  }

  const showFiles = () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ files ${selectedHost.name}`,
      'command'
    )

    setActiveTab('files')

    selectedHost.details.files.forEach((file) => {
      const locked =
        hostState[selectedHost.id]?.encrypted

      addTerminal(
        `${locked ? '[LOCKED]' : '[AVAILABLE]'}  ${file.name}  ${file.size}`
      )
    })
  }

  const simulateEncryption = async () => {
    if (!selectedHost) {
      addTerminal('Select a host first.', 'error')
      return
    }

    addTerminal(
      `$ encrypt ${selectedHost.name}`,
      'command'
    )

    const data = await performAction(
      'simulate_encryption',
      {
        host_id: selectedHost.id,
      }
    )

    if (data === null) return

    setEncryptionProgress((previous) => ({
      ...previous,
      [selectedHost.id]: 0,
    }))

    addTerminal(
      `Encryption simulation started on ${selectedHost.name}.`,
      'warning'
    )

    addTimeline(
      `File encryption simulation started on ${selectedHost.name}.`,
      'danger'
    )

    let progress = 0

    const interval = setInterval(() => {
      progress += 20

      setEncryptionProgress((previous) => ({
        ...previous,
        [selectedHost.id]: Math.min(progress, 100),
      }))

      if (progress >= 100) {
        clearInterval(interval)

        updateHost(selectedHost.id, {
          encrypted: true,
        })

        addTerminal(
          `${selectedHost.name}: simulated files are now LOCKED.`,
          'danger'
        )

        addTimeline(
          `${selectedHost.name} file system marked LOCKED.`,
          'danger'
        )

        setCompletedActions((previous) => ({
          ...previous,
          encrypt: true,
          encryption: true,
        }))
      }
    }, 300)
  }

  const assessImpact = async () => {
    addTerminal('$ impact', 'command')

    const data = await performAction('assess_impact')

    if (data === null) return

    const compromisedCount =
      compromisedHosts.length ||
      Object.values(hostState).filter(
        (item) => item.compromised
      ).length

    const encryptedCount =
      Object.values(hostState).filter(
        (item) => item.encrypted
      ).length

    const calculatedImpact = {
      compromised: compromisedCount,
      encrypted: encryptedCount,
      unavailable: encryptedCount,
      severity:
        encryptedCount >= 3
          ? 'CRITICAL'
          : encryptedCount >= 1
            ? 'HIGH'
            : 'MEDIUM',
    }

    setImpact(calculatedImpact)

    addTerminal(
      `Compromised systems: ${compromisedCount}`,
      'output'
    )
    addTerminal(
      `Encrypted systems: ${encryptedCount}`,
      'output'
    )
    addTerminal(
      `Operational severity: ${calculatedImpact.severity}`,
      'danger'
    )

    addTimeline(
      `Impact assessment completed: ${calculatedImpact.severity}.`,
      'danger'
    )

    setCompletedActions((previous) => ({
      ...previous,
      impact: true,
    }))

    setStage('impact')
  }

  const handleCommand = async (command) => {
    if (loading) return

    switch (command) {
      case 'discover':
        await discoverNetwork()
        break
      case 'inspect':
        await inspectHost()
        break
      case 'services':
        await showServices()
        break
      case 'shares':
        await showShares()
        break
      case 'users':
        await showUsers()
        break
      case 'patch-status':
        await checkPatchStatus()
        break
      case 'access':
        await establishAccess()
        break
      case 'move':
        await simulateMovement()
        break
      case 'compromise':
        await markCompromised()
        break
      case 'files':
        showFiles()
        break
      case 'encrypt':
        await simulateEncryption()
        break
      case 'impact':
        await assessImpact()
        break
      default:
        break
    }
  }

  const selectHost = (host) => {
    if (!hostState[host.id]?.discovered) return

    setSelectedHostId(host.id)
    setActiveTab('system')

    addTerminal(
      `Selected ${host.name} (${host.ip})`,
      'system'
    )
  }

  const completeSimulation = async () => {
    if (!sessionId) return

    try {
      setLoading(true)

      await API.post(
        `/api/red-ransomware/${sessionId}/complete`,
        {
          score,
          stage,
        }
      )

      const response = await API.get(
        `/api/red-ransomware/${sessionId}/report`
      )

      navigate('/red-ransomware-report', {
        state: {
          report: response.data?.report,
        },
      })
    } catch (err) {
      console.error(err)
      setError(
        err.response?.data?.message ||
          'Unable to generate the ransomware report.'
      )
    } finally {
      setLoading(false)
    }
  }

  if (starting) {
    return (
      <div className="rr-page">
        <NetworkBackground />

        <div className="rr-loading">
          <div className="rr-loading-card">
            <div className="rr-loading-mark">S</div>
            <div className="rr-loading-title">
              INITIALIZING SENTINEL
            </div>
            <div className="rr-loading-subtitle">
              Preparing isolated ransomware simulation environment...
            </div>
            <div className="rr-loading-bar">
              <span />
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="rr-page">
      <NetworkBackground />

      <div className="rr-shell">
        <header className="rr-header">
          <div className="rr-brand">
            <div className="rr-brand-icon">S</div>

            <div>
              <div className="rr-brand-title">
                SENTINEL
              </div>
              <div className="rr-brand-subtitle">
                RED TEAM / RANSOMWARE SIMULATION
              </div>
            </div>
          </div>

          <div className="rr-header-center">
            <div className="rr-environment">
              NORTHBRIDGE HEALTH NETWORK
            </div>

            <div className="rr-progress">
              <div className="rr-progress-track">
                <div
                  className="rr-progress-fill"
                  style={{
                    width: `${progressPercent}%`,
                  }}
                />
              </div>
            </div>
          </div>

          <div className="rr-score">
            <span>SCORE</span>
            <strong>
              {score}
              <small>/{MAX_SCORE}</small>
            </strong>
          </div>
        </header>

        {error && (
          <div className="rr-error">
            <span>{error}</span>
            <button onClick={() => setError('')}>
              ×
            </button>
          </div>
        )}

        <div className="rr-stagebar">
          {STAGES.map((item, index) => (
            <div
              key={item.id}
              className={`rr-stage ${
                item.id === stage ? 'active' : ''
              } ${
                index < stageIndex ? 'complete' : ''
              }`}
            >
              <div className="rr-stage-number">
                {index < stageIndex ? '✓' : index + 1}
              </div>
              <div className="rr-stage-label">
                {item.short}
              </div>
            </div>
          ))}
        </div>

        <main className="rr-workspace">
          {/* NETWORK */}
          <aside className="rr-panel rr-network-panel">
            <div className="rr-panel-header">
              <div>
                <span className="rr-panel-kicker">
                  ENVIRONMENT
                </span>
                <h2>NETWORK</h2>
              </div>

              <span className="rr-live">
                LIVE
              </span>
            </div>

            <div className="rr-network-summary">
              <div>
                <span>DISCOVERED</span>
                <strong>
                  {discoveredHosts.length}
                </strong>
              </div>

              <div>
                <span>COMPROMISED</span>
                <strong>
                  {compromisedHosts.length}
                </strong>
              </div>
            </div>

            <div className="rr-host-list">
              {HOSTS.map((host) => {
                const state = hostState[host.id]
                const isSelected =
                  selectedHostId === host.id

                return (
                  <button
                    key={host.id}
                    className={`rr-host ${
                      isSelected ? 'selected' : ''
                    } ${
                      state?.discovered
                        ? 'discovered'
                        : 'hidden'
                    } ${
                      state?.compromised
                        ? 'compromised'
                        : ''
                    } ${
                      state?.encrypted
                        ? 'encrypted'
                        : ''
                    }`}
                    onClick={() => selectHost(host)}
                    disabled={!state?.discovered}
                  >
                    <div className="rr-host-status">
                      <span />
                    </div>

                    <div className="rr-host-info">
                      <strong>{host.name}</strong>
                      <small>{host.ip}</small>
                      <em>{host.type}</em>
                    </div>

                    <div className="rr-host-state">
                      {state?.encrypted
                        ? 'LOCKED'
                        : state?.compromised
                          ? 'COMP'
                          : state?.discovered
                            ? 'ONLINE'
                            : 'UNKNOWN'}
                    </div>
                  </button>
                )
              })}
            </div>

            <div className="rr-network-legend">
              <span>
                <i className="online" />
                Online
              </span>
              <span>
                <i className="comp" />
                Compromised
              </span>
              <span>
                <i className="locked" />
                Locked
              </span>
            </div>
          </aside>

          {/* ACTIVE SYSTEM */}
          <section className="rr-panel rr-system-panel">
            <div className="rr-panel-header">
              <div>
                <span className="rr-panel-kicker">
                  ACTIVE SYSTEM
                </span>

                <h2>
                  {selectedHost
                    ? selectedHost.name
                    : 'NO HOST SELECTED'}
                </h2>
              </div>

              {selectedHost && (
                <div className="rr-host-header-status">
                  <span
                    className={
                      hostState[selectedHost.id]?.encrypted
                        ? 'locked'
                        : hostState[selectedHost.id]?.compromised
                          ? 'danger'
                          : 'online'
                    }
                  />
                  {hostState[selectedHost.id]?.encrypted
                    ? 'LOCKED'
                    : hostState[selectedHost.id]?.compromised
                      ? 'COMPROMISED'
                      : 'ONLINE'}
                </div>
              )}
            </div>

            {!selectedHost ? (
              <div className="rr-empty-system">
                <div className="rr-empty-icon">⌁</div>
                <h3>NO ACTIVE MACHINE</h3>
                <p>
                  Discover the network and select a
                  system from the network panel.
                </p>

                {stage === 'recon' && (
                  <button
                    className="rr-primary-button"
                    onClick={() =>
                      handleCommand('discover')
                    }
                  >
                    DISCOVER NETWORK
                  </button>
                )}
              </div>
            ) : (
              <>
                <div className="rr-system-meta">
                  <div>
                    <span>IP ADDRESS</span>
                    <strong>{selectedHost.ip}</strong>
                  </div>

                  <div>
                    <span>OPERATING SYSTEM</span>
                    <strong>{selectedHost.os}</strong>
                  </div>

                  <div>
                    <span>USER</span>
                    <strong>{selectedHost.user}</strong>
                  </div>
                </div>

                <div className="rr-tabs">
                  {[
                    ['system', 'SYSTEM'],
                    ['services', 'SERVICES'],
                    ['shares', 'SHARES'],
                    ['users', 'USERS'],
                    ['files', 'FILES'],
                  ].map(([id, label]) => (
                    <button
                      key={id}
                      className={
                        activeTab === id
                          ? 'active'
                          : ''
                      }
                      onClick={() => setActiveTab(id)}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <div className="rr-system-content">
                  {activeTab === 'system' && (
                    <div className="rr-system-overview">
                      <div className="rr-machine-visual">
                        <div className="rr-machine-screen">
                          <div className="rr-screen-top">
                            NORTHBRIDGE OS
                          </div>

                          <div className="rr-screen-grid">
                            <div>
                              <span>HOST</span>
                              <strong>
                                {selectedHost.name}
                              </strong>
                            </div>

                            <div>
                              <span>NETWORK</span>
                              <strong>
                                10.10.20.0/24
                              </strong>
                            </div>

                            <div>
                              <span>STATE</span>
                              <strong>
                                {hostState[
                                  selectedHost.id
                                ]?.encrypted
                                  ? 'LOCKED'
                                  : hostState[
                                      selectedHost.id
                                    ]?.compromised
                                    ? 'COMPROMISED'
                                    : 'NORMAL'}
                              </strong>
                            </div>

                            <div>
                              <span>ACCESS</span>
                              <strong>
                                {hostState[
                                  selectedHost.id
                                ]?.compromised
                                  ? 'ESTABLISHED'
                                  : 'NONE'}
                              </strong>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="rr-system-cards">
                        <div className="rr-info-card">
                          <span>HOST TYPE</span>
                          <strong>
                            {selectedHost.type}
                          </strong>
                        </div>

                        <div className="rr-info-card">
                          <span>SECURITY STATE</span>
                          <strong>
                            {hostState[
                              selectedHost.id
                            ]?.compromised
                              ? 'BREACHED'
                              : 'UNKNOWN'}
                          </strong>
                        </div>

                        <div className="rr-info-card">
                          <span>FILES</span>
                          <strong>
                            {selectedHost.details.files.length}
                          </strong>
                        </div>

                        <div className="rr-info-card">
                          <span>SHARES</span>
                          <strong>
                            {selectedHost.details.shares.length}
                          </strong>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 'services' && (
                    <div className="rr-data-view">
                      <div className="rr-data-heading">
                        <span>PORT</span>
                        <span>SERVICE</span>
                        <span>STATE</span>
                      </div>

                      {selectedHost.details.services.map(
                        (service) => (
                          <div
                            className="rr-data-row"
                            key={service.port}
                          >
                            <code>
                              {service.port}/tcp
                            </code>
                            <strong>
                              {service.name}
                            </strong>
                            <span className="rr-state-green">
                              {service.state}
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  )}

                  {activeTab === 'shares' && (
                    <div className="rr-object-grid">
                      {selectedHost.details.shares.map(
                        (share) => (
                          <div
                            className="rr-object-card"
                            key={share}
                          >
                            <span className="rr-folder-icon">
                              ▰
                            </span>
                            <strong>{share}</strong>
                            <small>
                              Network Share
                            </small>
                          </div>
                        )
                      )}
                    </div>
                  )}

                  {activeTab === 'users' && (
                    <div className="rr-user-list">
                      {selectedHost.details.users.map(
                        (user) => (
                          <div
                            className="rr-user-row"
                            key={user}
                          >
                            <span className="rr-user-avatar">
                              U
                            </span>
                            <div>
                              <strong>{user}</strong>
                              <small>
                                Local / simulated account
                              </small>
                            </div>
                          </div>
                        )
                      )}
                    </div>
                  )}

                  {activeTab === 'files' && (
                    <div className="rr-file-browser">
                      {selectedHost.details.files.map(
                        (file) => {
                          const locked =
                            hostState[
                              selectedHost.id
                            ]?.encrypted

                          return (
                            <div
                              className={`rr-file-row ${
                                locked
                                  ? 'locked'
                                  : ''
                              }`}
                              key={file.name}
                            >
                              <span className="rr-file-icon">
                                {locked ? '▣' : '□'}
                              </span>

                              <div>
                                <strong>
                                  {file.name}
                                </strong>
                                <small>
                                  {file.size}
                                </small>
                              </div>

                              <span>
                                {locked
                                  ? 'LOCKED'
                                  : 'AVAILABLE'}
                              </span>
                            </div>
                          )
                        }
                      )}

                      {encryptionProgress[
                        selectedHost.id
                      ] !== undefined &&
                        !hostState[
                          selectedHost.id
                        ]?.encrypted && (
                          <div className="rr-encryption-progress">
                            <div>
                              <span>
                                SIMULATED ENCRYPTION
                              </span>
                              <strong>
                                {
                                  encryptionProgress[
                                    selectedHost.id
                                  ]
                                }
                                %
                              </strong>
                            </div>

                            <div className="rr-progress-track">
                              <div
                                className="rr-progress-fill danger"
                                style={{
                                  width: `${
                                    encryptionProgress[
                                      selectedHost.id
                                    ]
                                  }%`,
                                }}
                              />
                            </div>
                          </div>
                        )}
                    </div>
                  )}
                </div>
              </>
            )}
          </section>

          {/* TIMELINE */}
          <aside className="rr-panel rr-timeline-panel">
            <div className="rr-panel-header">
              <div>
                <span className="rr-panel-kicker">
                  ACTIVITY
                </span>
                <h2>TIMELINE</h2>
              </div>

              <span className="rr-event-count">
                {timeline.length}
              </span>
            </div>

            <div className="rr-objectives">
              <span className="rr-panel-kicker">
                CURRENT OBJECTIVE
              </span>

              <strong>
                {STAGES[stageIndex]?.label}
              </strong>

              <p>
                {getObjectiveText(stage)}
              </p>
            </div>

            <div className="rr-timeline">
              {timeline
                .slice()
                .reverse()
                .map((event) => (
                  <div
                    className={`rr-event ${event.type}`}
                    key={event.id}
                  >
                    <div className="rr-event-dot" />

                    <div className="rr-event-content">
                      <span>
                        {event.time}
                      </span>
                      <p>{event.text}</p>
                    </div>
                  </div>
                ))}
            </div>
          </aside>
        </main>

        {/* TERMINAL */}
        <section className="rr-terminal-panel">
          <div className="rr-terminal-header">
            <div>
              <span className="rr-terminal-title">
                SIMULATION CONSOLE
              </span>
              <span className="rr-terminal-context">
                {selectedHost
                  ? `${selectedHost.name} / ${selectedHost.ip}`
                  : 'NETWORK CONSOLE'}
              </span>
            </div>

            <div className="rr-terminal-status">
              <span />
              SANDBOXED
            </div>
          </div>

          <div className="rr-terminal-body">
            <div className="rr-terminal-history">
              {terminalHistory.map((entry, index) => (
                <div
                  key={`${index}-${entry.text}`}
                  className={`rr-terminal-line ${entry.type}`}
                >
                  {entry.type === 'command' ? (
                    <span className="rr-terminal-prompt">
                      {entry.text}
                    </span>
                  ) : (
                    <span>{entry.text}</span>
                  )}
                </div>
              ))}

              {loading && (
                <div className="rr-terminal-line loading">
                  <span>
                    processing simulated action...
                  </span>
                </div>
              )}
            </div>

            <div className="rr-command-bar">
              <div className="rr-command-label">
                <span>$</span>
                ACTIONS
              </div>

              <div className="rr-command-buttons">
                {currentCommands.map((item) => {
                  const disabled =
                    loading ||
                    (item.requiresHost &&
                      !selectedHost)

                  return (
                    <button
                      key={item.command}
                      disabled={disabled}
                      className={`rr-command-button ${
                        completedActions[
                          item.command
                        ]
                          ? 'completed'
                          : ''
                      }`}
                      onClick={() =>
                        handleCommand(item.command)
                      }
                      title={item.description}
                    >
                      {completedActions[
                        item.command
                      ] && <span>✓</span>}
                      {item.label}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>
        </section>

        {/* FOOTER */}
        <footer className="rr-footer">
          <div className="rr-footer-status">
            <span className="rr-footer-dot" />
            SIMULATION ACTIVE
          </div>

          <div className="rr-footer-stage">
            STAGE {stageIndex + 1} / {STAGES.length}
            <strong>
              {STAGES[stageIndex]?.label}
            </strong>
          </div>

          {stage === 'impact' &&
            completedActions.impact && (
              <button
                className="rr-complete-button"
                disabled={loading}
                onClick={completeSimulation}
              >
                VIEW INCIDENT REPORT →
              </button>
            )}
        </footer>
      </div>
    </div>
  )
}

function getObjectiveText(currentStage) {
  switch (currentStage) {
    case 'recon':
      return 'Discover the simulated network and identify systems that could be relevant to the attack path.'

    case 'vulnerability':
      return 'Inspect discovered systems and identify the fictional vulnerable configuration.'

    case 'execution':
      return 'Use the simulation console to establish a safe simulated access state.'

    case 'propagation':
      return 'Use the network environment to simulate movement toward additional systems.'

    case 'compromise':
      return 'Mark reachable systems as compromised within the simulated environment.'

    case 'encryption':
      return 'Inspect the target file system and simulate the encryption event.'

    case 'impact':
      return 'Assess the operational consequences of the simulated ransomware event.'

    default:
      return 'Continue the simulation.'
  }
}

export default RedRansomwareSimulation