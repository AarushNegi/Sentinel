const ransomwareGuide = {
  title: 'Ransomware',

  headline:
    'WannaCry-Inspired Ransomware Incident Response',

  overview:
    'You are a Blue Team analyst responding to a ransomware outbreak affecting Northbridge Health Network. The incident is based on defensive lessons from the 2017 WannaCry attack, particularly the importance of identifying vulnerable systems, correlating endpoint activity, containing propagation, and restoring affected services. The environment is entirely fictional and all telemetry is simulated.',

  targets: [
    'Northbridge Health Network endpoints',
    'Clinical and administrative workstations',
    'Internal file servers',
    'Network segments connecting affected systems',
    'Critical services requiring recovery'
  ],

  stages: [
    {
      name: 'Alert',
      tactic:
        'Review the initial ransomware alert and determine the severity, affected systems, and indicators associated with the incident.'
    },

    {
      name: 'Endpoint Investigation',
      tactic:
        'Investigate affected endpoints and examine suspicious processes, file activity, and system telemetry.'
    },

    {
      name: 'Vulnerability Analysis',
      tactic:
        'Determine which systems are vulnerable and identify the weakness that enabled the ransomware outbreak to spread.'
    },

    {
      name: 'SIEM Correlation',
      tactic:
        'Correlate endpoint, authentication, network, and file-system events to understand the scope and timeline of the incident.'
    },

    {
      name: 'Propagation Analysis',
      tactic:
        'Identify additional affected hosts and determine how the ransomware moved through the fictional network.'
    },

    {
      name: 'Containment',
      tactic:
        'Take defensive actions to stop further propagation and isolate affected systems from the network.'
    },

    {
      name: 'Remediation',
      tactic:
        'Address vulnerable systems, remove the simulated threat, and prepare affected systems for recovery.'
    },

    {
      name: 'Recovery',
      tactic:
        'Restore affected services and validate that recovered systems are operating normally.'
    },

    {
      name: 'Incident Closure',
      tactic:
        'Verify containment, remediation, and recovery before formally closing the ransomware incident.'
    }
  ],

  tips: [
    'Start with the alert and establish the scope of the incident.',
    'Identify vulnerable systems before attempting broad containment.',
    'Use SIEM telemetry to correlate events across multiple hosts.',
    'Contain affected endpoints before the ransomware can spread further.',
    'Prioritize critical healthcare services during recovery.',
    'Verify remediation before returning systems to normal operation.',
    'This simulation uses fictional infrastructure and simulated ransomware activity.'
  ]
}

export default ransomwareGuide