const ransomwareGuide = {
  title: 'Ransomware',

  headline:
    'WannaCry-Inspired Ransomware Attack Simulation',

  overview:
    'You are operating as a Red Team analyst simulating a ransomware intrusion against Northbridge Health Network. This exercise is based on the documented characteristics of the 2017 WannaCry incident, including exploitation of vulnerable systems, rapid propagation, and disruption through file encryption. The environment is entirely fictional and uses simulated hosts, users, telemetry, and infrastructure.',

  targets: [
    'Northbridge Health Network',
    'Unpatched Windows workstation fleet',
    'Clinical and administrative endpoints',
    'Internal file server infrastructure',
    'Shared network resources'
  ],

  stages: [
    {
      name: 'Reconnaissance',
      tactic:
        'Review the fictional network environment and identify systems that may be susceptible to the simulated ransomware campaign.'
    },

    {
      name: 'Vulnerability Discovery',
      tactic:
        'Analyze the available system information and identify hosts with the simulated vulnerability associated with the WannaCry case study.'
    },

    {
      name: 'Initial Execution',
      tactic:
        'Initiate the simulated ransomware execution against a selected vulnerable host within the controlled Sentinel environment.'
    },

    {
      name: 'Propagation',
      tactic:
        'Observe how the simulated ransomware attempts to spread from the initially affected host to other vulnerable systems on the fictional network.'
    },

    {
      name: 'Host Compromise',
      tactic:
        'Track systems that become compromised as the simulated ransomware propagates through the environment.'
    },

    {
      name: 'File Encryption',
      tactic:
        'Trigger the simulated encryption phase and observe the effect on fictional files and shared resources.'
    },

    {
      name: 'Impact',
      tactic:
        'Assess operational disruption across the affected Northbridge Health Network systems.'
    },

    {
      name: 'Operation Complete',
      tactic:
        'Review the final attack telemetry, affected systems, and simulated operational impact.'
    }
  ],

  tips: [
    'Prioritize vulnerable systems during reconnaissance.',
    'Understand how unpatched systems contribute to ransomware propagation.',
    'Monitor the number of affected hosts as the simulation progresses.',
    'Track attack telemetry at every stage.',
    'Evaluate operational impact rather than focusing only on individual machines.',
    'This simulation uses fictional infrastructure and does not execute real ransomware.'
  ]
}

export default ransomwareGuide