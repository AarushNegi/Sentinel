export default {
  title: 'SUPPLY CHAIN',

  headline: 'Supplier Compromise Simulation',

  overview:
    'You are a Red Team operator simulating a controlled supply chain attack against a fictional enterprise environment. Your objective is to identify a trusted software supplier, investigate its update channel, establish simulated access, reach downstream systems, manipulate the trusted update path, and observe the resulting impact. The environment is entirely fictional and all activity is simulated.',

  targets: [
    'Northstar Software supplier',
    'Northstar Update Service v4.8.2',
    'ERP-APP-01 — Finance system',
    'ERP-APP-02 — Operations system',
    'Trusted software update channel',
    'Downstream enterprise systems',
  ],

  stages: [
    {
      name: 'Reconnaissance',
      tactic:
        'Discover the available supplier relationships and identify the software supplier that provides the most valuable attack path.',
    },

    {
      name: 'Supplier Identification',
      tactic:
        'Investigate the supplier network and identify Northstar Software as the compromised supplier in the simulated environment.',
    },

    {
      name: 'Package Inspection',
      tactic:
        'Inspect the simulated software update and identify the suspicious package version and simulated indicators.',
    },

    {
      name: 'Access',
      tactic:
        'Establish simulated access through the compromised trusted update channel.',
    },

    {
      name: 'Propagation',
      tactic:
        'Use the simulated supplier relationship to reach downstream systems that consume the affected software update.',
    },

    {
      name: 'Update Channel Manipulation',
      tactic:
        'Simulate manipulation of the trusted update channel and observe how the compromise can affect connected systems.',
    },

    {
      name: 'Impact',
      tactic:
        'Trigger the simulated downstream impact and observe the resulting effect on affected systems.',
    },
  ],

  tips: [
    'Begin by mapping the supplier relationships in the environment.',

    'Identify the supplier with the most valuable downstream access.',

    'Pay attention to package versions and simulated indicators.',

    'Follow the trusted software relationship toward downstream systems.',

    'Track the attack timeline as the simulated compromise progresses.',

    'Observe how a supplier compromise can affect systems that trust the supplier.',

    'This simulation uses fictional infrastructure and simulated attack activity.',
  ],
}