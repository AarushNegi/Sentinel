export default {
  title: 'SUPPLY CHAIN',

  headline: 'Supply Chain Incident Response',

  overview:
    'You are a Blue Team analyst responding to a simulated supply chain compromise involving a trusted software supplier. Your objective is to investigate the compromised supplier, identify affected systems and indicators, contain the threat, coordinate the vendor response, and recover affected services. The environment is entirely fictional and all telemetry is simulated.',

  targets: [
    'Northstar Software supplier relationship',
    'Northstar Update Service v4.8.2',
    'ERP-APP-01 — Finance system',
    'ERP-APP-02 — Operations system',
    'Trusted software update channel',
    'Affected downstream systems',
  ],

  stages: [
    {
      name: 'Alert',
      tactic:
        'Review the supply chain alert and determine why the supplier update requires investigation.',
    },

    {
      name: 'Supplier Investigation',
      tactic:
        'Investigate the available software suppliers and identify the supplier associated with the suspicious update.',
    },

    {
      name: 'IOC Analysis',
      tactic:
        'Examine the simulated package version, hashes, update information, and external indicators associated with the compromised supplier.',
    },

    {
      name: 'Containment',
      tactic:
        'Identify affected downstream systems and contain the simulated supplier-related activity to prevent further spread.',
    },

    {
      name: 'Vendor Response',
      tactic:
        'Coordinate with the simulated software supplier and block the compromised update channel while the incident is investigated.',
    },

    {
      name: 'Recovery',
      tactic:
        'Validate affected systems, restore trusted software versions, and confirm that recovered systems are operating normally.',
    },

    {
      name: 'Incident Closure',
      tactic:
        'Verify containment, vendor response, and recovery before formally closing the simulated supply chain incident.',
    },
  ],

  tips: [
    'Start with the supplier that generated the suspicious software update.',

    'Identify which systems depend on software from the affected supplier.',

    'Use package information and simulated hashes to correlate affected systems.',

    'Investigate the update channel before assuming individual endpoints are independently compromised.',

    'Contain affected downstream systems before continuing with recovery.',

    'Coordinate the simulated vendor response and block the compromised update channel.',

    'Verify recovered systems are using trusted software before closing the incident.',

    'This simulation uses fictional infrastructure and simulated supply chain activity.',
  ],
}