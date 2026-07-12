// data/scenarios/phishing-alerts.js
export default [
  {
    id: 1000,
    rule: "Suspicious email from external domain.",
    severity: "Low",
    type: "Phishing",
    timestamp: "07/05/2026 16:25:24.706",
    status: "unassigned",
    isThreat: true,
    description: "A suspicious email was received from an external sender with an unusual top-level domain. Note from SOC Lead: this detection rule still needs fine-tuning.",
    datasource: "email",
    direction: "inbound",
    fields: {
      subject: "Inheritance Alert: Unknown Billionaire Relative Left You Their Hat Fortunes",
      sender: "eileen@trendymillineryco.me",
      recipient: "support@tryhatme.com",
      attachment: "None",
      content: "A long lost billionaire relative has left you their secret hat empire. To claim your inheritance send us your banking details immediately."
    }
  },
  {
    id: 1001,
    rule: "Email with password-protected attachment from external sender.",
    severity: "Medium",
    type: "Phishing",
    timestamp: "07/05/2026 16:27:10.112",
    status: "unassigned",
    isThreat: true,
    description: "An external sender delivered a password-protected ZIP attachment — a common technique to bypass attachment scanning.",
    datasource: "email",
    direction: "inbound",
    fields: {
      subject: "Invoice #88213 — Payment Overdue",
      sender: "billing@accounts-verify-secure.com",
      recipient: "finance@tryhatme.com",
      attachment: "Invoice_88213.zip (password: 2024)",
      content: "Please find attached your overdue invoice. Extract using the password provided and remit payment within 24 hours to avoid service suspension."
    }
  },
  {
    id: 1002,
    rule: "Email from external domain — newsletter.",
    severity: "Low",
    type: "Phishing",
    timestamp: "07/05/2026 16:29:45.301",
    status: "unassigned",
    isThreat: false,
    description: "An email was received from a domain not on the internal allow-list.",
    datasource: "email",
    direction: "inbound",
    fields: {
      subject: "Your weekly cybersecurity digest",
      sender: "newsletter@krebsonsecurity.com",
      recipient: "analyst-team@tryhatme.com",
      attachment: "None",
      content: "This week: three new CVEs affecting enterprise VPN appliances, plus our roundup of the latest ransomware trends."
    }
  },
  {
    id: 1003,
    rule: "Suspicious Parent-Child Process Relationship",
    severity: "Low",
    type: "Process",
    timestamp: "07/05/2026 16:32:12.706",
    status: "unassigned",
    isThreat: false,
    description: "A process with an uncommon parent-child relationship was detected — unrelated to the current phishing investigation.",
    datasource: "sysmon",
    direction: null,
    fields: {
      "event.code": "1",
      "host.name": "win-3451",
      "process.name": "taskhostw.exe",
      "process.pid": "3585",
      "process.parent.pid": "3653",
      "process.parent.name": "svchost.exe",
      "process.command_line": "taskhostw.exe KEYROAMING",
      "process.working_directory": "C:\\Windows\\system32\\",
      "event.action": "Process Create (rule: ProcessCreate)"
    }
  }
]