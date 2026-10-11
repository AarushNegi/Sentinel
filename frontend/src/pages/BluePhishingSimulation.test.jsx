import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import BluePhishingSimulation from './BluePhishingSimulation'

const navigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal()),
  useNavigate: () => navigate,
}))

/* ---------------------- a fake of the Blue phishing API ---------------------- */

const ALERTS = [
  { id: 'ALR-1', title: 'Impossible-travel sign-in (corporate VPN)', severity: 'high', confidence: 45,
    source: 'Identity Protection', rule: 'Impossible travel', entity: 'd.v@acme.test',
    detected_at: '2026-10-10 09:10:00', description: 'Two sign-ins from different countries.',
    selected: false, triage: null, status: 'new' },
  { id: 'ALR-2', title: 'Suspicious email delivered to Finance', severity: 'medium', confidence: 78,
    source: 'Secure Email Gateway', rule: 'Phishing heuristics', entity: 'd.o@acme.test',
    detected_at: '2026-10-10 09:02:00', description: 'Gateway flagged a suspicious message.',
    selected: false, triage: null, status: 'new' },
  { id: 'ALR-3', title: 'Internal port scan detected', severity: 'medium', confidence: 88,
    source: 'Network IDS', rule: 'Port scan', entity: 'SEC-SCAN-01',
    detected_at: '2026-10-10 09:20:00', description: 'One host probed many addresses.',
    selected: false, triage: null, status: 'new' },
]

const act = (action, label, extra = {}) => ({
  action, label, group: 'investigation', targets: null, confirm: false, impact: null,
  enabled: true, done: false, reason: null, ...extra,
})
const target = (id, label, extra = {}) => ({ id, label, enabled: true, done: false, reason: null, ...extra })

const USER = { id: 'u1', name: 'Daniel Okafor', role: 'Finance Manager', department: 'Finance',
  email: 'd.o@acme.test', endpoint: 'FIN-WS-1', is_primary: true, mailbox: 'delivered',
  session: 'unknown', account: 'normal', endpoint_state: 'online', mfa: 'default', mailbox_rule: 'unknown' }

const OBJECTIVES = [
  ['triage', 'Triage every alert in the queue'], ['open', 'Open the reported phishing incident'],
  ['email', 'Inspect the email, headers and links'], ['ioc', 'Analyse indicators with the IOC tools'],
  ['users', 'Investigate users, endpoints and logs'], ['contain', 'Contain the threat and verify it'],
  ['remediate', 'Remediate and verify recovery'], ['close', 'Submit the closure decision'],
].map(([id, label]) => ({ id, label, done: false }))

function makeView(overrides = {}) {
  return {
    success: true, session_id: 'sess1', resumed: false, elapsed_seconds: 0,
    generation: { source: 'ollama', model: 'qwen3:4b', fallback: false, fallback_reason: null },
    incident: { id: 'PHISH-2026-123', open: false, title: 'No incident selected', severity: 'MEDIUM',
      severity_source: 'gateway', type: 'Phishing incident', status: 'triage',
      detected_at: '2026-10-10 09:02:00', summary: 'Select an alert in the queue to begin.',
      difficulty: 'medium', affected_user_count: 0 },
    alerts: ALERTS, email: { opened: false, available: false }, users: [], indicators: [], evidence: [],
    timeline: [{ clock: '09:44:00', tick: 0, kind: 'system', message: 'Email gateway generated phishing alert' }],
    events: [], assessment: null, objectives: OBJECTIVES, log_sources: ['auth', 'mailbox'],
    state: {}, stage: 'alert', score: 0, max_score: 1000,
    score_breakdown: { categories: [{ id: 'evidence', label: 'Evidence collection', earned: 0, max: 200 }],
      penalty_total: 0, penalties: [] },
    status: 'in_progress', closed: false, outcome: null,
    available_actions: [
      act('select_alert', 'Open alert', { group: 'triage',
        targets: ALERTS.map((a) => target(a.id, a.title)) }),
      act('open_email', 'Open email', { enabled: false, reason: 'Select the reported alert in the queue and open the incident first.' }),
    ],
    ...overrides,
  }
}

const EMAIL_OPENED = {
  opened: true, available: true, sender_name: 'Cobalt Payroll Service',
  sender_email: 'billing@cobalt-billing.test', recipient: 'd.o@acme.test',
  subject: 'Action required: verify your payroll profile', sent_at: '2026-10-10 09:02:00',
  gateway: { score: 78, verdict: 'Suspicious' }, greeting: 'Hello Daniel,',
  paragraphs: ['We are upgrading our payroll platform.', 'Verify within 24 hours.'],
  signature: 'Cobalt Payroll Security',
  links: [{ id: 'LINK-1', label: 'Verify profile', display_url: 'https://cobalt.test/review' }],
  attachment: { id: 'ATT-1', filename: 'Statement.docm', kind: 'docm', size_kb: 88 }, has_attachment: true,
}

const ev = (id, title, category, extra = {}) => ({
  id, title, category, source_artifact: 'Mail gateway', entity: null, related: [],
  content: { summary: `${title} summary`, fields: [['Field', 'Value']], columns: [], rows: [], verdict: null },
  preservable: false, preserved: false, discovered_at: '2026-10-10T09:45:00+00:00',
  provenance: { action: 'open_email', target: null, tick: 1 }, ...extra,
})

const incidentView = (overrides = {}) => makeView({
  incident: { ...makeView().incident, open: true, title: 'Suspicious email: Action required', status: 'open',
    target: { name: 'Daniel Okafor' }, affected_user_count: 1 },
  alerts: ALERTS.map((a) => (a.id === 'ALR-2'
    ? { ...a, selected: true, detail: 'The gateway delivered the message with a banner.', incident_alert: true }
    : a)),
  email: EMAIL_OPENED, users: [USER], stage: 'email', score: 62,
  evidence: [ev('EV-EMAIL', 'Original message captured', 'email', { preservable: true, related: ['EV-HEADERS'] }),
    ev('EV-HEADERS', 'Email authentication analysis', 'header', { provenance: { action: 'analyze_headers', target: null, tick: 2 } })],
  available_actions: [
    act('select_alert', 'Open alert', { group: 'triage', targets: ALERTS.map((a) => target(a.id, a.title, { done: a.id === 'ALR-2' })) }),
    act('triage_alert', 'Triage alert', { group: 'triage', targets: [target('ALR-2', 'Suspicious email')] }),
    act('open_email', 'Open email', { enabled: false, done: true }),
    act('view_raw_headers', 'View raw headers'),
    act('analyze_headers', 'Authentication analysis'),
    act('inspect_header_field', 'Inspect header field', { targets: [
      target('from', 'From'), target('reply_to', 'Reply-To'), target('return_path', 'Return-Path'), target('received', 'Received') ] }),
    act('reveal_link', 'Reveal link target', { targets: [target('LINK-1', 'Verify profile')] }),
    act('inspect_url', 'Analyse link destination', { targets: [target('LINK-1', 'Verify profile')] }),
    act('inspect_attachment', 'Analyse attachment', { targets: [target('ATT-1', 'Statement.docm')] }),
    act('search_siem', 'Search SIEM', { targets: [target('proxy_dns', 'DNS and web proxy activity'),
      target('mail_delivery', 'Mail delivery to recipients', { done: true })] }),
    act('ioc_lookup', 'Run IOC lookup', { targets: [
      target('IND-LURE-DOMAIN:domain_reputation', 'Domain reputation · secure.lure.test'),
      target('IND-LURE-DOMAIN:dns_analysis', 'DNS analysis · secure.lure.test') ] }),
    ...['analyze_auth_logs', 'investigate_user', 'investigate_endpoint'].map((n) =>
      act(n, { analyze_auth_logs: 'Analyse sign-in logs', investigate_user: 'Investigate user', investigate_endpoint: 'Investigate endpoint' }[n],
        { targets: [target('u1', 'Daniel Okafor')] })),
    act('quarantine_email', 'Quarantine email', { group: 'containment', confirm: true,
      impact: 'Removes the message from this mailbox and stores it in quarantine.',
      targets: [target('u1', 'Daniel Okafor')] }),
    act('block_indicator', 'Block indicator', { group: 'containment', confirm: true,
      impact: 'Blocks this indicator at the gateways for everyone.',
      targets: [target('IND-LURE-DOMAIN', 'secure.lure.test')] }),
    act('revoke_sessions', 'Revoke sessions', { group: 'containment', confirm: true, impact: 'Signs the user out.',
      targets: [target('u1', 'Daniel Okafor', { enabled: false, reason: "Analyse this user's sign-in logs before acting on their account." })] }),
    act('reset_account', 'Reset credentials', { group: 'remediation', confirm: true, impact: 'Forces a password reset.',
      targets: [target('u1', 'Daniel Okafor', { enabled: false, reason: "Analyse this user's sign-in logs before acting on their account." })] }),
    act('verify_containment', 'Verify containment', { group: 'verification', enabled: false, reason: 'Take at least one response action before verifying.' }),
    act('verify_remediation', 'Verify remediation', { group: 'verification', enabled: false, reason: 'Take at least one response action before verifying.' }),
    act('close_incident', 'Close incident', { group: 'closure', enabled: false, reason: 'Verify containment before closing the incident.' }),
  ],
  ...overrides,
})

let calls
function mockApi(handlers) {
  calls = []
  globalThis.fetch = vi.fn(async (url, options = {}) => {
    const path = String(url).replace('http://127.0.0.1:5000', '')
    const body = options.body ? JSON.parse(options.body) : null
    calls.push({ path, method: options.method || 'GET', body })
    const handler = handlers.find((h) => path.startsWith(h.path) && (!h.when || h.when(body)))
    if (!handler) throw new Error(`unexpected request ${path} ${JSON.stringify(body)}`)
    const { status = 200, json } = await handler.reply(body, path)
    return { ok: status < 400, status, json: async () => json }
  })
}
const actionCalls = () => calls.filter((c) => c.path.endsWith('/action')).map((c) => c.body)

const renderPage = () => render(<MemoryRouter><BluePhishingSimulation /></MemoryRouter>)

const NOTES_KEY = 'sentinel_blue_notes_sess1'
const PREFS_KEY = 'sentinel_blue_guide_v1'
const seedNotes = (extra = {}) => localStorage.setItem(NOTES_KEY, JSON.stringify(extra))
const seedPrefs = (extra = {}) => localStorage.setItem(PREFS_KEY, JSON.stringify({ seen: {}, ...extra }))
const seeAllTips = () => seedPrefs({ seen: { 'tip-alerts': true, 'tip-email': true, 'tip-activity': true, 'tip-contain': true, 'tip-fix': true } })

beforeEach(() => {
  localStorage.setItem('token', 'test-token')
  seeAllTips()
  navigate.mockReset()
})
afterEach(() => {
  vi.restoreAllMocks()
  localStorage.clear()
})

const ACTION = '/api/blue-phishing/sess1/action'
const HINT = '/api/blue-phishing/sess1/hint'
const noHint = { path: HINT, reply: () => ({ json: { success: true, hint: null, source: 'builtin' } }) }
const startWith = (view, extra = []) => mockApi([{ path: '/api/blue-phishing/start', reply: () => ({ status: 200, json: view }) }, noHint, ...extra])
const startOpened = (extra = []) => startWith(incidentView(), extra)
const actionReply = (view) => ({ path: ACTION, reply: () => ({ json: view }) })
// Land on a given step (the page remembers the step per session).
const at = (stepId) => seedNotes({ stepId })
const withEvidence = (...items) => incidentView({ evidence: [...incidentView().evidence, ...items] })
const next = (name) => screen.getByRole('button', { name: new RegExp(`^Next: ${name}`) })

/* ---------------------------- loading and errors ---------------------------- */

describe('start-up', () => {
  it('shows a loading state, then the first step', async () => {
    let release
    mockApi([{ path: '/api/blue-phishing/start', reply: () => new Promise((r) => { release = () => r({ status: 201, json: makeView() }) }) }, noHint])
    renderPage()
    expect(screen.getByText(/Generating a unique phishing incident/)).toBeInTheDocument()
    release()
    expect(await screen.findByRole('heading', { name: 'An alert arrives' })).toBeInTheDocument()
    expect(screen.getByText(/AI-generated scenario/)).toBeInTheDocument()
    expect(calls[0].body.generator).toBe('ai')
  })

  it('tells the user when the built-in fallback scenario is active', async () => {
    startWith(makeView({ generation: { source: 'template', model: null, fallback: true, fallback_reason: 'ollama_unavailable' } }))
    renderPage()
    expect(await screen.findByText(/Sentinel is using its built-in scenario generator because the local AI model \(Ollama\) is not running/)).toBeInTheDocument()
  })

  it('shows an error with retry and offline options when start fails', async () => {
    mockApi([{ path: '/api/blue-phishing/start', reply: () => ({ status: 500, json: { success: false, error: 'Unable to start the Blue Team simulation.' } }) }])
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to start the Blue Team simulation.')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /built-in scenario/i })).toBeInTheDocument()
  })

  it('never renders hidden scenario answers', async () => {
    at('email')
    startWith(incidentView())
    const { container } = renderPage()
    await screen.findByText('We are upgrading our payroll platform.')
    expect(container.textContent).not.toMatch(/ground_truth|critical_evidence|required_response|alert_truth/)
  })

  it('resumes at the first unfinished step when nothing was saved', async () => {
    startWith(incidentView({ evidence: [ev('EV-FIELD-from', 'Sender field', 'header')], alerts: ALERTS.map((a) => ({ ...a, selected: true, triage: 'monitor' })) }))
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Check the link' })).toBeInTheDocument()
  })
})

/* ---------------------------- one screen, one task --------------------------- */

describe('one screen, one task', () => {
  it('shows a single alert, a simple progress label and no other panels', async () => {
    startWith(makeView())
    renderPage()
    expect(await screen.findByRole('heading', { name: 'An alert arrives' })).toBeInTheDocument()
    expect(screen.getByText(/^Step 1 of \d+$/)).toBeInTheDocument()
    expect(screen.getByText('Suspicious email delivered to Finance')).toBeInTheDocument()
    expect(screen.queryByText('Internal port scan detected')).toBeNull()        // one alert at a time
    expect(screen.queryByRole('complementary')).toBeNull()                       // no side panels
    expect(screen.queryByRole('button', { name: /Back/ })).toBeNull()
  })

  it('has a header with the status and a threat indicator, and no list of phases', async () => {
    startWith(makeView())
    renderPage()
    await screen.findByRole('heading', { name: 'An alert arrives' })
    expect(screen.getByText('Waiting')).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: /steps/i })).toBeNull()
  })

  it('shows an escalating threat when the attacker has acted', async () => {
    at('email')
    startWith(incidentView({ timeline: [...makeView().timeline, { clock: '09:50:00', tick: 5, kind: 'attacker', message: 'Attacker created a forwarding rule' }] }))
    renderPage()
    expect(await screen.findByText('Threat is escalating')).toBeInTheDocument()
  })

  it('goes back and forward without losing progress, remembering the step', async () => {
    at('email')
    startWith(withEvidence(ev('EV-FIELD-from', 'Sender field', 'header')), [actionReply(incidentView())])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /^Next: Check the link/ }))
    expect(await screen.findByRole('heading', { name: 'Check the link' })).toBeInTheDocument()
    expect(JSON.parse(localStorage.getItem(NOTES_KEY)).stepId).toBe('link')
    await userEvent.click(screen.getByRole('button', { name: '← Back' }))
    expect(await screen.findByRole('heading', { name: 'Inspect the email' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Clues \(3\)/ })).toBeInTheDocument()
  })

  it('opens at the saved step after a reload', async () => {
    at('decide')
    startWith(incidentView())
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Decide what happened' })).toBeInTheDocument()
  })
})

/* -------------------------------- step 1: alerts ----------------------------- */

describe('alerts', () => {
  const statefulAlerts = () => {
    let alerts = ALERTS.map((a) => ({ ...a }))
    return { path: ACTION, reply: (body) => {
      if (body.action === 'select_alert') alerts = alerts.map((a) => (a.id === body.target ? { ...a, selected: true, detail: `Detail for ${a.id}.`, ...(a.id === 'ALR-2' ? { incident_alert: true } : {}) } : a))
      if (body.action === 'triage_alert') alerts = alerts.map((a) => (a.id === body.target ? { ...a, triage: body.params.disposition } : a))
      return { json: makeView({ alerts }) }
    } }
  }

  it('reads an alert, then decides how urgent it is, one alert at a time', async () => {
    startWith(makeView(), [statefulAlerts()])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Investigate alert' }))
    expect(actionCalls()).toEqual([{ action: 'select_alert', target: 'ALR-2' }])
    expect(await screen.findByText('Detail for ALR-2.')).toBeInTheDocument()
    expect(screen.getByText(/about the suspicious email/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Investigate now' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'triage_alert', target: 'ALR-2', params: { disposition: 'investigate_now' } })
    expect(await screen.findByText('Impossible-travel sign-in (corporate VPN)')).toBeInTheDocument()   // moved on
    expect(screen.getByText('Alert 2 of 3')).toBeInTheDocument()
  })

  it('stays locked until every alert has a decision, then offers the next step', async () => {
    startWith(makeView(), [statefulAlerts()])
    renderPage()
    expect(await screen.findByRole('button', { name: /^Next: Inspect the email/ })).toBeDisabled()
    expect(screen.getByText('Make a decision for every alert to continue.')).toBeInTheDocument()
    for (let i = 0; i < 3; i += 1) {
      await userEvent.click(await screen.findByRole('button', { name: 'Investigate alert' }))
      await userEvent.click(await screen.findByRole('button', { name: 'Monitor' }))
    }
    expect(await screen.findByText('All 3 alerts reviewed.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Next: Inspect the email/ })).toBeEnabled()
  })

  it('explains severity as a short tooltip, not a wall of text', async () => {
    startWith(makeView())
    renderPage()
    expect(await screen.findByText('Medium')).toHaveAttribute('title', 'Worth investigating; the risk is not yet fully known.')
  })
})

/* -------------------------------- step 2: email ----------------------------- */

describe('inspect the email', () => {
  it('asks the analyst to open the held email first', async () => {
    at('email')
    startWith(incidentView({ email: { ...EMAIL_OPENED, opened: false, links: undefined, paragraphs: undefined, attachment: undefined } }), [actionReply(incidentView())])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Open the email' }))
    expect(actionCalls()).toEqual([{ action: 'open_email' }])
  })

  it('shows the message and invites a click on the sender, never linking out', async () => {
    at('email')
    startOpened()
    const { container } = renderPage()
    expect(await screen.findByText('We are upgrading our payroll platform.')).toBeInTheDocument()
    expect(screen.getByText(/click the sender line/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Sender inspector' })).toBeNull()
    expect(container.querySelector('a[href]')).toBeNull()
  })

  it('opens a sender inspector on click and reveals evidence only when asked', async () => {
    at('email')
    startWith(incidentView({ evidence: [] }), [actionReply(withEvidence(ev('EV-FIELD-from', 'Sender address', 'header', {
      content: { summary: 'From field.', fields: [], columns: [], rows: [], verdict: 'The display name does not match the sending domain.' } })))])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /Cobalt Payroll Service <billing@cobalt-billing\.test>/ }))
    const inspector = within(screen.getByRole('region', { name: 'Sender inspector' }))
    expect(inspector.getByText('cobalt-billing.test')).toBeInTheDocument()
    expect(inspector.queryByText(/does not match/)).toBeNull()
    expect(next('Check the link')).toBeDisabled()
    await userEvent.click(inspector.getByRole('button', { name: 'Compare with the real organisation' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'inspect_header_field', target: 'from' })
    expect((await screen.findAllByText('The display name does not match the sending domain.')).length).toBeGreaterThan(0)
    await waitFor(() => expect(next('Check the link')).toBeEnabled())
  })

  it('records a verdict with brief, non-judgemental feedback', async () => {
    at('email')
    startWith(withEvidence(ev('EV-FIELD-from', 'Sender address', 'header')))
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /Cobalt Payroll Service <billing/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Looks suspicious' }))
    expect(screen.getByText(/Noted as suspicious/)).toBeInTheDocument()
    expect(JSON.parse(localStorage.getItem(NOTES_KEY)).verdicts.sender).toBe('suspicious')
    expect(actionCalls()).toHaveLength(0)                                    // an opinion, not an action
  })

  it('nudges back to the sender when a link is clicked too early', async () => {
    at('email')
    startOpened()
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Verify profile' }))
    expect(screen.getByText(/Links are checked in a moment/)).toBeInTheDocument()
    expect(actionCalls()).toHaveLength(0)
  })
})

/* ---------------------------- steps 3-5: link, file, security ---------------- */

describe('link, attachment and email security', () => {
  it('compares the words in the email with where the link goes, without visiting', async () => {
    at('link')
    startWith(incidentView(), [actionReply(incidentView())])
    renderPage()
    const inspector = within(await screen.findByRole('region', { name: 'Link inspector' }))
    expect(inspector.getByText('Hidden until you look')).toBeInTheDocument()
    await userEvent.click(inspector.getByRole('button', { name: 'Reveal where it really goes' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'reveal_link', target: 'LINK-1' })
    expect(inspector.getByText(/never opened/)).toBeInTheDocument()
  })

  it('shows the real destination once revealed, then offers the sandbox check and a verdict', async () => {
    at('link')
    const revealed = withEvidence(ev('EV-LINKTARGET-LINK-1', 'Link target', 'url', { content: { summary: 'Where it points.',
      fields: [['Actual target', 'https://login.evil.test/x'], ['Actual domain', 'login.evil.test']], columns: [], rows: [], verdict: 'The target is not the vendor site.' } }))
    startWith(revealed, [actionReply(revealed)])
    renderPage()
    expect((await screen.findAllByText('https://login.evil.test/x')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('The target is not the vendor site.').length).toBeGreaterThan(0)
    await userEvent.click(screen.getByRole('button', { name: 'Check it in the sandbox' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'inspect_url', target: 'LINK-1' })
    await userEvent.click(screen.getByRole('button', { name: 'Looks suspicious' }))
    expect(screen.getByText(/Noted as suspicious/)).toBeInTheDocument()
  })

  it('only includes the attachment step when the email has an attachment', async () => {
    at('link')
    startWith(incidentView())
    const { unmount } = renderPage()
    await screen.findByRole('heading', { name: 'Check the link' })
    expect(screen.getByRole('button', { name: /^Next: Check the attachment/ })).toBeInTheDocument()
    unmount()
    at('link')
    startWith(incidentView({ email: { ...EMAIL_OPENED, attachment: null, has_attachment: false } }))
    renderPage()
    await screen.findByRole('heading', { name: 'Check the link' })
    expect(screen.getByRole('button', { name: /^Next: Review email security/ })).toBeInTheDocument()
  })

  it('opens the attachment only in a simulated sandbox', async () => {
    at('attachment')
    startWith(incidentView(), [actionReply(incidentView())])
    renderPage()
    expect(await screen.findByText('Statement.docm')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Open in the sandbox' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'inspect_attachment', target: 'ATT-1' })
    expect(screen.getByText(/never downloaded or run/)).toBeInTheDocument()
  })

  it('runs the email security checks and hides raw headers until asked', async () => {
    at('security')
    startWith(incidentView({ evidence: [] }), [actionReply(incidentView())])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Run the security checks' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'analyze_headers' })
    expect(screen.getByText('Advanced: raw email headers')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Where do replies go?' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'inspect_header_field', target: 'reply_to' })
  })

  it('stays locked on the security step until the checks have run', async () => {
    at('security')
    startWith(incidentView({ evidence: [] }))
    renderPage()
    expect(await screen.findByRole('button', { name: /^Next: Investigate the indicator/ })).toBeDisabled()
  })
})

/* ------------------------------- step 6: indicator --------------------------- */

describe('investigate the indicator', () => {
  const indicator = { id: 'IND-LURE-DOMAIN', type: 'domain', value: 'secure.lure.test', label: 'Link destination', blocked: false }
  const result = ev('EV-IOC-IND-LURE-DOMAIN-domain_reputation', 'Domain Reputation: secure.lure.test', 'ioc', { entity: 'IND-LURE-DOMAIN', related: ['EV-HEADERS'],
    content: { summary: 'Reputation lookup.', fields: [['Reputation', 'MALICIOUS']], columns: [], rows: [], verdict: 'Registered two days ago and reported as phishing.' } })

  it('investigates the chosen indicator through the server', async () => {
    at('indicator')
    startWith(incidentView({ indicators: [indicator] }), [actionReply(incidentView({ indicators: [indicator] }))])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /Investigate: Check reputation/ }))
    expect(actionCalls().at(-1)).toEqual({ action: 'ioc_lookup', target: 'IND-LURE-DOMAIN:domain_reputation' })
  })

  it('shows what was found, the connected clues and an optional verdict', async () => {
    at('indicator')
    startWith(incidentView({ indicators: [indicator], evidence: [...incidentView().evidence, result] }))
    renderPage()
    expect((await screen.findAllByText('Registered two days ago and reported as phishing.')).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Email authentication analysis' }).length).toBeGreaterThan(0)   // connected clue
    await userEvent.click(screen.getByRole('button', { name: 'Looks malicious' }))
    expect(screen.getByText(/Noted as suspicious/)).toBeInTheDocument()
  })

  it('only offers indicators the investigation has discovered', async () => {
    at('indicator')
    startWith(incidentView())
    renderPage()
    expect(await screen.findByText(/No indicators found yet/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).toBeNull()
  })
})

/* ------------------------------- step 7: activity ---------------------------- */

describe("check the employee's activity", () => {
  const rows = [
    { id: 'LOG-0001', ts: '2026-10-10 08:52:11', source: 'auth', user_id: 'u1', user: 'd.o@acme.test', event_type: 'SignIn',
      src_ip: '10.20.4.11', outcome: 'success', device: 'Managed laptop', detail: 'Interactive sign-in, MFA approved', collected: false },
    { id: 'LOG-0002', ts: '2026-10-10 09:16:00', source: 'mailbox', user_id: 'u1', user: 'd.o@acme.test', event_type: 'InboxRuleCreated',
      src_ip: '198.51.100.7', outcome: 'success', device: 'Exchange Online', detail: "Rule 'sync' forwards all mail externally", collected: false },
  ]
  const queryHandler = () => ({ path: '/api/blue-phishing/sess1/query', reply: (body) => {
    const f = body?.filters || {}
    let out = rows
    if (body?.source) out = out.filter((r) => r.source === body.source)
    if (f.search) out = out.filter((r) => r.detail.toLowerCase().includes(f.search))
    return { json: { success: true, rows: out, total: out.length, truncated: false } }
  } })
  const open = async (extra = []) => {
    at('activity')
    startWith(incidentView(), [queryHandler(), ...extra])
    renderPage()
    await screen.findByRole('heading', { name: "Check the employee's activity" })
  }

  it('shows events in time order, anchored by the arrival of the email', async () => {
    await open()
    await screen.findByText('2 events shown.')
    const items = screen.getAllByRole('listitem').map((li) => li.textContent).filter((t) => /SignIn|InboxRule|email arrived/i.test(t))
    expect(items[0]).toMatch(/SignIn/)
    expect(items[1]).toMatch(/The suspicious email arrived/)
    expect(items[2]).toMatch(/InboxRuleCreated/)
  })

  it('runs the matching check and narrows the events', async () => {
    await open([actionReply(incidentView())])
    await userEvent.click(await screen.findByRole('button', { name: 'Check recent sign-ins' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'analyze_auth_logs', target: 'u1' })
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith('/query')).at(-1).body.source).toBe('auth'))
    expect(await screen.findByText('1 event shown.')).toBeInTheDocument()
  })

  it('expands an event, saves it as a clue and filters on request', async () => {
    await open([actionReply(incidentView())])
    await userEvent.click(await screen.findByRole('button', { name: /InboxRuleCreated/ }))
    expect(screen.getByText("Rule 'sync' forwards all mail externally")).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save as a clue' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'collect_log', target: 'LOG-0002' })
    await userEvent.type(screen.getByLabelText('Search the events'), 'forwards')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filter' }))
    expect(await screen.findByText('1 event shown.')).toBeInTheDocument()
  })

  it('explains an empty result honestly and reports a failed search', async () => {
    at('activity')
    let fail = false
    startWith(incidentView(), [{ path: '/api/blue-phishing/sess1/query', reply: () => (fail
      ? { status: 400, json: { success: false, error: 'Unknown log source.' } }
      : { json: { success: true, rows: [], total: 0, truncated: false } }) }])
    renderPage()
    expect(await screen.findByText(/does not prove the account is safe/)).toBeInTheDocument()
    fail = true
    await userEvent.type(screen.getByLabelText('Search the events'), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filter' }))
    expect(await screen.findByText('Unknown log source.')).toBeInTheDocument()
  })

  it('shows the server reason when a check is blocked', async () => {
    at('activity')
    const view = incidentView()
    view.available_actions = view.available_actions.map((a) => (a.action === 'analyze_auth_logs'
      ? { ...a, targets: [target('u1', 'Daniel Okafor', { enabled: false, reason: 'Open the suspicious email first.' })] } : a))
    startWith(view, [queryHandler()])
    renderPage()
    const button = await screen.findByRole('button', { name: 'Check recent sign-ins' })
    expect(button).toBeDisabled()
    expect(button).toHaveAttribute('title', 'Open the suspicious email first.')
  })
})

/* ------------------------------ steps 8-11: decisions ------------------------ */

describe('decide, stop the threat, fix and verify', () => {
  const contained = () => incidentView({ users: [{ ...USER, mailbox: 'quarantined' }], score: 120 })

  it('records the classification and severity as a real decision', async () => {
    at('decide')
    startWith(incidentView(), [actionReply(incidentView({ assessment: { classification: 'credential_compromise', severity: 'high' } }))])
    renderPage()
    expect(await screen.findByRole('button', { name: 'Record my decision' })).toBeDisabled()
    await userEvent.click(screen.getByRole('radio', { name: /An account was taken over/ }))
    await userEvent.click(screen.getByRole('button', { name: 'High' }))
    await userEvent.click(screen.getByRole('button', { name: 'Record my decision' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'set_assessment', params: { classification: 'credential_compromise', severity: 'high' } })
    expect(await screen.findByText(/You can change it until you close the case/)).toBeInTheDocument()
  })

  it('shows only relevant actions as simple cards', async () => {
    at('contain')
    startOpened()
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Quarantine the email' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Block an address' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Clean a device' })).toBeNull()
    expect(next('Fix the damage')).toBeEnabled()                         // a response is the student's choice
  })

  it('confirms with the real target, sends confirm only after approval and shows the backend outcome', async () => {
    at('contain')
    startOpened([actionReply(contained())])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Quarantine for Daniel Okafor' }))
    const dialog = screen.getByRole('dialog', { name: 'Quarantine this email?' })
    expect(within(dialog).getByText('Daniel Okafor')).toBeInTheDocument()
    expect(within(dialog).getByText(/stores it in quarantine/)).toBeInTheDocument()
    expect(actionCalls()).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm Quarantine' }))
    expect(actionCalls()).toEqual([{ action: 'quarantine_email', target: 'u1', params: { confirm: true } }])
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText('Email quarantined')).toBeInTheDocument()
  })

  it('cancelling or pressing Escape sends nothing', async () => {
    at('contain')
    startOpened()
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Block secure.lure.test' }))
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByRole('button', { name: 'Quarantine for Daniel Okafor' }))
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(actionCalls()).toHaveLength(0)
  })

  it('disables an action whose prerequisite is unmet and says why', async () => {
    at('contain')
    startOpened()
    renderPage()
    const revoke = await screen.findByRole('button', { name: 'Revoke sessions: Daniel Okafor' })
    expect(revoke).toBeDisabled()
    expect(revoke).toHaveAttribute('title', "Analyse this user's sign-in logs before acting on their account.")
  })

  it('explains a refused action in plain language with the penalty', async () => {
    at('contain')
    const view = incidentView()
    view.available_actions = view.available_actions.map((a) => (a.action === 'revoke_sessions' ? { ...a, targets: [target('u1', 'Daniel Okafor')] } : a))
    startWith(view, [{ path: ACTION, reply: () => ({ status: 400, json: { ...view, success: false, error: "Analyse this user's sign-in logs before acting on their account.", penalty_points: 10 } }) }])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke sessions: Daniel Okafor' }))
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm Revoke' }))
    expect(await screen.findByText('You cannot complete this step yet')).toBeInTheDocument()
    expect(screen.getByText(/Score penalty: −10/)).toBeInTheDocument()
  })

  it('offers related-message search and evidence copies as cards', async () => {
    at('contain')
    const view = withEvidence(ev('EV-RULE', 'Mailbox rule', 'user', { preservable: true }))
    view.available_actions = view.available_actions.map((a) => (a.action === 'search_siem'
      ? { ...a, targets: a.targets.map((t) => ({ ...t, done: false })) } : a))
    startWith(view, [actionReply(view)])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Search mailboxes' }))
    expect(actionCalls().at(-1)).toEqual({ action: 'search_siem', target: 'mail_delivery' })
    expect(screen.getByRole('heading', { name: 'Save evidence copies' })).toBeInTheDocument()
  })

  it('keeps fixing separate from stopping', async () => {
    at('fix')
    startOpened()
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Reset the password' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Quarantine the email' })).toBeNull()
  })

  it('verifies with the backend and shows what is missing', async () => {
    at('verify')
    const verified = { ...incidentView(), verification: { kind: 'containment', complete: false, lines: ['Mailboxes cleared of the message: 1/2'] }, message: 'Verification found gaps.' }
    verified.available_actions = verified.available_actions.map((a) => (['verify_containment', 'verify_remediation'].includes(a.action) ? { ...a, enabled: true, reason: null } : a))
    startWith(verified, [actionReply(verified)])
    renderPage()
    expect(await screen.findByRole('button', { name: /^Next: Who was affected/ })).toBeDisabled()
    await userEvent.click(screen.getAllByRole('button', { name: 'Run this check' })[0])
    expect(actionCalls().at(-1)).toEqual({ action: 'verify_containment' })
    expect(await screen.findByText('Something is missing')).toBeInTheDocument()
    expect(screen.getAllByText('Mailboxes cleared of the message: 1/2').length).toBeGreaterThan(0)
    expect(screen.queryByText('Containment verified')).toBeNull()
    expect(screen.getByRole('button', { name: 'Go back and fix it' })).toBeInTheDocument()
  })
})

/* --------------------------------- closing the case --------------------------- */

describe('close the case', () => {
  const closable = () => {
    const v = incidentView({ assessment: { classification: 'credential_compromise', severity: 'high' } })
    v.available_actions = v.available_actions.map((a) => (a.action === 'close_incident' ? { ...a, enabled: true, reason: null } : a))
    return v
  }

  it('asks who was affected, then the cause, then closes with proof', async () => {
    at('affected')
    const closed = { ...closable(), status: 'completed', closed: true, outcome: 'contained', score: 900 }
    startWith(closable(), [actionReply(closed),
      { path: '/api/blue-phishing/sess1/complete', reply: () => ({ json: { success: true, report_id: 'r1' } }) },
      { path: '/api/blue-phishing/sess1/report', reply: () => ({ json: { success: true, report: REPORT } }) }])
    renderPage()
    await userEvent.click(await screen.findByRole('checkbox', { name: /^Daniel Okafor/ }))
    await userEvent.click(screen.getByRole('button', { name: /^Next: How did it happen/ }))
    expect(screen.getByRole('button', { name: /^Next: Prove it/ })).toBeDisabled()
    await userEvent.click(screen.getByRole('radio', { name: /A phishing link stole a password/ }))
    await userEvent.click(screen.getByRole('radio', { name: /^None/ }))
    await userEvent.click(screen.getByRole('radio', { name: 'Yes, the evidence was saved' }))
    await userEvent.click(screen.getByRole('button', { name: /^Next: Prove it/ }))
    expect(screen.getByRole('button', { name: 'Close the case' })).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /Email authentication analysis/ }))
    await userEvent.type(screen.getByLabelText('In your own words, what happened?'), 'A phishing link stole a password and the account was reset.')
    await userEvent.click(screen.getByRole('button', { name: 'Close the case' }))
    expect(actionCalls()).toHaveLength(0)                                   // confirmation first
    const dialog = screen.getByRole('dialog', { name: 'Close this case?' })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm Close case' }))
    const body = actionCalls()[0]
    expect(body.action).toBe('close_incident')
    expect(body.params).toMatchObject({ classification: 'credential_compromise', severity: 'high', root_cause: 'phishing_link_credential_theft',
      residual_risk: 'none', evidence_preserved: true, affected_user_ids: ['u1'], supporting_evidence_ids: ['EV-HEADERS'] })
    expect(body.params.confirm).toBeUndefined()
    expect(await screen.findByRole('heading', { name: 'Threat contained' })).toBeInTheDocument()
  })

  it('will not close without a recorded decision', async () => {
    at('close')
    startWith(incidentView())
    renderPage()
    expect(await screen.findByText(/Go back to "Decide what happened"/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Close the case' })).toBeDisabled()
  })
})

/* ----------------------------------- debrief ---------------------------------- */

const REPORT = {
  report_id: 'r1', score: 900, mode: 'blue', attack: 'phishing',
  evaluation: {
    classification: { correct: true }, successful_actions: [{ label: 'Quarantine email' }],
    incorrect_decisions: [{ code: 'blocked_legitimate', points: 50, message: 'Blocked the supplier domain.' }],
    missed_evidence: [{ id: 'EV-X', title: 'Mailbox forwarding rule' }], missed_indicators: [],
    containment: { missing: [] }, remediation: { verified: true },
  },
  timeline: [{ clock: '09:44:00', kind: 'analyst', message: 'Opened the email' }],
  debrief: { ground_truth_timeline: [{ time: '09:00', text: 'The attacker sent the lure.' }], ai_commentary: 'Good containment work overall.' },
  score_breakdown: { categories: [{ id: 'evidence', label: 'Evidence collection', earned: 150, max: 200, detail: 'Found most clues.' }] },
}

describe('mission debrief', () => {
  const closedView = (extra = {}) => ({ ...incidentView(), status: 'completed', closed: true, outcome: 'contained', score: 900,
    score_breakdown: { categories: [], penalty_total: 0, penalties: [] }, ...extra })
  const reportApi = [
    { path: '/api/blue-phishing/sess1/complete', reply: () => ({ json: { success: true, report_id: 'r1' } }) },
    { path: '/api/blue-phishing/sess1/report', reply: () => ({ json: { success: true, report: REPORT } }) }]

  it('builds the debrief from the saved report, with a rating and what really cost points', async () => {
    startWith(closedView(), reportApi)
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Threat contained' })).toBeInTheDocument()
    expect(screen.getByLabelText('Mission rating S')).toBeInTheDocument()
    expect(await screen.findByText('Quarantine email')).toBeInTheDocument()
    expect(screen.getByText(/−50 Blocked the supplier domain\./)).toBeInTheDocument()
    expect(screen.getByText(/Good containment work overall/)).toBeInTheDocument()
  })

  it('reveals missed clues and the decision timeline only on request', async () => {
    startWith(closedView(), reportApi)
    renderPage()
    await screen.findByText('Quarantine email')
    expect(screen.queryByText('Mailbox forwarding rule')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Review missed clues' }))
    expect(screen.getByText('Mailbox forwarding rule')).toBeInTheDocument()
    expect(screen.getByText('Inspect decision timeline')).toBeInTheDocument()
  })

  it('replays with a brand-new session and opens the full report', async () => {
    startWith(closedView(), reportApi)
    renderPage()
    await screen.findByText('Quarantine email')
    await userEvent.click(screen.getByRole('button', { name: 'View the full report' }))
    expect(navigate).toHaveBeenCalledWith('/outcome', { state: { reportId: 'r1', report: REPORT } })
    await userEvent.click(screen.getByRole('button', { name: 'Replay incident' }))
    await waitFor(() => expect(calls.filter((c) => c.path === '/api/blue-phishing/start').at(-1).body).toEqual({ generator: 'ai', restart: true }))
  })

  it('shows an honest message if the report cannot be loaded', async () => {
    startWith(closedView(), [{ path: '/api/blue-phishing/sess1/complete', reply: () => ({ status: 500, json: { error: 'Unable to complete.' } }) }])
    renderPage()
    expect(await screen.findByText('Unable to complete.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View the full report' })).toBeDisabled()
  })
})

/* ------------------------------ clues, hints and help ------------------------- */

describe('clues, hints and help', () => {
  it('opens the clue tray on request with source and time, and closes with Escape', async () => {
    at('email')
    startOpened()
    renderPage()
    await screen.findByText('We are upgrading our payroll platform.')
    await userEvent.click(screen.getByRole('button', { name: /^Clues \(2\)/ }))
    const tray = within(screen.getByRole('dialog', { name: 'Your clues' }))
    expect(tray.getByText('Original message captured')).toBeInTheDocument()
    expect(tray.getAllByText(/Mail gateway · found at/).length).toBeGreaterThan(0)
    await userEvent.click(tray.getByRole('button', { name: /Email authentication analysis/ }))
    expect(document.querySelector('[data-evidence-id="EV-HEADERS"]')).not.toBeNull()
    await userEvent.click(tray.getByRole('tab', { name: 'What happened' }))
    expect(tray.getByText('Email gateway generated phishing alert')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('reveals hints one at a time using the built-in text when the model is unavailable', async () => {
    at('email')
    startOpened()
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Need a hint?' }))
    expect(screen.queryByText(/Hint 1/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Show hint 1' }))
    expect(await screen.findByText(/Hint 1 — Where to look/)).toBeInTheDocument()
    expect(screen.queryByText(/Hint 2/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Show hint 2' }))
    await userEvent.click(screen.getByRole('button', { name: 'Show hint 3' }))
    expect(await screen.findByText(/Hint 3 — Why it matters/)).toBeInTheDocument()
    expect(screen.getByText('That is all the help for this step.')).toBeInTheDocument()
    expect(actionCalls()).toHaveLength(0)                                    // hints complete nothing
  })

  it('uses the AI mentor hint from the server when there is one', async () => {
    at('email')
    mockApi([{ path: '/api/blue-phishing/start', reply: () => ({ json: incidentView() }) },
      { path: HINT, reply: (body) => ({ json: { success: true, hint: 'Look closely at who the message says it is from.', source: 'ai', level: body.level } }) }])
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Need a hint?' }))
    await userEvent.click(screen.getByRole('button', { name: 'Show hint 1' }))
    expect(await screen.findByText(/Look closely at who the message says it is from\./)).toBeInTheDocument()
    expect(screen.getByText(/\(AI mentor\)/)).toBeInTheDocument()
    expect(calls.find((c) => c.path === HINT).body).toMatchObject({ level: 1, step: 'email' })
  })

  it('never puts the verdict in a built-in hint', async () => {
    at('email')
    startOpened()
    const { container } = renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Need a hint?' }))
    for (const n of [1, 2, 3]) await userEvent.click(await screen.findByRole('button', { name: `Show hint ${n}` }))
    const text = container.querySelector('.bg-hint-panel').textContent
    expect(text).not.toMatch(/cobalt-billing|is malicious|is a phishing/i)
  })

  it('shows a first-time tip once and remembers it', async () => {
    seedPrefs({ seen: {} })
    startWith(makeView())
    const { unmount } = renderPage()
    expect(await screen.findByRole('note', { name: 'Your mission.' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: "Got it, let's start" }))
    expect(screen.queryByRole('note')).toBeNull()
    expect(JSON.parse(localStorage.getItem(PREFS_KEY)).seen['tip-alerts']).toBe(true)
    unmount()
    startWith(makeView())
    renderPage()
    await screen.findByRole('heading', { name: 'An alert arrives' })
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('explains a term from a small ? with a short answer and an optional deeper one', async () => {
    at('email')
    startWith(incidentView({ evidence: [ev('EV-FIELD-from', 'x', 'header')] }))
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /Cobalt Payroll Service <billing/ }))
    const q = screen.getByRole('button', { name: 'What is Sender domain?' })
    await userEvent.click(q)
    const dialog = screen.getByRole('dialog', { name: 'What is Sender domain?' })
    expect(within(dialog).getByText(/after the @ sign/)).toBeInTheDocument()
    expect(within(dialog).getByText('Learn more')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(document.activeElement).toBe(q)
  })

  it('opens the glossary from Help and only one overlay at a time', async () => {
    at('email')
    startOpened()
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Help' }))
    await userEvent.click(screen.getByRole('button', { name: 'Phishing' }))
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect(screen.getByRole('dialog', { name: 'What is Phishing?' })).toBeInTheDocument()
  })

  it('asks before leaving and leaves only on confirmation', async () => {
    at('email')
    startOpened()
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Exit' }))
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Stay' }))
    expect(navigate).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Exit' }))
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Exit Investigation' }))
    expect(navigate).toHaveBeenCalledWith('/dashboard')
  })

  it('has an optional sound toggle that is off by default', async () => {
    at('email')
    startOpened()
    renderPage()
    const toggle = await screen.findByRole('button', { name: 'Sound off' })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    await userEvent.click(toggle)
    expect(screen.getByRole('button', { name: 'Sound on' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('says clearly when the server cannot be reached', async () => {
    at('email')
    startOpened([{ path: ACTION, reply: () => { throw new Error('offline') } }])
    vi.spyOn(console, 'error').mockImplementation(() => {})
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: /Cobalt Payroll Service <billing/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Compare with the real organisation' }))
    expect(await screen.findByText('Sentinel could not reach the server')).toBeInTheDocument()
  })
})
