// utils/irEngine.js
// Pure logic for the Incident Response simulator: which events occur given the
// analyst's actions, SIEM search, host state, scoring, and metrics.

export const LEVEL = { clean: 0, suspicious: 1, compromised: 2, encrypted: 3 }
export const LEVEL_NAME = ['clean', 'suspicious', 'compromised', 'encrypted']
export const PTS = { best: 10, risky: 5, wrong: 0 }

const t = (h, m) => h * 60 + m

export const fmt = (m) =>
  `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`

// Turn completed actions into the active response state.
export function deriveState(actionsDone) {
  const s = { isolated: {}, disabled: {}, c2Blocked: null }
  for (const a of actionsDone) {
    const e = a.effect
    if (!e) continue
    const when = a.effectiveAt ?? a.at // an action only takes effect when it finishes
    if (e.type === 'isolate' && s.isolated[e.host] == null) s.isolated[e.host] = when
    if (e.type === 'disable' && s.disabled[e.user] == null) s.disabled[e.user] = when
    if (e.type === 'c2' && s.c2Blocked == null) s.c2Blocked = when
  }
  return s
}

// Events visible at `clock`, after removing anything the analyst prevented.
export function computeEvents(events, clock, state) {
  const byId = Object.fromEntries(events.map((e) => [e.id, e]))
  const memo = new Map()
  const occurs = (e) => {
    if (memo.has(e.id)) return memo.get(e.id)
    let ok = true
    if (e.needs) ok = e.needs.every((id) => occurs(byId[id]))
    if (ok && e.via && state.isolated[e.via] != null && state.isolated[e.via] <= e.at) ok = false
    if (ok && e.hostBlocked && state.isolated[e.host] != null && state.isolated[e.host] <= e.at) ok = false
    if (ok && e.usesCreds && state.disabled[e.user] != null && state.disabled[e.user] <= e.at) ok = false
    if (ok && e.c2 && state.c2Blocked != null && state.c2Blocked <= e.at) ok = false
    memo.set(e.id, ok)
    return ok
  }
  return events.filter((e) => e.at <= clock && occurs(e)).sort((a, b) => a.at - b.at)
}

// Highest state per host from visible events: { host: 0..3 }
export function hostLevels(visible) {
  const out = {}
  for (const e of visible) {
    if (!e.state) continue
    out[e.host] = Math.max(out[e.host] || 0, LEVEL[e.state])
  }
  return out
}

const KNOWN_FIELDS = ['severity', 'host', 'user', 'source', 'mitre', 'stage']

// Small SIEM query language: free text plus field:value filters.
export function searchEvents(visible, query) {
  const q = (query || '').trim()
  if (!q) return [...visible]
  const tokens = q.match(/(?:[^\s"]+|"[^"]*")+/g) || []
  const filters = []
  const terms = []
  for (const tok of tokens) {
    const i = tok.indexOf(':')
    const key = i > 0 ? tok.slice(0, i).toLowerCase() : ''
    if (KNOWN_FIELDS.includes(key)) filters.push([key, tok.slice(i + 1).replace(/"/g, '').toLowerCase()])
    else terms.push(tok.replace(/"/g, '').toLowerCase())
  }
  return visible.filter((e) => {
    const hay = `${e.message} ${e.host} ${e.user || ''} ${e.source} ${e.mitre || ''} ${e.ioc || ''}`.toLowerCase()
    if (!terms.every((x) => hay.includes(x))) return false
    return filters.every(([k, v]) => {
      if (k === 'severity') return e.severity === v
      if (k === 'host') return (e.host || '').toLowerCase() === v
      if (k === 'user') return (e.user || '').toLowerCase() === v
      if (k === 'source') return e.source.toLowerCase().includes(v)
      if (k === 'mitre') return (e.mitre || '').toLowerCase().startsWith(v)
      if (k === 'stage') return (e.stage || '').toLowerCase().includes(v)
      return true
    })
  })
}

// Is an action unlocked, given what has been done?
export function isUnlocked(action, doneIds) {
  const u = action.unlock
  if (!u) return true
  if (u.anyOf && !u.anyOf.some((id) => doneIds.includes(id))) return false
  if (u.allOf && !u.allOf.every((id) => doneIds.includes(id))) return false
  return true
}

// Rating can depend on whether the action's target host was actually affected.
export function resolveAction(action, levels) {
  if (!action.affectedHost) return { rating: action.rating, feedback: action.feedback }
  const affected = (levels[action.affectedHost] || 0) > 0
  return affected
    ? { rating: action.rating, feedback: action.feedback }
    : { rating: 'risky', feedback: action.unaffectedFeedback || action.feedback }
}

export function containedAtOf(actionsDone) {
  const times = actionsDone.filter((a) => a.effect).map((a) => a.effectiveAt ?? a.at)
  return times.length ? Math.min(...times) : null
}

export function scoreRun(ctx) {
  const { scenario, actionsDone, pinned, flagged, severity, visible, levels, hintsUsed, ackAt, recoveredAt } = ctx
  const { actions, assets, events, detectAt, incidentStart } = scenario
  const realAssets = assets.filter((a) => !a.external)
  const affected = realAssets.filter((a) => (levels[a.id] || 0) > 0).map((a) => a.id)
  const encrypted = realAssets.filter((a) => (levels[a.id] || 0) === LEVEL.encrypted).map((a) => a.id)

  const actionPts = actionsDone.reduce((n, a) => n + PTS[a.rating], 0)
  const coreIds = actions
    .filter((a) => a.core || (a.coreIfAffected && affected.includes(a.affectedHost)))
    .map((a) => a.id)
  const coreMax = coreIds.length * 10

  const visibleKey = visible.filter((e) => e.key).map((e) => e.id)
  const pinnedKey = pinned.filter((id) => visibleKey.includes(id))
  const pinnedNoise = pinned.filter((id) => events.find((e) => e.id === id)?.noise)
  const evidencePts = Math.max(0, 2 * pinnedKey.length - pinnedNoise.length)
  const evidenceMax = 2 * visibleKey.length

  const tp = flagged.filter((id) => affected.includes(id)).length
  const fp = flagged.filter((id) => !affected.includes(id)).length
  const scopePts = Math.max(0, 2 * tp - fp)
  const scopeMax = 2 * affected.length

  const severityPts = severity === 'High' || severity === 'Critical' ? 5 : 0

  const containedAt = containedAtOf(actionsDone)
  let speedPts = 0
  if (containedAt != null) {
    speedPts = containedAt < t(9, 0) ? 15 : containedAt < t(9, 7) ? 10 : containedAt < t(9, 20) ? 5 : 0
  }

  const damage = encrypted.length * 5
  const hintPen = hintsUsed * 3

  const total = actionPts + evidencePts + scopePts + severityPts + speedPts - damage - hintPen
  const max = coreMax + evidenceMax + scopeMax + 5 + 15
  const score = Math.max(0, Math.min(Math.round(total), max))

  const breakdown = [
    { label: 'Response actions', pts: Math.min(actionPts, coreMax), max: coreMax },
    { label: 'Evidence quality', pts: evidencePts, max: evidenceMax },
    { label: 'Scoping affected assets', pts: scopePts, max: scopeMax },
    { label: 'Severity assessment', pts: severityPts, max: 5 },
    { label: 'Speed of containment', pts: speedPts, max: 15 }
  ]

  const metrics = {
    incidentStart,
    detectAt,
    mttd: detectAt - incidentStart,
    mtta: ackAt != null ? ackAt - detectAt : null,
    mttc: containedAt != null ? containedAt - incidentStart : null,
    mttr: recoveredAt != null ? recoveredAt - incidentStart : null
  }

  return { score, max, breakdown, metrics, affected, encrypted, containedAt, damage, hintPen }
}