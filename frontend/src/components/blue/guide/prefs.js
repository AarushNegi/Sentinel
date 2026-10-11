// components/blue/guide/prefs.js
// Small, per-browser preferences and per-session notes. Everything is wrapped
// in try/catch: storage can be unavailable or full, and the simulation must
// work without it. Server-side state (evidence, actions, scoring) never lives here.
import { useCallback, useState } from 'react'

const PREFS_KEY = 'sentinel_blue_guide_v1'
const DEFAULTS = { guided: true, advanced: false, onboarded: false, seen: {} }

function readJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key)
    return raw ? { ...fallback, ...JSON.parse(raw) } : fallback
  } catch {
    return fallback
  }
}

function writeJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* storage unavailable: preferences just will not persist */
  }
}

export function useGuidePrefs() {
  const [prefs, setPrefs] = useState(() => readJson(PREFS_KEY, DEFAULTS))

  const update = useCallback((patch) => {
    setPrefs((current) => {
      const next = { ...current, ...(typeof patch === 'function' ? patch(current) : patch) }
      writeJson(PREFS_KEY, next)
      return next
    })
  }, [])

  const markSeen = useCallback((key) => {
    update((p) => ({ seen: { ...p.seen, [key]: true } }))
  }, [update])

  return { prefs, update, markSeen }
}

// Notes that belong to one session (working hypothesis, indicator notes,
// evidence ticked as supporting). They are conveniences, not scored state.
const notesKey = (sessionId) => `sentinel_blue_notes_${sessionId}`
const NOTE_DEFAULTS = { verdicts: {}, pinned: [], stepId: null, form: null }

export const loadNotes = (sessionId) => (sessionId ? readJson(notesKey(sessionId), NOTE_DEFAULTS) : NOTE_DEFAULTS)
export const saveNotes = (sessionId, notes) => { if (sessionId) writeJson(notesKey(sessionId), notes) }
