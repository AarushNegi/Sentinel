// components/IntroAnimation.jsx
// Full-screen, scroll-scrubbed logo intro for the public homepage ("/").
// Two phases share one continuous scroll track, both driven the same way —
// a scroll-stepped sequence of images, never a <video> element:
//   Phase 1 — the red-snake/blue-wolf logo-formation sequence.
//   Phase 2 — the SENTINEL name-reveal sequence, picking up exactly where
//             phase 1 ends (same completed emblem).
// Renders nothing (and costs nothing) once the intro has already played in
// this browser session, when the user prefers reduced motion, or when no
// frames are found — Landing then renders exactly as it did before this
// component existed.
import { useEffect, useMemo, useRef, useState } from 'react'
import './IntroAnimation.css'

// Picking up every image dropped into these folders means the frame counts
// never have to be hard-coded — add, remove, or reorder files there (sorted
// alphabetically) and this component adapts automatically.
const frameModules = import.meta.glob('../assets/intro/*.{jpg,jpeg,png,webp}', {
  eager: true,
  import: 'default',
})
const FRAME_SRCS = Object.keys(frameModules)
  .sort()
  .map((key) => frameModules[key])

const revealModules = import.meta.glob('../assets/intro-reveal/*.{jpg,jpeg,png,webp}', {
  eager: true,
  import: 'default',
})
const REVEAL_SRCS = Object.keys(revealModules)
  .sort()
  .map((key) => revealModules[key])

// Target total scroll distance per phase, not a fixed per-frame amount —
// so a denser or sparser frame sequence keeps the same cinematic length
// instead of ballooning into many screens of scrolling. Per-frame distance
// is clamped so a very small or very large frame count still feels right.
const TOTAL_SCRUB_TARGET_PX = 2800
const MIN_PX_PER_FRAME = 10
const MAX_PX_PER_FRAME = 90
const SESSION_KEY = 'sentinel_intro_seen'
// The intro plays at most once per page load, however many public entry
// pages mount it ("/" and "/login"): in-app navigation or Back/Forward
// between them must never replay it.
let playedThisLoad = false

function scrubHeightFor(count) {
  if (count === 0) return 0
  const perFrame = Math.max(MIN_PX_PER_FRAME, Math.min(MAX_PX_PER_FRAME, TOTAL_SCRUB_TARGET_PX / count))
  return Math.round(perFrame * count)
}

function prefersReducedMotion() {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}

function readSession() {
  try {
    return sessionStorage.getItem(SESSION_KEY) === '1'
  } catch {
    return false
  }
}

function writeSession() {
  try {
    sessionStorage.setItem(SESSION_KEY, '1')
  } catch {
    // Private-mode / blocked storage — the intro will just replay next time.
  }
}

// True when the intro is about to play for this visit. The login page uses it
// to send a first-time visitor to the homepage, where the intro lives, so the
// intro always ends on the homepage and never on the login page.
export function introPending() {
  if (playedThisLoad) return false
  if (FRAME_SRCS.length === 0) {
    if (import.meta.env.DEV) console.info('[IntroAnimation] skipped: no frames found in src/assets/intro/')
    return false
  }
  if (prefersReducedMotion()) {
    if (import.meta.env.DEV) console.info('[IntroAnimation] skipped: prefers-reduced-motion is enabled (OS/browser setting)')
    return false
  }
  // The once-per-tab skip is a production UX choice (don't replay on every
  // internal nav back to "/"). In dev it would otherwise fire on nearly
  // every reload while iterating, so it's bypassed here.
  if (readSession() && import.meta.env.PROD) return false
  return true
}

export default function IntroAnimation() {
  const frameCount = FRAME_SRCS.length
  const revealCount = REVEAL_SRCS.length
  const [active] = useState(introPending)
  useEffect(() => {
    if (active) playedThisLoad = true
  }, [active])
  // A frame that fails to load must never leave a stuck full-screen intro.
  const [failed, setFailed] = useState(false)
  const wrapperRef = useRef(null)
  const tickingRef = useRef(false)
  const [frameIndex, setFrameIndex] = useState(0)
  const [revealIndex, setRevealIndex] = useState(0)
  const [stage, setStage] = useState('images') // 'images' | 'reveal'
  const [progress, setProgress] = useState(0)
  const [finished, setFinished] = useState(false)

  const imageScrubHeight = useMemo(() => scrubHeightFor(frameCount), [frameCount])
  const revealScrubHeight = useMemo(() => scrubHeightFor(revealCount), [revealCount])
  const scrubHeight = imageScrubHeight + revealScrubHeight
  // Where phase 1 (logo formation) ends and phase 2 (name reveal) begins,
  // as a fraction of overall scroll progress (0..1). Progress itself never
  // resets at this boundary — it's one continuous value across both phases.
  const phase1Share = scrubHeight > 0 ? imageScrubHeight / scrubHeight : 1

  // Preload every frame in both sequences up front so fast scrubbing never
  // shows a blank frame.
  useEffect(() => {
    if (!active) return
    FRAME_SRCS.forEach((src) => {
      const img = new window.Image()
      img.src = src
    })
    REVEAL_SRCS.forEach((src) => {
      const img = new window.Image()
      img.src = src
    })
  }, [active])

  useEffect(() => {
    if (!active) return

    const handleScroll = () => {
      if (tickingRef.current) return
      tickingRef.current = true
      window.requestAnimationFrame(() => {
        tickingRef.current = false
        const el = wrapperRef.current
        if (!el) return
        const rect = el.getBoundingClientRect()
        const scrollable = el.offsetHeight - window.innerHeight
        const raw = scrollable > 0 ? -rect.top / scrollable : 0
        const clamped = Math.min(1, Math.max(0, raw))
        setProgress(clamped)

        if (revealCount === 0 || clamped < phase1Share) {
          setStage('images')
          const p1 = phase1Share > 0 ? clamped / phase1Share : 1
          setFrameIndex(Math.min(frameCount - 1, Math.floor(p1 * frameCount)))
        } else {
          setStage('reveal')
          setFrameIndex(frameCount - 1)
          const p2 = phase1Share < 1 ? (clamped - phase1Share) / (1 - phase1Share) : 1
          setRevealIndex(Math.min(revealCount - 1, Math.floor(p2 * revealCount)))
        }

        setFinished((prev) => {
          if (clamped >= 0.999 && !prev) writeSession()
          return clamped >= 0.999
        })
      })
    }

    handleScroll()
    window.addEventListener('scroll', handleScroll, { passive: true })
    window.addEventListener('resize', handleScroll)
    return () => {
      window.removeEventListener('scroll', handleScroll)
      window.removeEventListener('resize', handleScroll)
    }
  }, [active, frameCount, revealCount, phase1Share])

  const handleSkip = () => {
    const el = wrapperRef.current
    if (el) {
      const target = el.offsetTop + el.offsetHeight - window.innerHeight
      window.scrollTo({ top: target, behavior: 'smooth' })
    }
    writeSession()
  }

  if (!active || failed) return null

  return (
    <div
      ref={wrapperRef}
      className="intro-wrap"
      style={{ '--intro-scrub': `${scrubHeight}px` }}
      aria-hidden={finished}
    >
      <div className={`intro-sticky ${finished ? 'intro-done' : ''}`}>
        <div className="intro-ambient" />
        <div className="intro-circuit" />

        <img
          className={`intro-frame ${stage !== 'images' ? 'intro-layer-hidden' : ''} ${frameIndex === frameCount - 1 ? 'intro-frame-final' : ''}`}
          src={FRAME_SRCS[frameIndex]}
          alt="Sentinel logo formation — red and blue emblem merging into the final mark"
          draggable={false}
          onError={() => setFailed(true)}
        />

        {revealCount > 0 && (
          <img
            className={`intro-frame ${stage !== 'reveal' ? 'intro-layer-hidden' : ''}`}
            src={REVEAL_SRCS[revealIndex]}
            alt="Sentinel brand name reveal, following the logo animation"
            draggable={false}
            onError={() => setFailed(true)}
          />
        )}

        <div className="intro-vignette" />

        {!finished && (
          <>
            <div className={`intro-hint ${progress > 0.04 ? 'intro-hint-hidden' : ''}`}>
              <span className="intro-hint-chevron">⌄</span>
              Scroll to explore
            </div>

            <button type="button" className="intro-skip" onClick={handleSkip}>
              Skip Intro
            </button>

            <div className="intro-progress">
              <div className="intro-progress-fill" style={{ width: `${progress * 100}%` }} />
            </div>
          </>
        )}
      </div>
    </div>
  )
}
