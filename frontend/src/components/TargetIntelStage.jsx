// components/TargetIntelStage.jsx
// Stage 1 — Reconnaissance. The student specifies who they're investigating;
// a persona is procedurally generated from that name (see
// data/phishingSimulation.js — deterministic, no two different names
// resolve to the same company/role/content). The student then inspects
// realistic-looking intel sections themselves — nothing reveals "the right
// answer" automatically.
import { useState } from 'react'
import { ChevronDown, CheckCircle2, Search, Building2, ShieldAlert, Contact, Rss, Loader2, Users, Landmark } from 'lucide-react'
import LearningPopup from './LearningPopup'
import { generateTarget, buildIntelSections, PLATFORM_TYPES } from '../data/phishingSimulation'
import './TargetIntelStage.css'

const PLATFORM_ICONS = { social: Users, banking: Landmark }

const SECTION_ICONS = { profile: Search, feed: Rss, org: Building2, bulletin: ShieldAlert, contact: Contact }

const SEARCH_STEPS = [
  (q) => `Querying public professional profiles for "${q}"...`,
  () => 'Cross-referencing company directories...',
  () => 'Compiling target dossier...',
]

function SectionBody({ section, target }) {
  const { kind, data } = section

  if (kind === 'profile') {
    return (
      <div className="ti-mock ti-mock-profile">
        <div className="ti-mock-avatar">{target.name.charAt(0)}</div>
        <div className="ti-mock-profile-main">
          <strong>{target.name}</strong>
          <span>{data.headline}</span>
          <span className="ti-mock-dim">{data.location} · {data.connections} connections</span>
          <p>{data.about}</p>
          <div className="ti-mock-experience">
            {data.experience.map((e) => (
              <div key={e.role + e.org} className="ti-mock-exp-row">
                <strong>{e.role}</strong>
                <span>{e.org} · {e.years}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (kind === 'feed') {
    return (
      <div className="ti-mock ti-mock-feed">
        {data.posts.map((p) => (
          <div key={p.text} className="ti-mock-post">
            <div className="ti-mock-post-head"><strong>{target.name}</strong><span>{p.time}</span></div>
            <p>{p.text}</p>
            <span className="ti-mock-dim">♥ {p.likes}</span>
          </div>
        ))}
      </div>
    )
  }

  if (kind === 'org') {
    return (
      <div className="ti-mock ti-mock-org">
        <div className="ti-mock-org-head">
          <div className="ti-mock-org-logo">{target.organization.charAt(0)}</div>
          <div>
            <strong>{target.organization}</strong>
            <span className="ti-mock-dim">{data.industry} · {data.size} · Founded {data.founded}</span>
          </div>
        </div>
        <p>{data.about}</p>
      </div>
    )
  }

  if (kind === 'bulletin') {
    return (
      <div className="ti-mock ti-mock-bulletin">
        <div className="ti-mock-bulletin-head">
          <span className="ti-mock-badge">{data.severity}</span>
          <strong>{data.title}</strong>
        </div>
        <span className="ti-mock-dim">To: {data.sentTo}</span>
        <p>{data.body}</p>
      </div>
    )
  }

  // contact
  return (
    <div className="ti-mock ti-mock-contact">
      <div className="ti-mock-avatar small">{target.name.charAt(0)}</div>
      <div>
        <strong>{target.name}</strong>
        <span>{data.email}</span>
        <span>{data.messenger} · {data.handle}</span>
      </div>
    </div>
  )
}

export default function TargetIntelStage({ inspected, onInspect, onContinue, onTargetFound, onPlatformChosen }) {
  const [phase, setPhase] = useState('platform') // platform | search | searching | results
  const [platform, setPlatform] = useState(null)
  const [query, setQuery] = useState('')
  const [searchStepIdx, setSearchStepIdx] = useState(0)
  const [target, setTarget] = useState(null)
  const [sections, setSections] = useState([])
  const [openId, setOpenId] = useState(null)
  const [showNudge, setShowNudge] = useState(false)

  const choosePlatform = (key) => {
    const p = PLATFORM_TYPES[key]
    setPlatform(p)
    onPlatformChosen(p)
    setPhase('search')
  }

  const beginInvestigation = () => {
    if (!query.trim()) return
    setPhase('searching')
    setSearchStepIdx(0)
    const t1 = setTimeout(() => setSearchStepIdx(1), 550)
    const t2 = setTimeout(() => setSearchStepIdx(2), 1100)
    const t3 = setTimeout(() => {
      const t = generateTarget(query, platform)
      setTarget(t)
      setSections(buildIntelSections(t, platform))
      onTargetFound(t)
      setPhase('results')
    }, 1700)
    return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3) }
  }

  const toggle = (section) => {
    const willOpen = openId !== section.id
    setOpenId(willOpen ? section.id : null)
    if (willOpen && !inspected.has(section.id)) {
      onInspect(section.id, section.log)
    }
  }

  const handleContinue = () => {
    if (inspected.size === 0) {
      setShowNudge(true)
      return
    }
    onContinue()
  }

  if (phase === 'platform') {
    return (
      <div className="rp-action-panel">
        <div className="rp-stage-tag">RED TEAM // CHOOSE ATTACK</div>
        <h1>Choose your attack type.</h1>
        <p>Different platforms, different lures. Pick what kind of account you're going after.</p>

        <div className="ti-platform-grid">
          {Object.values(PLATFORM_TYPES).map((p) => {
            const Icon = PLATFORM_ICONS[p.key]
            return (
              <button key={p.key} type="button" className="ti-platform-card" onClick={() => choosePlatform(p.key)}>
                <Icon size={22} />
                <strong>{p.attackLabel}</strong>
                <span>{p.description}</span>
              </button>
            )
          })}
        </div>
      </div>
    )
  }

  if (phase === 'search') {
    return (
      <div className="rp-action-panel">
        <div className="rp-stage-tag">RED TEAM // RECONNAISSANCE</div>
        <h1>Specify your target.</h1>
        <p>Who are you investigating? Enter a name to begin open-source reconnaissance (OSINT).</p>

        <LearningPopup type="learning">
          OSINT means gathering publicly available information before making contact — social profiles,
          company directories, public posts. Real attackers do exactly this before sending a single email.
          Try a full name — the profile, company, and details you get back are generated fresh for
          whoever you search.
        </LearningPopup>

        <div className="ti-search">
          <Search size={16} />
          <input
            placeholder="e.g. Priya Sharma"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && beginInvestigation()}
          />
        </div>
        <button className="rp-primary-btn" onClick={beginInvestigation} disabled={!query.trim()}>
          Begin Investigation →
        </button>
      </div>
    )
  }

  if (phase === 'searching') {
    return (
      <div className="rp-action-panel">
        <div className="rp-stage-tag">RED TEAM // RECONNAISSANCE</div>
        <h1>Searching public records…</h1>
        <div className="ti-searching-log">
          {SEARCH_STEPS.slice(0, searchStepIdx + 1).map((stepFn, i) => (
            <div key={i} className="ti-searching-line">
              {i === searchStepIdx ? <Loader2 size={13} className="ti-spin" /> : <CheckCircle2 size={13} className="ti-check" />}
              {stepFn(query)}
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="rp-action-panel">
      <div className="rp-stage-tag">RED TEAM // RECONNAISSANCE</div>
      <h1>Investigate the target.</h1>
      <p>
        Search results for "{query}" resolved to one match: <strong>{target.name}</strong>. Review the
        sections below — nothing here is pre-sorted into "useful" or "not useful," that's your call.
      </p>

      <div className="ti-sections">
        {sections.map((section) => {
          const isOpen = openId === section.id
          const done = inspected.has(section.id)
          const Icon = SECTION_ICONS[section.kind]
          return (
            <div key={section.id} className={`ti-section ${isOpen ? 'open' : ''}`}>
              <button type="button" className="ti-section-head" onClick={() => toggle(section)}>
                <Icon size={14} className="ti-section-icon" />
                {done && <CheckCircle2 size={14} className="ti-check" />}
                <span>{section.label}</span>
                <ChevronDown size={15} className="ti-chevron" />
              </button>
              {isOpen && <div className="ti-section-body"><SectionBody section={section} target={target} /></div>}
            </div>
          )
        })}
      </div>

      {showNudge && (
        <LearningPopup type="hint" onDismiss={() => setShowNudge(false)}>
          Look for information that could make a message appear relevant to the target —
          open at least one section above before moving on.
        </LearningPopup>
      )}

      <button className="rp-primary-btn" onClick={handleContinue}>
        Continue to Target Profiling →
      </button>
    </div>
  )
}
