// pages/Landing.jsx
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LandingNetworkBackground } from '../components/LandingNetworkBackground'
import { MagneticButton } from '../components/MagneticButton'
import { GlowCard } from '../components/GlowCard'
import { useReveal } from '../hooks/useReveal'
import {
  Shield, Swords, Radar, Bell, Search, Trophy, Target, Terminal, Activity, ArrowRight, ChevronRight, Cpu,
} from 'lucide-react'

const killChain = ['RECON', 'WEAPONIZE', 'DELIVER', 'EXPLOIT', 'INSTALL', 'C2', 'ACTIONS']

export default function Landing() {
  useReveal()
  const navigate = useNavigate()
  const [chainStep, setChainStep] = useState(0)
  const [alertPulse, setAlertPulse] = useState(0)

  useEffect(() => {
    const i = setInterval(() => setChainStep((s) => (s + 1) % killChain.length), 1400)
    const j = setInterval(() => setAlertPulse((n) => n + 1), 2200)
    return () => {
      clearInterval(i)
      clearInterval(j)
    }
  }, [])

  return (
    <div className="relative min-h-screen bg-background text-foreground">
      <LandingNetworkBackground />
      <div className="pointer-events-none fixed inset-0 z-0 bg-cyber-grid opacity-40" aria-hidden />
      <div className="pointer-events-none fixed inset-0 z-0 hero-bg" aria-hidden />

      <Nav navigate={navigate} />

      <main className="relative z-10">
        <Hero chainStep={chainStep} navigate={navigate} />
        <HowItWorks />
        <Features alertPulse={alertPulse} />
        <RedVsBlue navigate={navigate} />
        <FinalCTA navigate={navigate} />
        <Footer />
      </main>

      <div
        className="pointer-events-none fixed inset-x-0 top-0 z-[5] h-24 opacity-[0.06] animate-scanline"
        style={{ background: 'linear-gradient(to bottom, transparent, rgba(59,130,246,0.9), transparent)' }}
        aria-hidden
      />
    </div>
  )
}

function Nav({ navigate }) {
  return (
    <header className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
      <a href="#" className="group flex items-center gap-2.5">
        <div className="relative flex h-8 w-8 items-center justify-center rounded-md border border-border bg-card">
          <Shield className="h-4 w-4 text-[color:var(--blue-team-glow)]" />
        </div>
        <span className="font-mono text-sm uppercase tracking-[0.3em]">
          Sentinel<span className="text-[color:var(--red-team-glow)]">/</span><span className="text-[color:var(--blue-team-glow)]">SOC</span>
        </span>
      </a>
      <nav className="hidden items-center gap-8 font-mono text-xs uppercase tracking-widest text-muted-foreground md:flex">
        <a href="#how" className="hover:text-foreground transition-colors">How it works</a>
        <a href="#features" className="hover:text-foreground transition-colors">Features</a>
        <a href="#teams" className="hover:text-foreground transition-colors">Red / Blue</a>
        <a href="#start" className="hover:text-foreground transition-colors">Get access</a>
      </nav>
      <MagneticButton variant="ghost" className="!py-2 !px-4 text-[11px]" onClick={() => navigate('/login')}>
        Sign in
      </MagneticButton>
    </header>
  )
}

function Hero({ chainStep, navigate }) {
  return (
    <section className="relative mx-auto flex min-h-[92vh] max-w-7xl flex-col items-center justify-center px-6 pt-10 pb-24 text-center">
      <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-3 py-1 font-mono text-[11px] uppercase tracking-widest text-muted-foreground backdrop-blur">
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[color:var(--terminal)] opacity-75" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-[color:var(--terminal)]" />
        </span>
        Live SOC — 1,284 analysts online
      </div>

      <h1 className="max-w-5xl font-sans text-5xl font-semibold leading-[1.05] tracking-tight sm:text-6xl md:text-7xl">
        Learn <span className="text-glow-red text-[color:var(--red-team-glow)]">offense</span>{' '}and{' '}
        <span className="text-glow-blue text-[color:var(--blue-team-glow)]">defense</span>
        <br />through <span className="gradient-red-blue-text">live simulation.</span>
      </h1>

      <p className="mt-6 max-w-2xl text-balance text-base text-muted-foreground sm:text-lg">
        Sentinel is a hands-on cybersecurity range where students step into a real Security
        Operations Center. Run kill-chain attacks, triage alerts, investigate a SIEM, and race
        the clock to contain incidents — scored in real time.
      </p>

      <div className="mt-16 w-full max-w-3xl rounded-xl border border-border bg-card/60 p-4 backdrop-blur-md">
        <div className="mb-3 flex items-center justify-between font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          <div className="flex items-center gap-2">
            <Activity className="h-3 w-3 text-[color:var(--terminal)]" />
            kill_chain.stream
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--red-team)]" />
            attack in progress
          </div>
        </div>
        <div className="flex items-center gap-1 overflow-hidden">
          {killChain.map((step, i) => {
            const active = i === chainStep
            const passed = i < chainStep
            return (
              <div key={step} className="flex flex-1 items-center gap-1">
                <div
                  className={`flex-1 rounded px-2 py-2 text-center font-mono text-[10px] uppercase tracking-widest transition-all duration-500 ${
                    active
                      ? 'bg-[color:var(--red-team)]/20 text-[color:var(--red-team-glow)] border-glow-red'
                      : passed
                      ? 'bg-[color:var(--blue-team)]/10 text-[color:var(--blue-team-glow)] border border-[color:var(--blue-team)]/30'
                      : 'border border-border text-muted-foreground'
                  }`}
                >
                  {step}
                </div>
                {i < killChain.length - 1 && (
                  <ChevronRight className={`h-3 w-3 shrink-0 transition-colors ${passed ? 'text-[color:var(--blue-team-glow)]' : 'text-muted-foreground/40'}`} />
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="mt-10 flex flex-wrap items-center justify-center gap-x-8 gap-y-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
        <span>MITRE ATT&CK aligned</span>
        <span className="opacity-30">•</span>
        <span>SIEM-grade investigation</span>
        <span className="opacity-30">•</span>
        <span>Timed &amp; scored</span>
      </div>
    </section>
  )
}

const steps = [
  { n: '01', title: 'Mode select', desc: 'Pick Red Team, Blue Team, or Purple — dual perspective on the same scenario.', icon: Target },
  { n: '02', title: 'Attack scenario', desc: 'Load a mission: ransomware, phishing→lateral movement, insider threat, cloud takeover.', icon: Cpu },
  { n: '03', title: 'Guided brief', desc: 'Tooling, objectives, and hints scale with your rank — no dead ends, no pixel-hunting.', icon: Terminal },
  { n: '04', title: 'Live simulation', desc: 'Alerts fire in real time. Attack the network or defend it while the clock counts down.', icon: Activity },
  { n: '05', title: 'Outcome report', desc: 'Kill-chain replay, dwell time, MITRE techniques used, and a rank-adjusted score.', icon: Trophy },
]

function HowItWorks() {
  return (
    <section id="how" className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader eyebrow="Session flow" title="One session. Five stages. Zero fluff." subtitle="Every simulation runs the same loop so muscle memory sticks. Attack. Detect. Respond. Learn." />
      <ol className="mt-16 grid gap-4 md:grid-cols-5">
        {steps.map((s, i) => (
          <li key={s.n} className="reveal-on-scroll" style={{ transitionDelay: `${i * 80}ms` }}>
            <GlowCard className="h-full">
              <div className="mb-4 flex items-center justify-between font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
                <span>step {s.n}</span>
                <s.icon className="h-4 w-4 text-[color:var(--blue-team-glow)]" />
              </div>
              <h3 className="text-lg font-semibold">{s.title}</h3>
              <p className="mt-2 text-sm text-muted-foreground">{s.desc}</p>
            </GlowCard>
          </li>
        ))}
      </ol>
    </section>
  )
}

function Features({ alertPulse }) {
  return (
    <section id="features" className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader eyebrow="Inside the platform" title="The tools a real analyst uses — built for learning." subtitle="Every panel in Sentinel mirrors production SOC tooling, tuned so you can see cause and effect in seconds, not shifts." />
      <div className="mt-16 grid gap-6 md:grid-cols-6">
        <div className="reveal-on-scroll md:col-span-4">
          <GlowCard team="red" className="h-full">
            <FeatureLabel icon={Radar} tone="red">Kill Chain Visualizer</FeatureLabel>
            <h3 className="mt-3 text-2xl font-semibold">Watch every technique light up the chain.</h3>
            <p className="mt-2 text-sm text-muted-foreground">
              Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives. Nodes glow as adversary TTPs land, mapped straight to MITRE ATT&amp;CK.
            </p>
            <KillChainVisual />
          </GlowCard>
        </div>
        <div className="reveal-on-scroll md:col-span-2" style={{ transitionDelay: '80ms' }}>
          <GlowCard team="blue" className="h-full">
            <FeatureLabel icon={Bell} tone="blue">Live Alert Queue</FeatureLabel>
            <h3 className="mt-3 text-xl font-semibold">Triage under pressure.</h3>
            <p className="mt-2 text-sm text-muted-foreground">Alerts stream in with severity, host, and detection rule. Escalate, close, or pivot to investigation — every action is scored.</p>
            <AlertQueue pulse={alertPulse} />
          </GlowCard>
        </div>
        <div className="reveal-on-scroll md:col-span-3" style={{ transitionDelay: '120ms' }}>
          <GlowCard team="blue" className="h-full">
            <FeatureLabel icon={Search} tone="blue">SIEM-style Investigation</FeatureLabel>
            <h3 className="mt-3 text-xl font-semibold">Pivot on any field.</h3>
            <p className="mt-2 text-sm text-muted-foreground">A KQL-like query bar, timeline, and host graph. Chain events into a story and submit your verdict.</p>
            <div className="mt-5 rounded-md border border-border bg-background/70 p-3 font-mono text-[11px] leading-6">
              <div className="flex items-center gap-2 text-muted-foreground">
                <span className="text-[color:var(--terminal)]">›</span>
                <span className="text-foreground">SecurityEvent</span>
                <span>| where</span>
                <span className="text-[color:var(--blue-team-glow)]">EventID == 4688</span>
              </div>
              <div className="text-muted-foreground">| where <span className="text-[color:var(--red-team-glow)]">ProcessName has "rundll32"</span></div>
              <div className="text-muted-foreground">| project TimeGenerated, Host, User, CommandLine</div>
              <div className="mt-1 text-[color:var(--terminal)]">→ 12 events in 4 hosts · pivot ready</div>
            </div>
          </GlowCard>
        </div>
        <div className="reveal-on-scroll md:col-span-3" style={{ transitionDelay: '160ms' }}>
          <GlowCard team="red" className="h-full">
            <FeatureLabel icon={Trophy} tone="red">Scoring &amp; Leaderboard</FeatureLabel>
            <h3 className="mt-3 text-xl font-semibold">Ranked, replayable, ruthless.</h3>
            <p className="mt-2 text-sm text-muted-foreground">Points reward dwell time reduction, correct verdicts, and MITRE coverage. Climb your class board or take on global weekly ops.</p>
            <Leaderboard />
          </GlowCard>
        </div>
      </div>
    </section>
  )
}

function KillChainVisual() {
  return (
    <div className="mt-6 grid grid-cols-7 gap-1.5">
      {killChain.map((s, i) => (
        <div key={s} className="rounded-md border border-[color:var(--red-team)]/25 bg-[color:var(--red-team)]/5 p-2 text-center font-mono text-[9px] uppercase tracking-widest text-[color:var(--red-team-glow)]" style={{ animation: `pulse-glow 2.4s ${i * 0.15}s ease-in-out infinite` }}>
          {s}
        </div>
      ))}
    </div>
  )
}

function AlertQueue({ pulse }) {
  const alerts = [
    { sev: 'CRIT', host: 'WEB-03', rule: 'Rundll32 spawns cmd' },
    { sev: 'HIGH', host: 'DC-01', rule: 'Kerberoast attempt' },
    { sev: 'MED', host: 'HR-12', rule: 'Suspicious macro' },
    { sev: 'HIGH', host: 'APP-07', rule: 'Beacon jitter C2' },
  ]
  return (
    <div className="mt-5 space-y-1.5">
      {alerts.map((a, i) => {
        const active = i === pulse % alerts.length
        return (
          <div key={a.host + i} className={`flex items-center gap-2 rounded-md border px-2.5 py-2 font-mono text-[10px] transition-colors duration-300 ${active ? 'border-[color:var(--blue-team)]/60 bg-[color:var(--blue-team)]/10' : 'border-border bg-background/40'}`}>
            <span className={`rounded px-1.5 py-0.5 text-[9px] ${a.sev === 'CRIT' ? 'bg-[color:var(--red-team)]/25 text-[color:var(--red-team-glow)]' : a.sev === 'HIGH' ? 'bg-[color:var(--red-team)]/15 text-[color:var(--red-team-glow)]' : 'bg-muted text-muted-foreground'}`}>{a.sev}</span>
            <span className="text-foreground">{a.host}</span>
            <span className="truncate text-muted-foreground">· {a.rule}</span>
          </div>
        )
      })}
    </div>
  )
}

function Leaderboard() {
  const rows = [
    { rank: 1, name: 'nyx.exe', team: 'red', score: 9820 },
    { rank: 2, name: 'kernel_pnda', team: 'blue', score: 9614 },
    { rank: 3, name: '0xhex', team: 'red', score: 9410 },
    { rank: 4, name: 'you', team: 'blue', score: 9128 },
  ]
  return (
    <div className="mt-5 divide-y divide-border rounded-md border border-border bg-background/40 font-mono text-xs">
      {rows.map((r) => (
        <div key={r.rank} className={`flex items-center justify-between px-3 py-2 ${r.name === 'you' ? 'bg-[color:var(--blue-team)]/10' : ''}`}>
          <div className="flex items-center gap-3">
            <span className="w-6 text-muted-foreground">#{r.rank}</span>
            <span className={r.team === 'red' ? 'text-[color:var(--red-team-glow)]' : 'text-[color:var(--blue-team-glow)]'}>{r.name}</span>
          </div>
          <span className="tabular-nums">{r.score.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}

function RedVsBlue({ navigate }) {
  return (
    <section id="teams" className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader eyebrow="Pick a side. Or both." title="Red Team vs Blue Team." subtitle="Every scenario ships with both playbooks. Learn the attacker's moves, then defend against them from the other seat." />
      <div className="mt-16 grid gap-6 md:grid-cols-2">
        <div className="reveal-on-scroll">
          <GlowCard team="red" className="h-full">
            <div className="flex items-center justify-between">
              <FeatureLabel icon={Swords} tone="red">Red Team</FeatureLabel>
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">offense</span>
            </div>
            <h3 className="mt-3 text-2xl font-semibold text-[color:var(--red-team-glow)]">Break in. Move quietly. Reach the objective.</h3>
            <ul className="mt-5 space-y-2 font-mono text-sm text-muted-foreground">
              <TeamLine tone="red">Phishing &amp; initial access playbooks</TeamLine>
              <TeamLine tone="red">Living-off-the-land binaries (LOLBAS)</TeamLine>
              <TeamLine tone="red">Privilege escalation on Windows &amp; Linux</TeamLine>
              <TeamLine tone="red">C2 profiles, evasion, and cleanup</TeamLine>
            </ul>
            <MagneticButton variant="red" className="mt-6 w-full" onClick={() => navigate('register', { state: { mode: 'red' } })}>
              Enter as Red Team
            </MagneticButton>
          </GlowCard>
        </div>
        <div className="reveal-on-scroll" style={{ transitionDelay: '100ms' }}>
          <GlowCard team="blue" className="h-full">
            <div className="flex items-center justify-between">
              <FeatureLabel icon={Shield} tone="blue">Blue Team</FeatureLabel>
              <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">defense</span>
            </div>
            <h3 className="mt-3 text-2xl font-semibold text-[color:var(--blue-team-glow)]">Detect early. Contain fast. Write the report.</h3>
            <ul className="mt-5 space-y-2 font-mono text-sm text-muted-foreground">
              <TeamLine tone="blue">SIEM triage &amp; detection engineering</TeamLine>
              <TeamLine tone="blue">Endpoint &amp; network forensics</TeamLine>
              <TeamLine tone="blue">Threat hunting with hypothesis loops</TeamLine>
              <TeamLine tone="blue">Incident response &amp; executive briefing</TeamLine>
            </ul>
            <MagneticButton variant="blue" className="mt-6 w-full" onClick={() => navigate('register', { state: { mode: 'blue' } })}>
              Enter as Blue Team
            </MagneticButton>
          </GlowCard>
        </div>
      </div>
    </section>
  )
}

function TeamLine({ tone, children }) {
  return (
    <li className="flex items-start gap-2">
      <span className={`mt-2 h-1 w-3 shrink-0 rounded-full ${tone === 'red' ? 'bg-[color:var(--red-team)]' : 'bg-[color:var(--blue-team)]'}`} />
      <span>{children}</span>
    </li>
  )
}

function FeatureLabel({ icon: Icon, tone, children }) {
  return (
    <div className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest ${tone === 'red' ? 'border-[color:var(--red-team)]/40 text-[color:var(--red-team-glow)] bg-[color:var(--red-team)]/10' : 'border-[color:var(--blue-team)]/40 text-[color:var(--blue-team-glow)] bg-[color:var(--blue-team)]/10'}`}>
      <Icon className="h-3 w-3" />
      {children}
    </div>
  )
}

function SectionHeader({ eyebrow, title, subtitle }) {
  return (
    <div className="reveal-on-scroll mx-auto max-w-3xl text-center">
      <div className="mb-4 inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.3em] text-muted-foreground">
        <span className="h-px w-6 bg-border" />
        {eyebrow}
        <span className="h-px w-6 bg-border" />
      </div>
      <h2 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">{title}</h2>
      <p className="mt-4 text-balance text-muted-foreground">{subtitle}</p>
    </div>
  )
}

function FinalCTA({ navigate }) {
  return (
    <section id="start" className="relative mx-auto max-w-7xl px-6 py-32">
      <div className="reveal-on-scroll relative overflow-hidden rounded-2xl border border-border bg-card/60 p-10 backdrop-blur-md sm:p-16">
        <div className="pointer-events-none absolute inset-0 opacity-40" style={{ background: 'radial-gradient(600px circle at 20% 20%, rgba(239,68,68,0.25), transparent 50%), radial-gradient(600px circle at 80% 80%, rgba(59,130,246,0.25), transparent 50%)' }} aria-hidden />
        <div className="relative flex flex-col items-center text-center">
          <div className="mb-4 font-mono text-[11px] uppercase tracking-[0.3em] text-muted-foreground">sentinel.range/start</div>
          <h2 className="max-w-3xl text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Your first incident is <span className="gradient-red-blue-text">waiting.</span>
          </h2>
          <p className="mt-4 max-w-xl text-muted-foreground">Free tier includes 3 scenarios, full SIEM access, and the kill-chain replay. No card required. Bring a keyboard.</p>
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row">
            <MagneticButton variant="blue" className="min-w-[220px]" onClick={() => navigate('/register')}>
              Create free account
              <ArrowRight className="h-4 w-4" />
            </MagneticButton>
          
          </div>
          <div className="mt-6 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">trusted by learners at 200+ universities &amp; bootcamps</div>
        </div>
      </div>
    </section>
  )
}

function Footer() {
  return (
    <footer className="relative mx-auto max-w-7xl px-6 pb-12">
      <div className="flex flex-col items-start justify-between gap-6 border-t border-border pt-8 font-mono text-[11px] uppercase tracking-widest text-muted-foreground sm:flex-row sm:items-center">
        <div className="flex items-center gap-2">
          <Shield className="h-3.5 w-3.5 text-[color:var(--blue-team-glow)]" />
          Sentinel — Live SOC Range · v0.9 preview
        </div>
        <div className="flex items-center gap-6">
          <a href="#" className="hover:text-foreground transition-colors">Docs</a>
          <a href="#" className="hover:text-foreground transition-colors">Discord</a>
          <a href="#" className="hover:text-foreground transition-colors">Status</a>
          <a href="#" className="hover:text-foreground transition-colors">Privacy</a>
        </div>
      </div>
    </footer>
  )
}