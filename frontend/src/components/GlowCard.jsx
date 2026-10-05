import { useRef } from 'react'

export function GlowCard({ children, team = 'neutral', className = '' }) {
  const ref = useRef(null)

  const onMove = (e) => {
    const el = ref.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width) * 100
    const y = ((e.clientY - rect.top) / rect.height) * 100
    el.style.setProperty('--mx', x + '%')
    el.style.setProperty('--my', y + '%')
  }

  const glow =
    team === 'red' ? 'rgba(239,68,68,0.22)' : team === 'blue' ? 'rgba(59,130,246,0.22)' : 'rgba(180,200,255,0.15)'

  return (
    <div
      ref={ref}
      onMouseMove={onMove}
      className={`group relative overflow-hidden rounded-xl border border-border bg-card/60 p-6 backdrop-blur-sm transition-colors duration-300 hover:border-[color:var(--blue-team)]/50 ${className}`}
      style={{
        backgroundImage: `radial-gradient(500px circle at var(--mx,50%) var(--my,50%), ${glow}, transparent 40%)`,
      }}
    >
      {children}
    </div>
  )
}