import { useRef } from 'react'

export function MagneticButton({ variant = 'blue', children, className = '', ...rest }) {
  const ref = useRef(null)

  const onMove = (e) => {
    const el = ref.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const x = e.clientX - rect.left - rect.width / 2
    const y = e.clientY - rect.top - rect.height / 2
    el.style.transform = `translate(${x * 0.25}px, ${y * 0.35}px)`
  }
  const onLeave = () => {
    const el = ref.current
    if (el) el.style.transform = 'translate(0,0)'
  }

  const base =
    'relative inline-flex items-center justify-center gap-2 rounded-md px-6 py-3 font-mono text-sm uppercase tracking-widest transition-[transform,box-shadow,background,color] duration-300 will-change-transform'
  const styles =
    variant === 'red'
      ? 'bg-[color:var(--red-team)] text-white hover:shadow-red-glow'
      : variant === 'blue'
      ? 'bg-[color:var(--blue-team)] text-white hover:shadow-blue-glow'
      : 'border border-border bg-transparent text-foreground hover:border-[color:var(--blue-team)] hover:text-[color:var(--blue-team-glow)]'

  return (
    <button ref={ref} onMouseMove={onMove} onMouseLeave={onLeave} className={`${base} ${styles} ${className}`} {...rest}>
      {children}
    </button>
  )
}