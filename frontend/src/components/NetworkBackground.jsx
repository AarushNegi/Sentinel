// components/NetworkBackground.jsx
import { useEffect, useRef } from 'react'
import './NetworkBackground.css'

export default function NetworkBackground({ variant = 'blue' }) {
  const canvasRef = useRef(null)
  const isRed = variant === 'red'
  const accent = isRed ? '#ef4444' : '#3b82f6'

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let animationId
    let particles = []
    let sweepAngle = 0
    let lastFlash = 0

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const COUNT = 70
    const speed = isRed ? 1.1 : 0.4
    particles = Array.from({ length: COUNT }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * speed,
      vy: (Math.random() - 0.5) * speed
    }))

    const draw = (time) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      particles.forEach(p => {
        p.x += p.vx
        p.y += p.vy
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1
      })

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i], b = particles[j]
          const dist = Math.hypot(a.x - b.x, a.y - b.y)
          if (dist < 180) {
            ctx.strokeStyle = accent
            ctx.globalAlpha = (1 - dist / 180) * 0.5
            ctx.lineWidth = 1.2
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b.x, b.y)
            ctx.stroke()
          }
        }
      }

      ctx.globalAlpha = 1
      particles.forEach(p => {
        ctx.shadowBlur = 12
        ctx.shadowColor = accent
        ctx.fillStyle = accent
        ctx.beginPath()
        ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2)
        ctx.fill()
        ctx.shadowBlur = 0
      })

      if (isRed) {
        if (time - lastFlash > 2200 && Math.random() < 0.02) {
          lastFlash = time
          const fx = Math.random() * canvas.width
          const fy = Math.random() * canvas.height
          ctx.beginPath()
          ctx.arc(fx, fy, 60, 0, Math.PI * 2)
          const grad = ctx.createRadialGradient(fx, fy, 0, fx, fy, 60)
          grad.addColorStop(0, 'rgba(239,68,68,0.35)')
          grad.addColorStop(1, 'rgba(239,68,68,0)')
          ctx.fillStyle = grad
          ctx.fill()
        }
      } else {
        sweepAngle += 0.008
        const cx = canvas.width / 2
        const cy = canvas.height / 2
        const radius = Math.max(canvas.width, canvas.height)
        if (ctx.createConicGradient) {
          const grad = ctx.createConicGradient(sweepAngle, cx, cy)
          grad.addColorStop(0, 'rgba(59,130,246,0.12)')
          grad.addColorStop(0.05, 'rgba(59,130,246,0)')
          grad.addColorStop(1, 'rgba(59,130,246,0)')
          ctx.fillStyle = grad
          ctx.beginPath()
          ctx.arc(cx, cy, radius, 0, Math.PI * 2)
          ctx.fill()
        }
      }

      animationId = requestAnimationFrame(draw)
    }
    animationId = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(animationId)
      window.removeEventListener('resize', resize)
    }
  }, [variant])

  return <canvas ref={canvasRef} className="nb-canvas" />
}