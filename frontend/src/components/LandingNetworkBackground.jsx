import { useEffect, useRef } from 'react'

export function LandingNetworkBackground() {
  const canvasRef = useRef(null)
  const mouseRef = useRef({ x: -9999, y: -9999, active: false })
  const nodesRef = useRef([])
  const rafRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = Math.min(window.devicePixelRatio || 1, 2)

    const resize = () => {
      const w = window.innerWidth
      const h = window.innerHeight
      canvas.width = w * dpr
      canvas.height = h * dpr
      canvas.style.width = w + 'px'
      canvas.style.height = h + 'px'
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

      const density = Math.min(120, Math.floor((w * h) / 14000))
      const nodes = []
      for (let i = 0; i < density; i++) {
        const roll = Math.random()
        const team = roll < 0.18 ? 'red' : roll < 0.36 ? 'blue' : 'neutral'
        nodes.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.25,
          vy: (Math.random() - 0.5) * 0.25,
          team,
          radius: team === 'neutral' ? 1.2 : 1.8,
        })
      }
      nodesRef.current = nodes
    }

    resize()
    window.addEventListener('resize', resize)

    const onMove = (e) => {
      mouseRef.current.x = e.clientX
      mouseRef.current.y = e.clientY
      mouseRef.current.active = true
    }
    const onLeave = () => {
      mouseRef.current.active = false
      mouseRef.current.x = -9999
      mouseRef.current.y = -9999
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseleave', onLeave)

    const colorFor = (team, alpha) => {
      if (team === 'red') return `rgba(239, 68, 68, ${alpha})`
      if (team === 'blue') return `rgba(59, 130, 246, ${alpha})`
      return `rgba(180, 200, 255, ${alpha})`
    }

    const render = () => {
      const w = window.innerWidth
      const h = window.innerHeight
      ctx.clearRect(0, 0, w, h)

      const nodes = nodesRef.current
      const mouse = mouseRef.current
      const linkDist = 140
      const mouseRadius = 180

      for (const n of nodes) {
        if (mouse.active) {
          const dx = mouse.x - n.x
          const dy = mouse.y - n.y
          const dist = Math.hypot(dx, dy)
          if (dist < mouseRadius) {
            const force = (1 - dist / mouseRadius) * 0.6
            const dirX = dx / (dist || 1)
            const dirY = dy / (dist || 1)
            if (dist < 60) {
              n.vx -= dirX * force * 0.12
              n.vy -= dirY * force * 0.12
            } else {
              n.vx += dirX * force * 0.03
              n.vy += dirY * force * 0.03
            }
          }
        }

        n.vx *= 0.985
        n.vy *= 0.985
        const speed = Math.hypot(n.vx, n.vy)
        const max = 1.2
        if (speed > max) {
          n.vx = (n.vx / speed) * max
          n.vy = (n.vy / speed) * max
        }

        n.x += n.vx
        n.y += n.vy

        if (n.x < 0) n.x = w
        else if (n.x > w) n.x = 0
        if (n.y < 0) n.y = h
        else if (n.y > h) n.y = 0
      }

      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j]
          const dx = a.x - b.x
          const dy = a.y - b.y
          const dist = Math.hypot(dx, dy)
          if (dist < linkDist) {
            const alpha = (1 - dist / linkDist) * 0.35
            let team = 'neutral'
            if (a.team === b.team && a.team !== 'neutral') team = a.team
            else if (a.team !== 'neutral') team = a.team
            else if (b.team !== 'neutral') team = b.team
            ctx.strokeStyle = colorFor(team, alpha)
            ctx.lineWidth = 0.7
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b.x, b.y)
            ctx.stroke()
          }
        }
      }

      if (mouse.active) {
        for (const n of nodes) {
          const dx = mouse.x - n.x
          const dy = mouse.y - n.y
          const dist = Math.hypot(dx, dy)
          if (dist < mouseRadius) {
            const alpha = (1 - dist / mouseRadius) * 0.55
            ctx.strokeStyle = colorFor(n.team, alpha)
            ctx.lineWidth = 0.9
            ctx.beginPath()
            ctx.moveTo(mouse.x, mouse.y)
            ctx.lineTo(n.x, n.y)
            ctx.stroke()
          }
        }
      }

      for (const n of nodes) {
        ctx.fillStyle = colorFor(n.team, 0.9)
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2)
        ctx.fill()

        if (n.team !== 'neutral') {
          ctx.fillStyle = colorFor(n.team, 0.12)
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.radius * 4, 0, Math.PI * 2)
          ctx.fill()
        }
      }

      rafRef.current = requestAnimationFrame(render)
    }

    rafRef.current = requestAnimationFrame(render)

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseleave', onLeave)
    }
  }, [])

  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 z-0" aria-hidden="true" />
}