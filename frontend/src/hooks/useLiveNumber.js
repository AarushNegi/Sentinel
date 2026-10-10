// hooks/useLiveNumber.js
// Slowly increments a number on an interval, for cosmetic "this is alive"
// stat cards. Purely simulated/local — never fetches or claims real data.
import { useEffect, useState } from 'react'

export function useLiveNumber(initial, { min = 1, max = 12, intervalMs = 4000 } = {}) {
  const [value, setValue] = useState(initial)

  useEffect(() => {
    const id = setInterval(() => {
      setValue(v => v + Math.floor(Math.random() * (max - min + 1)) + min)
    }, intervalMs + Math.random() * 1500)
    return () => clearInterval(id)
  }, [min, max, intervalMs])

  return value
}
