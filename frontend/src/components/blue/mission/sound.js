// components/blue/mission/sound.js
// Optional, tiny synthesized cues (no audio files, no network). Off by default.
let ctx = null

export function play(kind) {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext
    if (!AudioCtx) return
    ctx = ctx || new AudioCtx()
    const tones = { ok: [660, 880], warn: [330, 247], alert: [880, 660, 880], info: [520] }[kind] || [520]
    tones.forEach((freq, i) => {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.frequency.value = freq
      gain.gain.value = 0.04
      osc.connect(gain)
      gain.connect(ctx.destination)
      const start = ctx.currentTime + i * 0.12
      osc.start(start)
      osc.stop(start + 0.1)
    })
  } catch {
    /* sound is optional */
  }
}
