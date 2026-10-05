// components/HashPlayground.jsx
import { useState, useEffect } from 'react'
import './HashPlayground.css'

async function sha256(text) {
  const data = new TextEncoder().encode(text)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export default function HashPlayground() {
  const [input, setInput] = useState('Sentinel')
  const [hash, setHash] = useState('')
  const [prevHash, setPrevHash] = useState('')

  useEffect(() => {
    sha256(input).then((h) => {
      setPrevHash(hash)
      setHash(h)
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input])

  const diffCount = hash && prevHash
    ? hash.split('').filter((c, i) => c !== prevHash[i]).length
    : 0

  return (
    <div className="hp-wrapper">
      <label className="hp-label">Type anything — watch the hash change completely</label>
      <input
        className="hp-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Type here..."
      />
      <div className="hp-hash-box">
        <span className="hp-hash-label">SHA-256 digest</span>
        <code className="hp-hash-value">{hash}</code>
      </div>
      {prevHash && (
        <p className="hp-note">
          That single keystroke changed <strong>{diffCount}</strong> of 64 hex characters — this is the avalanche effect.
        </p>
      )}
    </div>
  )
}