import { useEffect, useState } from 'react'
import { getKillChain } from '../services/api'
import './KillChainVisualizer.css'

const STATUS_CONFIG = {
  completed: { color: '#22c55e', label: 'Completed' },
  active:    { color: '#eab308', label: 'Active' },
  pending:   { color: '#374151', label: 'Pending' },
}

export default function KillChainVisualizer({ simulationId }) {
  const [data, setData]         = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [selected, setSelected] = useState(null) // selected stage object for drawer

  useEffect(() => {
    if (!simulationId) return

    let cancelled = false
    setLoading(true)
    setError('')

    getKillChain(simulationId)
      .then(res => { if (!cancelled) setData(res.data) })
      .catch(err => { if (!cancelled) setError(err.response?.data?.error || 'Failed to load kill chain data.') })
      .finally(() => { if (!cancelled) setLoading(false) })

    return () => { cancelled = true }
  }, [simulationId])

  if (!simulationId) {
    return <div className="kc-empty">No simulation selected.</div>
  }

  if (loading) {
    return <div className="kc-empty">Loading kill chain…</div>
  }

  if (error) {
    return <div className="kc-empty kc-error">{error}</div>
  }

  if (!data) return null

  return (
    <div className="kc-wrapper">
      <div className="kc-header">
        <h2>Kill Chain — <span className="kc-attack-type">{data.attack_type}</span></h2>
        <span className={`kc-status-badge ${data.status === 'Running' ? 'running' : ''}`}>
          {data.status}
        </span>
      </div>

      <div className="kc-timeline">
        {data.stages.map((stage, i) => {
          const cfg = STATUS_CONFIG[stage.status]
          const isLast = i === data.stages.length - 1

          return (
            <div className="kc-row" key={stage.id}>
              <div className="kc-rail">
                <button
                  className={`kc-node kc-node-${stage.status}`}
                  style={{ '--node-color': cfg.color }}
                  onClick={() => setSelected(stage)}
                  aria-label={`View details for ${stage.name}`}
                >
                  {stage.status === 'completed' ? '✓' : i + 1}
                </button>
                {!isLast && (
                  <div className={`kc-connector ${stage.status === 'completed' ? 'kc-connector-done' : ''}`} />
                )}
              </div>

              <div
                className="kc-content"
                onClick={() => setSelected(stage)}
              >
                <div className="kc-content-top">
                  <span className="kc-stage-name">{stage.name}</span>
                  <span className="kc-pill" style={{ color: cfg.color, borderColor: cfg.color }}>
                    {cfg.label}
                  </span>
                </div>
                {stage.timestamp && <span className="kc-timestamp">{stage.timestamp}</span>}
                {stage.description && (
                  <p className="kc-desc-preview">{stage.description}</p>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Side Drawer */}
      <div className={`kc-drawer-overlay ${selected ? 'open' : ''}`} onClick={() => setSelected(null)} />
      <div className={`kc-drawer ${selected ? 'open' : ''}`}>
        {selected && (
          <>
            <div className="kc-drawer-header">
              <div>
                <span
                  className="kc-pill"
                  style={{
                    color: STATUS_CONFIG[selected.status].color,
                    borderColor: STATUS_CONFIG[selected.status].color
                  }}
                >
                  {STATUS_CONFIG[selected.status].label}
                </span>
                <h3>{selected.name}</h3>
              </div>
              <button className="kc-drawer-close" onClick={() => setSelected(null)}>✕</button>
            </div>

            {selected.timestamp && (
              <div className="kc-drawer-meta">🕐 {selected.timestamp}</div>
            )}

            {selected.mitre_id && (
              <div className="kc-drawer-meta">
                🎯 MITRE ATT&CK: <span className="kc-mitre">{selected.mitre_id}</span>
              </div>
            )}

            <p className="kc-drawer-desc">
              {selected.description || 'No details available for this stage yet.'}
            </p>

            {selected.logs?.length > 0 && (
              <div className="kc-drawer-logs">
                <div className="kc-drawer-logs-title">Related Logs</div>
                {selected.logs.map((log, idx) => (
                  <div key={idx} className="kc-log-line">{log}</div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}