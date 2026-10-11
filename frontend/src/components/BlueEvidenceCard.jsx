// components/BlueEvidenceCard.jsx
// Renders one piece of scenario evidence returned by the Blue Team API.
// All values are untrusted (scenario text may come from a language model), so
// everything is rendered as plain text — never as HTML, and links are never
// made clickable.
import { clock, prettify } from './blue/blueApi'

export default function BlueEvidenceCard({
  evidence,
  onPreserve,
  busy = false,
  highlight = false,
  onSelectRelated,
  pinned,
  onTogglePin,
  titleOf,
}) {
  const { content = {} } = evidence
  const fields = content.fields || []
  const columns = content.columns || []
  const rows = content.rows || []
  const provenance = evidence.provenance || {}

  return (
    <article
      className={`bt-evidence${highlight ? ' bt-evidence-new' : ''}`}
      data-evidence-id={evidence.id}
    >
      <header className="bt-evidence-head">
        <div>
          <span className="bt-evidence-cat">{evidence.category}</span>
          <strong>{evidence.title}</strong>
        </div>

        <div className="bt-evidence-tools">
          {onTogglePin && (
            <label className="bt-pin" title="Use this evidence to support your conclusion">
              <input
                type="checkbox"
                checked={Boolean(pinned)}
                onChange={() => onTogglePin(evidence.id)}
              />
              Support
            </label>
          )}
          {evidence.preservable && (
            evidence.preserved ? (
              <span className="bt-evidence-kept">PRESERVED ✓</span>
            ) : (
              <button
                type="button"
                className="bt-mini-btn"
                disabled={busy || !onPreserve}
                onClick={() => onPreserve && onPreserve(evidence.id)}
                title="Create a forensic copy of this artifact"
              >
                Preserve
              </button>
            )
          )}
        </div>
      </header>

      {(evidence.source_artifact || provenance.action) && (
        <p className="bt-evidence-meta">
          {evidence.source_artifact && <span>Source: {evidence.source_artifact}</span>}
          {provenance.action && (
            <span>
              Found by: {prettify(provenance.action)}
              {provenance.target ? ` (${provenance.target})` : ''}
            </span>
          )}
          {evidence.discovered_at && <span>Collected: {clock(evidence.discovered_at)}</span>}
          {provenance.tick != null && <span>Step {provenance.tick}</span>}
        </p>
      )}

      {content.summary && <p className="bt-evidence-summary">{content.summary}</p>}

      {fields.length > 0 && (
        <dl className="bt-evidence-fields">
          {fields.map(([key, value], i) => (
            <div key={`${key}-${i}`}>
              <dt>{key}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}

      {rows.length > 0 && (
        <div className="bt-evidence-table-wrap">
          <table className="bt-evidence-table">
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => (
                    <td key={c}>{String(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {content.verdict && (
        <p className="bt-evidence-verdict">
          <span>ANALYSIS</span>
          {content.verdict}
        </p>
      )}

      {evidence.related && evidence.related.length > 0 && onSelectRelated && (
        <p className="bt-evidence-related">
          Related evidence:
          {evidence.related.map((id) => (
            <button type="button" key={id} className="bt-link-btn" onClick={() => onSelectRelated(id)}>
              {titleOf ? titleOf(id) : id}
            </button>
          ))}
        </p>
      )}
    </article>
  )
}
