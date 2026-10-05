// components/RecentActivity.jsx
// Real recent simulation activity, backed by getMyReports() in Dashboard.jsx.
import './RecentActivity.css'

export default function RecentActivity({ reports, loading, onOpen, timeAgo }) {
  return (
    <div className="ract-card">
      <div className="ract-head">
        <h3>Recent Activity</h3>
      </div>

      {loading && <div className="ract-empty">Loading…</div>}

      {!loading && reports.length === 0 && (
        <div className="ract-empty">No simulations yet — start one above to see it here.</div>
      )}

      {!loading && reports.length > 0 && (
        <div className="ract-list">
          {reports.map((r) => (
            <button key={r._id} className="ract-row" onClick={() => onOpen(r)}>
              <span className={`ract-dot ract-${r.result}`} />
              <div className="ract-info">
                <span className="ract-title">
                  {r.guide_title} <span className="ract-mode">· {r.mode === 'red' ? 'Red Team' : 'Blue Team'}</span>
                </span>
                <span className="ract-sub">
                  {r.result === 'success' ? 'Completed' : `Failed at ${r.failed_at_stage}`} · {r.score}/{r.max_score} pts
                </span>
              </div>
              <span className="ract-time">{timeAgo(r.created_at)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
