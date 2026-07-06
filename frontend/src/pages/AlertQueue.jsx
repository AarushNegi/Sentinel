// pages/AlertQueue.jsx
import { useState } from 'react'
import phishingAlerts from '../data/scenarios/phishing-alerts'
import './AlertQueue.css'

const SEVERITY_COLOR = {
  Low: '#eab308',
  Medium: '#f97316',
  High: '#ef4444'
}

export default function AlertQueue() {
  const [alerts, setAlerts] = useState(phishingAlerts)
  const [expandedId, setExpandedId] = useState(null)

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id)
  }

  const assignToSelf = (id, e) => {
    e.stopPropagation()
    setAlerts(alerts.map(a =>
      a.id === id ? { ...a, status: 'investigating' } : a
    ))
    setExpandedId(id)
  }

  const classify = (id, verdict) => {
    setAlerts(alerts.map(a =>
      a.id === id ? { ...a, status: 'closed', verdict } : a
    ))
  }

  const renderFields = (alert) => {
    return Object.entries(alert.fields).map(([key, value]) => (
      <div className="aq-field-row" key={key}>
        <span className="aq-field-key">{key}:</span>
        <span className="aq-field-value">{value}</span>
      </div>
    ))
  }

  return (
    <div className="aq-wrapper">
      <div className="aq-toolbar">
        <input className="aq-search" placeholder="Search for an alert" />
        <span className="aq-count">{alerts.length} alerts</span>
      </div>

      <div className="aq-table">
        <div className="aq-header-row">
          <span>ID</span>
          <span>Alert rule</span>
          <span>Severity</span>
          <span>Type</span>
          <span>Date</span>
          <span>Status</span>
          <span>Action</span>
        </div>

        {alerts.map((alert) => {
          const isOpen = expandedId === alert.id
          const isCorrect = alert.verdict !== undefined
            ? (alert.verdict === 'true_positive') === alert.isThreat
            : null

          return (
            <div className="aq-row-group" key={alert.id}>
              <div className="aq-row" onClick={() => toggleExpand(alert.id)}>
                <span className="aq-id">{alert.id}</span>
                <span className="aq-rule">
                  {alert.rule}
                  <span className={`aq-caret ${isOpen ? 'open' : ''}`}>⌄</span>
                </span>
                <span style={{ color: SEVERITY_COLOR[alert.severity] }}>{alert.severity}</span>
                <span>{alert.type}</span>
                <span className="aq-date">{alert.timestamp}</span>
                <span className={`aq-status aq-status-${alert.status}`}>
                  <span className="aq-status-dot" />
                  {alert.status === 'unassigned' && 'Awaiting action'}
                  {alert.status === 'investigating' && 'Investigating'}
                  {alert.status === 'closed' && 'Closed'}
                </span>
                <span className="aq-action">
                  {alert.status === 'unassigned' && (
                    <button className="aq-assign-btn" onClick={(e) => assignToSelf(alert.id, e)}>
                      + Assign
                    </button>
                  )}
                  {alert.status !== 'unassigned' && isCorrect !== null && (
                    <span className={`aq-verdict-tag ${isCorrect ? 'correct' : 'incorrect'}`}>
                      {isCorrect ? '✓' : '✕'}
                    </span>
                  )}
                </span>
              </div>

              {isOpen && (
                <div className="aq-details">
                  <p className="aq-desc">{alert.description}</p>

                  <div className="aq-field-grid">
                    <div className="aq-field-row">
                      <span className="aq-field-key">datasource:</span>
                      <span className="aq-field-value">{alert.datasource}</span>
                    </div>
                    {alert.direction && (
                      <div className="aq-field-row">
                        <span className="aq-field-key">direction:</span>
                        <span className="aq-field-value">{alert.direction}</span>
                      </div>
                    )}
                    {renderFields(alert)}
                  </div>

                  {alert.status === 'investigating' && (
                    <div className="aq-classify">
                      <span className="aq-classify-label">Incident classification</span>
                      <button
                        className="aq-classify-btn aq-classify-true"
                        onClick={() => classify(alert.id, 'true_positive')}
                      >
                        True Positive
                      </button>
                      <button
                        className="aq-classify-btn aq-classify-false"
                        onClick={() => classify(alert.id, 'false_positive')}
                      >
                        False Positive
                      </button>
                    </div>
                  )}

                  {alert.status === 'closed' && (
                    <div className={`aq-result ${isCorrect ? 'correct' : 'incorrect'}`}>
                      You marked this as {alert.verdict === 'true_positive' ? 'True Positive' : 'False Positive'} —
                      {isCorrect ? ' correct.' : ' incorrect.'}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}