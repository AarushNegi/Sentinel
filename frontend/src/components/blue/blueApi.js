// components/blue/blueApi.js
// Shared constants and the fetch helper for the Blue Team simulation.

export const API_BASE_URL = 'http://127.0.0.1:5000'

export async function callApi(path, { method = 'POST', body, signal } = {}) {
  const token = localStorage.getItem('token')
  if (!token) {
    return { ok: false, status: 401, data: { error: 'Authentication required.' } }
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    signal,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  let data = {}
  try {
    data = await response.json()
  } catch {
    data = { error: 'Unexpected server response.' }
  }
  return { ok: response.ok, status: response.status, data }
}

export function formatTime(seconds) {
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

export const CLASSIFICATIONS = [
  ['false_positive', 'False positive (benign)'],
  ['phishing_no_compromise', 'Phishing attempt, no compromise'],
  ['credential_compromise', 'Credential compromise'],
  ['malware_infection', 'Malware infection'],
  ['widespread_campaign', 'Widespread campaign with multiple victims'],
]

export const SEVERITIES = ['low', 'medium', 'high', 'critical']

export const ROOT_CAUSES = [
  ['no_user_interaction', 'No user interaction (message only delivered)'],
  ['phishing_link_credential_theft', 'Phishing link: credential theft'],
  ['malicious_attachment_malware', 'Malicious attachment: malware'],
  ['spoofed_sender_social_engineering', 'Spoofed sender: social engineering'],
  ['multiple_vectors', 'Multiple attack vectors'],
]

export const RESIDUAL_RISKS = [
  ['none', 'None: fully contained and recovered'],
  ['low', 'Low'],
  ['medium', 'Medium: remediation gaps remain'],
  ['high', 'High: attacker access or malware remains'],
]

export const DISPOSITIONS = [
  ['investigate_now', 'Investigate now'],
  ['monitor', 'Monitor'],
  ['close_benign', 'Close as benign'],
]

export const IOC_TOOL_LABELS = {
  domain_reputation: 'Domain reputation',
  url_reputation: 'URL reputation',
  ip_reputation: 'IP reputation',
  dns_analysis: 'DNS analysis',
  hash_lookup: 'File hash lookup',
  related_search: 'Related indicators',
}

export const FALLBACK_REASONS = {
  ollama_unavailable: 'the local AI model (Ollama) is not running',
  model_missing: 'the configured AI model is not installed',
  timeout: 'the AI model took too long to respond',
  invalid_output: 'the AI model returned unusable output',
  validation_failed: 'the AI model output failed safety validation',
  ai_disabled: 'AI generation is disabled',
  ollama_error: 'the AI model returned an error',
  generator_error: 'scenario generation failed',
}

export const prettify = (text) =>
  String(text || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

export const clock = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString([], { hour12: false })
}
