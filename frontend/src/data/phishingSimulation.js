// data/phishingSimulation.js
// Scenario content + deterministic, local scoring for the Red Team
// "FaceWorld Account Security Verification" phishing simulation.
// Pure functions only — no network calls, no AI dependency.
//
// The target is procedurally generated from whatever name the student
// enters: same name always yields the same persona (deterministic hash),
// but different names yield a genuinely different role, organization,
// email domain, activity, and security bulletin — not reskinned copy.

// Two fictional attack platforms the student can choose between. Both are
// original fictional brands — never a real company's name, logo, or trade
// dress — but styled to genuinely read as "personal social media" / "online
// banking" rather than generic business software.
export const PLATFORM_TYPES = {
  social: {
    key: 'social',
    attackLabel: 'Social Media Account Takeover',
    description: 'Steal a personal login via a fake "new device sign-in" or "account flagged" lure.',
    platform: 'FaceWorld',
    title: 'FaceWorld Account Security Verification',
    trainingDomain: 'faceworld-training.local',
    defaultPath: 'login/verify',
    loginTitle: 'Log in to FaceWorld',
  },
  banking: {
    key: 'banking',
    attackLabel: 'Online Banking Credential Theft',
    description: 'Steal net-banking credentials via a fake UPI alert, KYC update or account-verification lure.',
    platform: 'Sarvodaya Trust Bank',
    title: 'Sarvodaya Trust Bank Account Verification',
    trainingDomain: 'sarvodayatrust-training.local',
    defaultPath: 'secure/signin',
    loginTitle: 'Log in to Online Banking',
  },
}

export const TRAINING_PASSWORD = 'TrainingOnly!2026'

const ROLES = [
  'Marketing Executive', 'Finance Manager', 'HR Coordinator', 'Sales Director',
  'Product Manager', 'Accounts Officer', 'IT Support Specialist',
  'Executive Assistant', 'Operations Lead', 'Placement Coordinator',
]

const ORGANIZATIONS = [
  { name: 'Kaveri Textiles', domain: 'kaveritextiles.example', industry: 'Textile Manufacturing', size: '500–1,000 employees', founded: '1998', about: 'Manufactures cotton and silk fabrics for exporters and retailers across Tamil Nadu and Gujarat.' },
  { name: 'Sahyadri Institute of Technology', domain: 'sahyadriit.example', industry: 'Higher Education', size: '200–500 staff', founded: '2005', about: 'A private engineering college that handles semester fees, examinations and campus placements for about 4,000 students.' },
  { name: 'Deccan Logistics', domain: 'deccanlogistics.example', industry: 'Logistics & Courier', size: '1,000+ employees', founded: '2009', about: 'Runs parcel and freight delivery across Pune, Hyderabad and Bengaluru and handles customs and e-way bill paperwork.' },
  { name: 'Ganga Power Distribution', domain: 'gangapower.example', industry: 'Electricity Utility', size: '1,000+ employees', founded: '1994', about: 'A regional electricity distribution company that issues monthly bills, meter readings and disconnection notices.' },
  { name: 'Lotus Finserv', domain: 'lotusfinserv.example', industry: 'Financial Services', size: '200–500 employees', founded: '2012', about: 'A non-banking finance company that offers small-business loans and handles KYC checks and UPI collections.' },
  { name: 'Navbharat Tech Solutions', domain: 'navbharattech.example', industry: 'IT Services', size: '250–500 employees', founded: '2014', about: 'A Bengaluru software services firm that hires interns and fresh graduates through campus drives every semester.' },
]

const LOCATIONS = [
  'Pune, Maharashtra Area', 'Bengaluru, Karnataka Area', 'Hyderabad, Telangana Area',
  'Chennai, Tamil Nadu Area', 'Ahmedabad, Gujarat Area', 'Jaipur, Rajasthan Area',
]

const PRIOR_ROLES = ['Coordinator', 'Associate', 'Analyst', 'Specialist', 'Assistant Manager']
const PRIOR_ORGS = ['Sundaram Softworks', 'Kalinga Industries', 'Malabar Consulting Group', 'Himalaya Solutions', 'Narmada Holdings']

const ACTIVITY_TEMPLATES = [
  (org) => `Great energy at the ${org.name} annual day this week!`,
  (org, platformName) => `Ugh, ${platformName} made me reset my password again. Third time this month.`,
  (org) => `Excited to be representing ${org.name} at the regional meet in Mumbai next week.`,
  (org, platformName) => `Anyone else's ${platformName} account acting up today? Keeps asking me to re-verify.`,
  (org) => `Wrapping up a big festive-season quarter for the team at ${org.name}.`,
  (org, platformName) => `Finally got my ${platformName} profile verified after three tries. Worth it though.`,
]

const SECURITY_TEMPLATES = [
  () => "Please verify sender addresses before clicking links in emails referencing password resets or account verification. Never share your OTP, UPI PIN or password with anyone. Report anything suspicious to IT Security.",
  (org) => `${org.name} IT reminds staff: legitimate password-reset emails never ask you to confirm your password by replying or visiting a third-party link.`,
]

function hashString(str) {
  let h = 0
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0
  }
  return Math.abs(h)
}

function splitName(fullName) {
  const parts = fullName.trim().split(/\s+/)
  const first = parts[0] || 'Rahul'
  const last = parts.length > 1 ? parts[parts.length - 1] : 'Verma'
  return { first, last }
}

function pickTwoDistinct(pool, seed) {
  const i1 = seed % pool.length
  let i2 = Math.floor(seed / 3) % pool.length
  if (i2 === i1) i2 = (i2 + 1) % pool.length
  return [pool[i1], pool[i2]]
}

// Procedurally generates a target persona from whatever name the student
// enters. Deterministic: the same name always resolves to the same
// persona, so scoring stays reproducible, but different names resolve to
// a genuinely different role, company, domain, and content.
export function generateTarget(rawName, platform = PLATFORM_TYPES.social) {
  const name = (rawName || '').trim().replace(/\s+/g, ' ') || 'Rahul Verma'
  const seed = hashString(name.toLowerCase())
  const { first, last } = splitName(name)

  const role = ROLES[seed % ROLES.length]
  const org = ORGANIZATIONS[Math.floor(seed / 7) % ORGANIZATIONS.length]
  const location = LOCATIONS[Math.floor(seed / 13) % LOCATIONS.length]
  const priorRole = PRIOR_ROLES[Math.floor(seed / 17) % PRIOR_ROLES.length]
  const priorOrg = PRIOR_ORGS[Math.floor(seed / 19) % PRIOR_ORGS.length]
  const connections = 100 + (seed % 9) * 50
  const yearsAtCurrent = 1 + (seed % 6)
  const [activityFn1, activityFn2] = pickTwoDistinct(ACTIVITY_TEMPLATES, seed)
  const securityFn = SECURITY_TEMPLATES[Math.floor(seed / 23) % SECURITY_TEMPLATES.length]

  // Who the lure pretends to come from. Deterministic per target, like the rest
  // of the persona: 'platform' = the service itself (FaceWorld / the bank),
  // 'corporate' = the target's own employer (IT / accounts) acting about it.
  const lureStyle = Math.floor(seed / 29) % 2 === 0 ? 'platform' : 'corporate'

  const emailLocal = `${first}.${last}`.toLowerCase().replace(/[^a-z.]/g, '')
  const trainingFirst = first.toLowerCase().replace(/[^a-z]/g, '') || 'rahul'

  return {
    name,
    firstName: first,
    role,
    organization: org.name,
    orgDomain: org.domain,
    orgIndustry: org.industry,
    orgSize: org.size,
    orgFounded: org.founded,
    orgAbout: org.about,
    location,
    lureStyle,
    connections: `${connections}+`,
    email: `${emailLocal}@${org.domain}`,
    trainingAccount: `${trainingFirst}.training@sentinel.local`,
    trainingPassword: TRAINING_PASSWORD,
    about: `${yearsAtCurrent} year${yearsAtCurrent === 1 ? '' : 's'} in ${org.industry.toLowerCase()}. Currently a ${role.toLowerCase()} at ${org.name}.`,
    experience: [
      { role, org: org.name, years: `${2026 - yearsAtCurrent} — Present` },
      { role: priorRole, org: priorOrg, years: `${2026 - yearsAtCurrent - 3} — ${2026 - yearsAtCurrent}` },
    ],
    activityPosts: [
      { text: activityFn1(org, platform.platform), time: '6d', likes: 8 + (seed % 50) },
      { text: activityFn2(org, platform.platform), time: '2d', likes: 8 + (Math.floor(seed / 3) % 50) },
    ],
    securityBulletin: securityFn(org),
    messenger: `${platform.platform} Messenger`,
    handle: `@${emailLocal}`,
  }
}

// Stage 1 — Reconnaissance: sections the student must inspect, built fresh
// from the generated target so content genuinely differs per persona.
export function buildIntelSections(target, platform = PLATFORM_TYPES.social) {
  return [
    {
      id: 'profile',
      label: 'Professional Profile',
      log: 'Target profile accessed',
      kind: 'profile',
      data: {
        headline: `${target.role} at ${target.organization}`,
        location: target.location,
        connections: target.connections,
        about: target.about,
        experience: target.experience,
      },
    },
    {
      id: 'activity',
      label: 'Recent Activity',
      log: 'Recent activity discovered',
      kind: 'feed',
      data: { posts: target.activityPosts },
    },
    {
      id: 'organization',
      label: 'Organization',
      log: 'Organization identified',
      kind: 'org',
      data: {
        industry: target.orgIndustry,
        size: target.orgSize,
        founded: target.orgFounded,
        about: `${target.orgAbout} IT enforces a standard password-expiry policy; staff are known to use ${platform.platform} for ${platform.key === 'banking' ? 'personal banking' : 'personal social media'}.`,
      },
    },
    {
      id: 'security',
      label: 'Security Context',
      log: 'Security posture noted',
      kind: 'bulletin',
      data: {
        title: 'Security Awareness Reminder',
        severity: 'INFO',
        sentTo: `All ${target.organization} Staff`,
        body: target.securityBulletin,
      },
    },
    {
      id: 'contact',
      label: 'Contact Information',
      log: 'Communication channel identified',
      kind: 'contact',
      data: { email: target.email, messenger: target.messenger, handle: target.handle },
    },
  ]
}

// Stage 2 — Target Profiling: intel the student can choose to build into the
// campaign, built fresh per target. `value: 'high'` items meaningfully raise
// Relevance when referenced in the email; `value: 'low'` items are
// plausible-looking filler that doesn't help.
export function buildIntelItems(target, platform = PLATFORM_TYPES.social) {
  const orgKeyword = target.organization.split(' ')[0].toLowerCase()
  const platformKeyword = platform.platform.toLowerCase()
  return [
    { id: 'role',      label: target.role,                             value: 'high', keywords: [target.role.toLowerCase(), ...target.role.toLowerCase().split(' ')] },
    { id: 'activity',  label: `Recent ${platform.platform} activity`,  value: 'high', keywords: [platformKeyword, 'password reset', 'password'] },
    { id: 'interests', label: 'Personal interests',                    value: 'low',  keywords: ['hobby', 'weekend', 'interest'] },
    { id: 'org',       label: 'Organization context',                  value: 'high', keywords: [orgKeyword, target.organization.toLowerCase()] },
    { id: 'generic',   label: 'Generic information',                   value: 'low',  keywords: ['company', 'general'] },
  ]
}

const GENERIC_DOMAINS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com']
const URGENCY_WORDS = [
  'urgent', 'immediately', 'now', 'asap', 'expire', 'expires', 'expiring',
  '24 hours', 'action required', 'verify now', 'suspended', 'final notice', 'locked out',
]

function clamp(n, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n)))
}

export function scoreRelevance({ subject = '', body = '', selectedIntel = [], target }) {
  const text = `${subject} ${body}`.toLowerCase()
  let score = 15
  selectedIntel.forEach((item) => {
    const hit = item.keywords.some((k) => text.includes(k))
    if (hit) score += item.value === 'high' ? 18 : 4
  })
  if (target && text.includes(target.firstName.toLowerCase())) score += 10
  return clamp(score)
}

export function scoreCredibility({ sender = '', body = '', target }) {
  let score = 55
  const domain = (sender.split('@')[1] || '').toLowerCase()
  const orgKeyword = target ? target.organization.split(' ')[0].toLowerCase() : null
  if (!domain) score -= 25
  else if (GENERIC_DOMAINS.some((d) => domain.includes(d))) score -= 30
  else if (orgKeyword && domain.includes(orgKeyword)) score += 25
  else score += 5

  const exclamations = (body.match(/!/g) || []).length
  if (exclamations >= 3) score -= 15
  const shoutyWords = (body.match(/\b[A-Z]{4,}\b/g) || []).length
  if (shoutyWords >= 2) score -= 15
  if (body.trim().length < 40) score -= 10
  return clamp(score)
}

export function scoreUrgency({ subject = '', body = '', cta = '' }) {
  const text = `${subject} ${body} ${cta}`.toLowerCase()
  const hits = URGENCY_WORDS.filter((w) => text.includes(w)).length
  return clamp(10 + hits * 15)
}

export function scoreSuspicion({ credibility, urgency, subject = '' }) {
  let score = (100 - credibility) * 0.45 + urgency * 0.35
  if (!subject || subject.trim().length < 8) score += 15
  return clamp(score)
}

export function analyzeCampaign({ sender, subject, body, cta, selectedIntel, target }) {
  const relevance = scoreRelevance({ subject, body, selectedIntel, target })
  const credibility = scoreCredibility({ sender, body, target })
  const urgency = scoreUrgency({ subject, body, cta })
  const suspicion = scoreSuspicion({ credibility, urgency, subject })
  return { relevance, credibility, urgency, suspicion }
}

// Composite campaign quality used purely to decide the target's reaction.
export function campaignQuality(analysis) {
  return clamp(analysis.relevance * 0.35 + analysis.credibility * 0.35 + (100 - analysis.suspicion) * 0.3)
}

// Deterministic outcome thresholds — no randomness, reproducible for teaching.
export function determineDeliveryOutcome(analysis) {
  const quality = campaignQuality(analysis)
  if (quality < 35) return { outcome: 'ignored', quality }
  if (quality < 60) return { outcome: 'partial', quality }
  return { outcome: 'clicked', quality }
}

export function getFailureReasons(analysis) {
  const reasons = []
  if (analysis.relevance < 40) reasons.push('Low contextual relevance')
  if (analysis.credibility < 45) reasons.push('Suspicious sender domain')
  if (analysis.urgency > 75 && analysis.suspicion > 55) reasons.push('Excessive urgency')
  if (analysis.suspicion > 70) reasons.push('Message reads as generic or suspicious')
  if (reasons.length === 0) reasons.push('Overall message lacked a convincing, believable context')
  return reasons
}

export const LEARNING_MOMENTS = {
  ignored: 'Effective social engineering generally relies on believable context rather than obviously unrealistic messages. Attackers who reference specific, accurate details about a target\'s role and organization are far more likely to succeed than those relying on generic urgency alone.',
  partial: 'A message can be believable enough to open but still fail to convert. Small gaps — a slightly-off sender domain, a vague subject line — are often enough for a cautious reader to stop short of clicking.',
  clicked: 'Urgency and specific, accurate context are a powerful combination — this is exactly why security awareness training emphasizes checking sender addresses and resisting pressure to "act now."',
}

// Fictional sender identity that fits the active scenario. The student still
// writes the From line themselves; this only supplies the placeholder example
// and the worked-example draft so the context reads coherently:
//  - platform lure  -> a look-alike of the platform's own notification address
//  - corporate lure -> the target's own (fictional) employer domain
export function buildSenderExample(target, platform = PLATFORM_TYPES.social) {
  if (target?.lureStyle === 'corporate') {
    return `${platform.key === 'banking' ? 'accounts' : 'it-helpdesk'}@${target.orgDomain}`
  }
  return platform.key === 'banking' ? 'alerts@sarvodayatrust-alerts.example' : 'security@faceworld-notify.example'
}

// A deliberately strong, worked example the student can use or adapt after
// a failed attempt — references the actual generated role/org/activity so
// it visibly demonstrates why specific context outperforms generic urgency.
export function buildSuggestedDraft(target, platform = PLATFORM_TYPES.social) {
  const sender = buildSenderExample(target, platform)
  const corporate = target.lureStyle === 'corporate'
  if (platform.key === 'banking') {
    if (corporate) {
      return {
        sender,
        subject: `${target.organization} Accounts: action required on your ${platform.platform} salary account`,
        body: `Hi ${target.firstName},\n\nThe accounts team at ${target.organization} is re-confirming salary-account KYC details for every ${target.role.toLowerCase()} before this month's payout. Your ${platform.platform} salary account is still pending, and we don't want your credit delayed.\n\nPlease verify your net-banking login within 24 hours so the payout goes through on time.`,
        cta: 'Verify Salary Account',
      }
    }
    return {
      sender,
      subject: `${platform.platform} alert: verify a recent sign-in and UPI payment attempt`,
      body: `Hi ${target.firstName},\n\nAs ${target.role.toLowerCase()} at ${target.organization}, you often sign in while traveling for work — which is why this one caught our attention. We saw a sign-in to your ${platform.platform} account from a new device, followed by a UPI payment attempt of Rs 4,999 (simulated reference UPI-SIM-48213), and wanted to confirm it was really you.\n\nPlease verify within 24 hours and re-confirm your KYC details so we don't have to temporarily limit account access.`,
      cta: 'Verify My Account',
    }
  }
  if (corporate) {
    return {
      sender,
      subject: `${target.organization} IT: please verify your ${platform.platform} account`,
      body: `Hi ${target.firstName},\n\nOur records show your ${platform.platform} account flagged another password reset attempt this week. Since you handle ${target.role.toLowerCase()} work that depends on ${platform.platform} access, IT wanted to make sure this was actually you before locking things down.\n\nPlease confirm your account within 24 hours to avoid any disruption.`,
      cta: 'Confirm My Account',
    }
  }
  return {
    sender,
    subject: `${platform.platform} Security: action required on your account`,
    body: `Hi ${target.firstName},\n\nWe noticed a password reset attempt on your ${platform.platform} account from a device near ${target.location.replace(' Area', '')}. As ${/^[aeiou]/i.test(target.role) ? 'an' : 'a'} ${target.role.toLowerCase()} at ${target.organization}, you rely on ${platform.platform} to stay in touch with partners, so we wanted to make sure this was really you.\n\nPlease confirm your account within 24 hours or access to your ${platform.platform} profile may be limited.`,
    cta: 'Secure My Account',
  }
}

export function buildIndicators({ sender, subject, simulatedLink, targetAccount, timestamp, credentialSubmitted }) {
  const indicators = [
    { type: 'suspicious_sender', label: 'Suspicious sender domain', detail: sender },
    { type: 'suspicious_domain', label: 'Suspicious training URL', detail: simulatedLink },
  ]
  // Only report credential/auth indicators if the target actually got that far —
  // a failed or ignored campaign never produces these artifacts.
  if (credentialSubmitted) {
    indicators.push(
      { type: 'credential_submission', label: 'Credential submission', detail: targetAccount },
      { type: 'authentication_anomaly', label: 'Authentication anomaly', detail: 'Login attempt did not match the target\'s normal access pattern' },
      { type: 'unexpected_login', label: 'Unexpected login attempt', detail: `Subject line referenced: "${subject}"` },
    )
  }
  return indicators.map((i) => ({ ...i, timestamp }))
}
