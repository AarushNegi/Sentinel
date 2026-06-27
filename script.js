/* ===========================
   script.js — CyberSim Login
   =========================== */

// ── Password toggle ──────────────────────────────────────────────
const toggleBtn  = document.getElementById('togglePw');
const pwInput    = document.getElementById('password');
const eyeIcon    = document.getElementById('eyeIcon');

const EYE_OPEN = `
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
  <circle cx="12" cy="12" r="3"/>
`;

const EYE_CLOSED = `
  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8
           a18.45 18.45 0 0 1 5.06-5.94"/>
  <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8
           a18.5 18.5 0 0 1-2.16 3.19"/>
  <line x1="1" y1="1" x2="23" y2="23"/>
`;

let pwVisible = false;

toggleBtn.addEventListener('click', () => {
  pwVisible = !pwVisible;
  pwInput.type    = pwVisible ? 'text' : 'password';
  eyeIcon.innerHTML = pwVisible ? EYE_CLOSED : EYE_OPEN;
});


// ── Remember me checkbox ─────────────────────────────────────────
const rememberCheckbox = document.getElementById('rememberMe');
rememberCheckbox.addEventListener('change', () => {
  // Persist preference
  localStorage.setItem('rememberMe', rememberCheckbox.checked);
});

// Restore on load
const savedRemember = localStorage.getItem('rememberMe');
if (savedRemember !== null) {
  rememberCheckbox.checked = savedRemember === 'true';
}


// ── Form submission ──────────────────────────────────────────────
const loginForm = document.getElementById('loginForm');

loginForm.addEventListener('submit', (e) => {
  e.preventDefault();

  const email    = document.getElementById('email').value.trim();
  const password = pwInput.value;

  // Simple validation
  if (!email || !validateEmail(email)) {
    shakeInput('email');
    return;
  }

  if (!password || password.length < 6) {
    shakeInput('password');
    return;
  }

  // Simulate loading state
  const btn = loginForm.querySelector('.btn-primary');
  btn.disabled    = true;
  btn.textContent = 'Signing in…';

  setTimeout(() => {
    btn.disabled      = false;
    btn.innerHTML     = `Sign In to Dashboard
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="5" y1="12" x2="19" y2="12"/>
        <polyline points="12 5 19 12 12 19"/>
      </svg>`;
    // In a real app, redirect or show dashboard here
    showToast('Welcome back! Loading dashboard…');
  }, 1400);
});


// ── Guest button ─────────────────────────────────────────────────
document.getElementById('guestBtn').addEventListener('click', () => {
  showToast('Continuing as guest…');
});


// ── Forgot Password ──────────────────────────────────────────────
document.querySelector('.forgot-link').addEventListener('click', (e) => {
  e.preventDefault();
  showToast('Password reset link will be sent to your email.');
});


// ── Helpers ──────────────────────────────────────────────────────
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function shakeInput(id) {
  const el = document.getElementById(id).closest('.input-group');
  el.style.animation = 'none';
  el.offsetHeight; // reflow
  el.style.animation = 'shake 0.35s ease';
  el.style.borderColor = 'rgba(239,68,68,0.6)';
  setTimeout(() => {
    el.style.borderColor = '';
    el.style.animation   = '';
  }, 1200);
}

function showToast(msg) {
  // Remove existing toasts
  document.querySelectorAll('.toast').forEach(t => t.remove());

  const toast = document.createElement('div');
  toast.className   = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}


// ── Inject dynamic styles ─────────────────────────────────────────
const style = document.createElement('style');
style.textContent = `
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20%       { transform: translateX(-6px); }
  40%       { transform: translateX(6px); }
  60%       { transform: translateX(-4px); }
  80%       { transform: translateX(4px); }
}

.toast {
  position: fixed;
  bottom: 28px;
  left: 50%;
  transform: translateX(-50%) translateY(20px);
  background: #1e293b;
  color: #e2e8f0;
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 10px;
  padding: 12px 22px;
  font-family: 'Inter', sans-serif;
  font-size: 13.5px;
  white-space: nowrap;
  opacity: 0;
  transition: opacity 0.3s, transform 0.3s;
  z-index: 9999;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}

.toast.toast-visible {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}
`;
document.head.appendChild(style);


// ── Animated logs counter ─────────────────────────────────────────
function animateCounter(el, target, duration = 2000) {
  const start   = 0;
  const startTs = performance.now();
  const fmt     = n => n.toLocaleString();

  function step(ts) {
    const elapsed  = ts - startTs;
    const progress = Math.min(elapsed / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = fmt(Math.round(start + (target - start) * ease));
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

// Run counter animation after a short delay
const logsEl = document.getElementById('logsCount');
if (logsEl) {
  setTimeout(() => animateCounter(logsEl, 18392, 2000), 600);
}