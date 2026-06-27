/* ===========================
   script.js — Sentinel Login
   =========================== */

const API_BASE = 'http://localhost:5000';

// ── Password toggle ──────────────────────────────────────────────
const toggleBtn = document.getElementById('togglePw');
const pwInput   = document.getElementById('password');
const eyeIcon   = document.getElementById('eyeIcon');

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
  pwVisible          = !pwVisible;
  pwInput.type       = pwVisible ? 'text' : 'password';
  eyeIcon.innerHTML  = pwVisible ? EYE_CLOSED : EYE_OPEN;
});


// ── Remember me ──────────────────────────────────────────────────
const rememberCheckbox = document.getElementById('rememberMe');

rememberCheckbox.addEventListener('change', () => {
  localStorage.setItem('rememberMe', rememberCheckbox.checked);
});

const savedRemember = localStorage.getItem('rememberMe');
if (savedRemember !== null) {
  rememberCheckbox.checked = savedRemember === 'true';
}

// Pre-fill email if remembered
const savedEmail = localStorage.getItem('savedEmail');
if (savedEmail) {
  document.getElementById('email').value = savedEmail;
}


// ── Form submission — hits /auth/login ───────────────────────────
const loginForm = document.getElementById('loginForm');
const btn       = loginForm.querySelector('.btn-primary');

const BTN_DEFAULT = `Sign In to Dashboard
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
       stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
    <line x1="5" y1="12" x2="19" y2="12"/>
    <polyline points="12 5 19 12 12 19"/>
  </svg>`;

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const email    = document.getElementById('email').value.trim();
  const password = pwInput.value;

  // Client-side validation
  if (!email || !validateEmail(email)) {
    shakeInput('email');
    showToast('Please enter a valid email address.', 'error');
    return;
  }

  if (!password || password.length < 6) {
    shakeInput('password');
    showToast('Password must be at least 6 characters.', 'error');
    return;
  }

  // Loading state
  btn.disabled  = true;
  btn.innerHTML = 'Signing in…';

  try {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok) {
      // Save JWT token
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));

      // Save email if remember me is checked
      if (rememberCheckbox.checked) {
        localStorage.setItem('savedEmail', email);
      } else {
        localStorage.removeItem('savedEmail');
      }

      showToast(`Welcome back, ${data.user.name}! Loading dashboard…`, 'success');

      // Redirect to dashboard after short delay
      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 1200);

    } else {
      // Server returned an error
      showToast(data.error || 'Login failed. Please try again.', 'error');
      btn.disabled  = false;
      btn.innerHTML = BTN_DEFAULT;
    }

  } catch (err) {
    // Network/server not running
    showToast('Cannot connect to server. Is it running?', 'error');
    btn.disabled  = false;
    btn.innerHTML = BTN_DEFAULT;
  }
});


// ── Guest button — hits /auth/guest ─────────────────────────────
document.getElementById('guestBtn').addEventListener('click', async () => {
  try {
    const response = await fetch(`${API_BASE}/auth/guest`, { method: 'POST' });
    const data     = await response.json();

    if (response.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      showToast('Continuing as guest…', 'success');
      setTimeout(() => { window.location.href = 'dashboard.html'; }, 1200);
    }
  } catch (err) {
    showToast('Cannot connect to server.', 'error');
  }
});


// ── Forgot Password ──────────────────────────────────────────────
document.querySelector('.forgot-link').addEventListener('click', (e) => {
  e.preventDefault();
  showToast('Password reset — coming soon!', 'info');
});


// ── Helpers ──────────────────────────────────────────────────────
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function shakeInput(id) {
  const el = document.getElementById(id).closest('.input-group');
  el.style.animation   = 'none';
  el.offsetHeight;
  el.style.animation   = 'shake 0.35s ease';
  el.style.borderColor = 'rgba(239,68,68,0.6)';
  setTimeout(() => {
    el.style.borderColor = '';
    el.style.animation   = '';
  }, 1200);
}

// Toast — supports success / error / info types
function showToast(msg, type = 'info') {
  document.querySelectorAll('.toast').forEach(t => t.remove());

  const colors = {
    success: '#22c55e',
    error  : '#ef4444',
    info   : '#3b82f6'
  };

  const toast       = document.createElement('div');
  toast.className   = 'toast';
  toast.textContent = msg;
  toast.style.borderColor = colors[type] || colors.info;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}


// ── Dynamic styles ────────────────────────────────────────────────
const style       = document.createElement('style');
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
  const startTs = performance.now();
  const fmt     = n => n.toLocaleString();

  function step(ts) {
    const elapsed  = ts - startTs;
    const progress = Math.min(elapsed / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3);
    el.textContent = fmt(Math.round(target * ease));
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

const logsEl = document.getElementById('logsCount');
if (logsEl) {
  setTimeout(() => animateCounter(logsEl, 18392, 2000), 600);
}