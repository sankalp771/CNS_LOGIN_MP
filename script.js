// Secure Login System using Captcha and Hashing with SALT (No backend)
// - Stores username and SHA-256 hashed password WITH SALT in localStorage
// - Validates captcha on register and login
// - Refreshes captcha on every attempt and toggle
// - Uses username as part of salt for better security

// ----------------------------
// Utilities
// ----------------------------

/** Generate a random 6-character alphanumeric captcha */
function generateCaptcha() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // exclude confusing chars like I, O, 0, 1
  let out = '';
  for (let i = 0; i < 6; i++) {
    const idx = Math.floor(Math.random() * chars.length);
    out += chars[idx];
  }
  return out;
}

/** Convert ArrayBuffer to hexadecimal string */
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  const hex = [];
  for (const b of bytes) {
    hex.push(b.toString(16).padStart(2, '0'));
  }
  return hex.join('');
}

/**
 * Hash text using SHA-256 via Web Crypto API
 * Returns a Promise<string> of hex digest
 */
async function sha256(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const hex = bufferToHex(digest);
  return hex;
}

/**
 * Hash password with salt (username-based + static salt)
 * This prevents rainbow table attacks and makes same passwords have different hashes
 */
async function sha256WithSalt(password, username) {
  const STATIC_SALT = 'CNS_PROJECT_2024_SECURE_SALT'; // Static application salt
  const dynamicSalt = username.toLowerCase(); // Per-user salt
  const saltedPassword = dynamicSalt + password + STATIC_SALT;
  return await sha256(saltedPassword);
}

/** Persist and read users map from localStorage */
function getUsersStore() {
  const raw = localStorage.getItem('users');
  if (!raw) return {};
  try { return JSON.parse(raw) || {}; } catch { return {}; }
}

function setUsersStore(map) {
  localStorage.setItem('users', JSON.stringify(map));
}

// ----------------------------
// Rate Limiting (Simple Implementation)
// ----------------------------
const LOGIN_ATTEMPTS = {};
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 60000; // 1 minute in milliseconds

function checkRateLimit(username) {
  const now = Date.now();
  if (!LOGIN_ATTEMPTS[username]) {
    LOGIN_ATTEMPTS[username] = { count: 0, lastAttempt: now };
    return true;
  }

  const attempt = LOGIN_ATTEMPTS[username];

  // Reset if lockout time has passed
  if (now - attempt.lastAttempt > LOCKOUT_TIME) {
    attempt.count = 0;
    attempt.lastAttempt = now;
    return true;
  }

  // Check if locked out
  if (attempt.count >= MAX_ATTEMPTS) {
    const timeLeft = Math.ceil((LOCKOUT_TIME - (now - attempt.lastAttempt)) / 1000);
    return { locked: true, timeLeft };
  }

  return true;
}

function recordFailedAttempt(username) {
  const now = Date.now();
  if (!LOGIN_ATTEMPTS[username]) {
    LOGIN_ATTEMPTS[username] = { count: 1, lastAttempt: now };
  } else {
    LOGIN_ATTEMPTS[username].count++;
    LOGIN_ATTEMPTS[username].lastAttempt = now;
  }
}

function resetAttempts(username) {
  if (LOGIN_ATTEMPTS[username]) {
    LOGIN_ATTEMPTS[username].count = 0;
  }
}

// ----------------------------
// DOM elements
// ----------------------------

const btnShowLogin = document.getElementById('show-login');
const btnShowRegister = document.getElementById('show-register');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const messageEl = document.getElementById('message');

// Login refs
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const loginCaptchaText = document.getElementById('login-captcha-text');
const loginCaptchaInput = document.getElementById('login-captcha-input');
const loginRefreshBtn = document.getElementById('login-refresh-captcha');

// Register refs
const regUsername = document.getElementById('reg-username');
const regPassword = document.getElementById('reg-password');
const regCaptchaText = document.getElementById('reg-captcha-text');
const regCaptchaInput = document.getElementById('reg-captcha-input');
const regRefreshBtn = document.getElementById('reg-refresh-captcha');

// ----------------------------
// State and helpers
// ----------------------------

function setMessage(text, type = '') {
  messageEl.textContent = text;
  messageEl.classList.remove('success', 'error');
  if (type) messageEl.classList.add(type);
}

function refreshLoginCaptcha() {
  const c = generateCaptcha();
  loginCaptchaText.textContent = c;
}

function refreshRegisterCaptcha() {
  const c = generateCaptcha();
  regCaptchaText.textContent = c;
}

function showLogin() {
  btnShowLogin.classList.add('active');
  btnShowRegister.classList.remove('active');
  btnShowLogin.setAttribute('aria-pressed', 'true');
  btnShowRegister.setAttribute('aria-pressed', 'false');
  loginForm.classList.add('form-active');
  registerForm.classList.remove('form-active');
  registerForm.hidden = true;
  loginForm.hidden = false;
  setMessage('');
  refreshLoginCaptcha();
}

function showRegister() {
  btnShowRegister.classList.add('active');
  btnShowLogin.classList.remove('active');
  btnShowRegister.setAttribute('aria-pressed', 'true');
  btnShowLogin.setAttribute('aria-pressed', 'false');
  registerForm.classList.add('form-active');
  loginForm.classList.remove('form-active');
  loginForm.hidden = true;
  registerForm.hidden = false;
  setMessage('');
  refreshRegisterCaptcha();
}

// ----------------------------
// Initialize
// ----------------------------

// Prefill sample for convenience during testing
if (!localStorage.getItem('users')) {
  console.log('🔒 CNS Project: Secure Login System initialized');
  console.log('📝 No users stored yet. Register a user to test login.');
  console.log('🔐 Security Features:');
  console.log('   - SHA-256 Hashing with Salt');
  console.log('   - Rate Limiting (5 attempts per minute)');
  console.log('   - Captcha Validation');
}

showLogin(); // default view

// ----------------------------
// Events: Toggle
// ----------------------------

btnShowLogin.addEventListener('click', showLogin);
btnShowRegister.addEventListener('click', showRegister);

// Captcha refresh buttons
loginRefreshBtn.addEventListener('click', () => {
  refreshLoginCaptcha();
  loginCaptchaInput.value = '';
  setMessage('Captcha refreshed.', '');
});

regRefreshBtn.addEventListener('click', () => {
  refreshRegisterCaptcha();
  regCaptchaInput.value = '';
  setMessage('Captcha refreshed.', '');
});

// ----------------------------
// Events: Register
// ----------------------------

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = (regUsername.value || '').trim();
  const password = regPassword.value || '';
  const captchaInput = (regCaptchaInput.value || '').trim().toUpperCase();
  const expectedCaptcha = regCaptchaText.textContent.trim().toUpperCase();

  if (!username || !password) {
    setMessage('Please enter username and password.', 'error');
    refreshRegisterCaptcha();
    return;
  }

  if (username.length < 3) {
    setMessage('Username must be at least 3 characters.', 'error');
    refreshRegisterCaptcha();
    return;
  }

  if (password.length < 6) {
    setMessage('Password must be at least 6 characters.', 'error');
    refreshRegisterCaptcha();
    return;
  }

  if (captchaInput !== expectedCaptcha) {
    setMessage('Invalid captcha. Please try again.', 'error');
    refreshRegisterCaptcha();
    regCaptchaInput.value = '';
    return;
  }

  const users = getUsersStore();
  if (users[username]) {
    setMessage('Username already exists. Choose another.', 'error');
    refreshRegisterCaptcha();
    return;
  }

  // Hash with salt (username + static salt)
  const hashed = await sha256WithSalt(password, username);
  console.log('[Register] Username:', username);
  console.log('[Register] SHA-256 Hash (with salt):', hashed);
  console.log('[Security] Salt includes username + static application salt');

  users[username] = {
    hashedPassword: hashed,
    createdAt: new Date().toISOString()
  };
  setUsersStore(users);

  setMessage('✅ Registration successful! You can login now.', 'success');

  // Clear inputs and switch to login
  regUsername.value = '';
  regPassword.value = '';
  regCaptchaInput.value = '';

  setTimeout(() => {
    showLogin();
    loginUsername.value = username;
  }, 1000);
});

// ----------------------------
// Events: Login
// ----------------------------

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = (loginUsername.value || '').trim();
  const password = loginPassword.value || '';
  const captchaInput = (loginCaptchaInput.value || '').trim().toUpperCase();
  const expectedCaptcha = loginCaptchaText.textContent.trim().toUpperCase();

  if (!username || !password) {
    setMessage('Please enter username and password.', 'error');
    refreshLoginCaptcha();
    return;
  }

  // Check rate limiting
  const rateLimitCheck = checkRateLimit(username);
  if (rateLimitCheck.locked) {
    setMessage(`🔒 Too many attempts. Try again in ${rateLimitCheck.timeLeft} seconds.`, 'error');
    refreshLoginCaptcha();
    loginCaptchaInput.value = '';
    return;
  }

  if (captchaInput !== expectedCaptcha) {
    setMessage('Invalid captcha. Please try again.', 'error');
    refreshLoginCaptcha();
    loginCaptchaInput.value = '';
    recordFailedAttempt(username);
    return;
  }

  const users = getUsersStore();
  const user = users[username];
  if (!user) {
    setMessage('Invalid credentials.', 'error');
    refreshLoginCaptcha();
    recordFailedAttempt(username);
    return;
  }

  // Hash the attempt with the same salt method
  const hashedAttempt = await sha256WithSalt(password, username);
  console.log('[Login] Username:', username);
  console.log('[Login] Attempt Hash (with salt):', hashedAttempt);
  console.log('[Login] Stored Hash:', user.hashedPassword);

  if (hashedAttempt === user.hashedPassword) {
    resetAttempts(username);
    setMessage('✅ Login Successful! Redirecting...', 'success');
    // Create a lightweight session and navigate to the explanation page
    localStorage.setItem('authUser', username);
    setTimeout(() => { window.location.href = 'success.html'; }, 800);
  } else {
    recordFailedAttempt(username);
    const attemptsLeft = MAX_ATTEMPTS - (LOGIN_ATTEMPTS[username]?.count || 0);
    setMessage(`Invalid credentials. ${attemptsLeft} attempts remaining.`, 'error');
  }

  // Refresh captcha after each attempt
  refreshLoginCaptcha();
  loginCaptchaInput.value = '';
});