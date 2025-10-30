// Secure Login System using Captcha and Hashing (No backend)
// - Stores username and SHA-256 hashed password in localStorage
// - Validates captcha on register and login
// - Refreshes captcha on every attempt and toggle

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
  // no users yet; just a hint in console
  console.log('No users stored yet. Register a user to test login.');
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

  const hashed = await sha256(password);
  console.log('[Register] Username:', username, 'SHA-256 Hash:', hashed);

  users[username] = { hashedPassword: hashed };
  setUsersStore(users);

  setMessage('Registration successful! You can login now.', 'success');

  // Clear inputs and switch to login
  regPassword.value = '';
  regCaptchaInput.value = '';
  showLogin();
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

  if (captchaInput !== expectedCaptcha) {
    setMessage('Invalid captcha. Please try again.', 'error');
    refreshLoginCaptcha();
    loginCaptchaInput.value = '';
    return;
  }

  const users = getUsersStore();
  const user = users[username];
  if (!user) {
    setMessage('Invalid credentials.', 'error');
    refreshLoginCaptcha();
    return;
  }

  const hashedAttempt = await sha256(password);
  console.log('[Login] Username:', username, 'Attempt Hash:', hashedAttempt);

  if (hashedAttempt === user.hashedPassword) {
    setMessage('Login Successful.', 'success');
    // Create a lightweight session and navigate to the explanation page
    localStorage.setItem('authUser', username);
    setTimeout(() => { window.location.href = 'success.html'; }, 350);
  } else {
    setMessage('Invalid credentials.', 'error');
  }

  // Refresh captcha after each attempt
  refreshLoginCaptcha();
  loginCaptchaInput.value = '';
});


