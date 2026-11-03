/**
 * SecureShare - Client-side interactive scripts
 * Externalized from templates to enforce strict Content Security Policy (no inline scripts).
 */
document.addEventListener('DOMContentLoaded', () => {

  /* ── 3D Tilt on Cards ── */
  document.querySelectorAll('.card').forEach(card => {
    card.addEventListener('mousemove', e => {
      const rect = card.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = (e.clientX - cx) / rect.width;
      const dy = (e.clientY - cy) / rect.height;
      card.style.transform = `perspective(900px) rotateX(${-dy * 4}deg) rotateY(${dx * 4}deg) translateY(-3px)`;
    });
    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
    });
  });

  /* ── Button Ripple Effect ── */
  document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
      const rect = this.getBoundingClientRect();
      const ripple = document.createElement('span');
      ripple.className = 'ripple-effect';
      ripple.style.left = `${e.clientX - rect.left}px`;
      ripple.style.top = `${e.clientY - rect.top}px`;
      const size = Math.max(rect.width, rect.height) * 0.5;
      ripple.style.setProperty('--ripple-size', `${size}px`);

      this.appendChild(ripple);
      setTimeout(() => ripple.remove(), 550);
    });
  });

  /* ── Password Visibility Toggle ── */
  document.querySelectorAll('[data-toggle-password]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-toggle-password');
      const input = document.getElementById(targetId);
      if (!input) return;
      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      btn.textContent = isHidden ? '🙈' : '👁';
      btn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
    });
  });

  /* ── Password Strength Meter (Registration) ── */
  const pwInput = document.getElementById('r-pw');
  const bar = document.getElementById('pw-bar');
  const hint = document.getElementById('pw-hint');
  if (pwInput && bar && hint) {
    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      let score = 0;
      if (pw.length >= 10) score++;
      if (/[A-Z]/.test(pw)) score++;
      if (/[a-z]/.test(pw)) score++;
      if (/\d/.test(pw)) score++;
      if (/[^A-Za-z0-9]/.test(pw)) score++;

      const colors = ['', 'var(--accent-red)', '#ff8c00', '#fbbf24', 'var(--accent-green)', 'var(--accent-cyan)'];
      const labels = ['', 'Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
      const widths = ['0%', '20%', '40%', '60%', '80%', '100%'];

      bar.style.width = widths[score];
      bar.style.backgroundColor = colors[score];
      if (score > 0) {
        hint.textContent = labels[score];
        hint.className = score >= 4 ? 'form-text text-strength-strong' : score >= 2 ? 'form-text text-strength-fair' : 'form-text text-strength-weak';
      } else {
        hint.textContent = '10+ chars with upper-case, lower-case & a digit';
        hint.className = 'form-text';
      }
    });
  }

  /* ── Upload Zone Drag & Drop Feedback ── */
  const fileInput = document.getElementById('upload-file');
  const uploadCard = document.getElementById('upload-card');
  if (fileInput && uploadCard) {
    uploadCard.classList.add('upload-zone');
    ['dragenter', 'dragover'].forEach(ev => {
      uploadCard.addEventListener(ev, e => {
        e.preventDefault();
        uploadCard.classList.add('drag-over');
      });
    });
    ['dragleave', 'drop'].forEach(ev => {
      uploadCard.addEventListener(ev, () => {
        uploadCard.classList.remove('drag-over');
      });
    });
  }

  /* ── Form Submit Loading Spinner ── */
  const formsToHandle = [
    { formId: 'login-form', btnId: 'login-btn', text: 'Authenticating...' },
    { formId: 'reg-form', btnId: 'reg-btn', text: 'Generating RSA Keys...' },
    { formId: 'upload-form', btnId: 'upload-btn', text: 'Encrypting...' },
    { formId: 'share-form', btnId: 'share-btn', text: 'Wrapping Key...' },
    { formId: 'pw-change-form', btnId: 'pw-change-btn', text: 'Re-wrapping Keys...' }
  ];

  formsToHandle.forEach(({ formId, btnId, text }) => {
    const form = document.getElementById(formId);
    if (!form) return;
    form.addEventListener('submit', () => {
      const btn = document.getElementById(btnId);
      if (btn) {
        btn.innerHTML = `<span class="spinner-container"><svg class="spinner-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> ${text}</span>`;
        // Delay disabling so form submission data is not canceled in edge browsers
        setTimeout(() => { btn.disabled = true; }, 0);
      }
    });
  });

});
