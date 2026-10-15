/* SecurePass – web front end for the C++ server */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const IDLE_MS = 5 * 60 * 1000, REVEAL_MS = 10000, CLIPBOARD_MS = 20000;

  let token = sessionStorage.getItem('sp_token') || '';
  let entries = [];
  let mode = 'login';
  let idleTimer, toastTimer, delId = null, editId = null;

  /* ---------- api ---------- */
  async function api(path, { method = 'GET', body } = {}) {
    const res = await fetch('/api' + path, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { const e = new Error(data.error || `Request failed (${res.status})`); e.status = res.status; throw e; }
    return data;
  }
  // Wrap vault actions so an expired session sends you back to sign in.
  async function guard(fn) {
    try { return await fn(); }
    catch (e) {
      if (e.status === 401 && token) { lock(e.message); return; }
      toast(e.message || 'Something went wrong.', true);
    }
  }

  /* ---------- ui helpers ---------- */
  function toast(msg, warn = false) {
    const t = $('toast');
    t.textContent = msg; t.className = 'toast' + (warn ? ' warn' : ''); t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 3800);
  }
  const hue = (s) => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
  const svg = (id) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('class', 'ic'); const u = document.createElementNS('http://www.w3.org/2000/svg', 'use'); u.setAttribute('href', `#${id}`); s.append(u); return s; };
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  function showAuth() { $('vault-view').hidden = true; $('auth-view').hidden = false; $('a-user').focus(); }
  function showVault() { $('auth-view').hidden = true; $('vault-view').hidden = false; armIdle(); }

  function lock(message) {
    if (token) api('/logout', { method: 'POST' }).catch(() => {});
    token = ''; sessionStorage.removeItem('sp_token'); entries = [];
    $('list').replaceChildren(); $('search').value = '';
    document.querySelectorAll('dialog[open]').forEach((d) => d.close());
    clearTimeout(idleTimer);
    setMode('login');
    showAuth();
    if (message) toast(message);
  }
  function armIdle() { clearTimeout(idleTimer); if (token) idleTimer = setTimeout(() => lock('Locked after 5 minutes of inactivity.'), IDLE_MS); }
  ['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, armIdle, { passive: true }));

  /* ---------- sign in / register ---------- */
  function setMode(m) {
    mode = m;
    $('tab-login').setAttribute('aria-selected', m === 'login');
    $('tab-register').setAttribute('aria-selected', m === 'register');
    $('a-submit').textContent = m === 'login' ? 'Sign in' : 'Create account';
    $('a-pass').autocomplete = m === 'login' ? 'current-password' : 'new-password';
    $('a-hint').hidden = m === 'login';
    $('a-error').textContent = '';
  }
  $('tab-login').addEventListener('click', () => setMode('login'));
  $('tab-register').addEventListener('click', () => setMode('register'));

  $('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('a-user').value.trim(), password = $('a-pass').value;
    if (!username || !password) { $('a-error').textContent = 'Enter your username and master password.'; return; }
    const btn = $('a-submit'); btn.disabled = true; $('a-error').textContent = '';
    try {
      const d = await api(mode === 'login' ? '/login' : '/register', { method: 'POST', body: { username, password } });
      token = d.token; sessionStorage.setItem('sp_token', token);
      $('a-pass').value = '';
      await loadEntries();
      showVault();
      if (mode === 'register') toast('Account created. Add your first login.');
    } catch (err) { $('a-error').textContent = err.message; }
    finally { btn.disabled = false; }
  });

  document.querySelectorAll('[data-eye]').forEach((b) => b.addEventListener('click', () => {
    const i = $(b.dataset.eye), show = i.type === 'password';
    i.type = show ? 'text' : 'password';
    b.querySelector('use').setAttribute('href', show ? '#i-eyeoff' : '#i-eye');
    b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  }));

  /* ---------- vault list ---------- */
  async function loadEntries() {
    const d = await api('/entries');
    entries = d.entries; $('who').textContent = d.username; render();
  }

  function render() {
    const q = $('search').value.trim().toLowerCase();
    const shown = entries.filter((x) => !q || x.accountName.toLowerCase().includes(q) || x.userName.toLowerCase().includes(q));
    $('count').textContent = entries.length ? (q ? `${shown.length} of ${entries.length} logins` : `${entries.length} ${entries.length === 1 ? 'login' : 'logins'}`) : '';
    const none = !shown.length;
    $('empty').hidden = !none;
    $('empty-title').textContent = entries.length ? 'No matches' : 'Your vault is empty';
    $('empty-sub').textContent = entries.length ? 'Try a different search.' : 'Add your first login to get started.';
    $('list').replaceChildren(...shown.map(item));
  }

  function item(x) {
    const li = el('li', 'item');
    const av = el('div', 'av', x.accountName.charAt(0)); av.style.setProperty('--h', hue(x.accountName));
    const meta = el('div', 'meta');
    const acct = el('div', 'acct'); acct.append(el('span', '', x.accountName));
    const tag = el('span', 'tag', x.strength); tag.dataset.level = x.strength.toLowerCase(); acct.append(tag);
    const secret = el('div', 'secret'); secret.hidden = true;
    meta.append(acct, el('div', 'usr', x.userName), secret);

    const acts = el('div', 'acts');
    const mk = (icon, label, cls, fn) => { const b = el('button'); b.type = 'button'; b.title = label; b.setAttribute('aria-label', label); if (cls) b.className = cls; b.append(svg(icon)); b.addEventListener('click', () => fn(b)); acts.append(b); return b; };

    let hideTimer;
    mk('i-eye', 'Show password', '', (b) => guard(async () => {
      if (!secret.hidden) { secret.hidden = true; clearTimeout(hideTimer); return; }
      secret.textContent = (await api(`/entries/${x.id}/password`)).password; secret.hidden = false;
      hideTimer = setTimeout(() => { secret.hidden = true; secret.textContent = ''; }, REVEAL_MS);
    }));
    mk('i-copy', 'Copy password', '', () => guard(async () => {
      const pw = (await api(`/entries/${x.id}/password`)).password;
      await navigator.clipboard.writeText(pw);
      toast('Password copied. It will be cleared from the clipboard in 20 seconds.');
      setTimeout(async () => { try { if ((await navigator.clipboard.readText()) === pw) await navigator.clipboard.writeText(''); } catch { /* no permission */ } }, CLIPBOARD_MS);
    }));
    mk('i-edit', 'Change password', '', () => openEdit(x));
    mk('i-trash', 'Delete login', 'del', () => openDelete(x));

    li.append(av, meta, acts);
    return li;
  }
  $('search').addEventListener('input', render);

  /* ---------- strength meter (rules live in the C++ server) ---------- */
  function bindMeter(inputId, meterId, levelId, issuesId) {
    let t;
    $(inputId).addEventListener('input', () => {
      clearTimeout(t);
      const p = $(inputId).value;
      if (!p) { $(meterId).dataset.level = 'none'; $(levelId).textContent = 'Enter a password'; $(issuesId).textContent = ''; return; }
      t = setTimeout(async () => {
        try {
          const d = await api('/strength', { method: 'POST', body: { password: p } });
          $(meterId).dataset.level = d.strength.toLowerCase();
          $(levelId).textContent = d.strength;
          $(issuesId).textContent = d.issues.join(' · ');
        } catch { /* meter is advisory */ }
      }, 180);
    });
  }
  bindMeter('f-pass', 'f-meter', 'f-level', 'f-issues');
  bindMeter('e-pass', 'e-meter', 'e-level', 'e-issues');

  function generate() {
    const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%^&*-+'];
    const all = sets.join(''), len = 18, rnd = new Uint32Array(len * 2);
    crypto.getRandomValues(rnd);
    const chars = sets.map((s, i) => s[rnd[i] % s.length]);
    for (let i = chars.length; i < len; i++) chars.push(all[rnd[i] % all.length]);
    for (let i = chars.length - 1; i > 0; i--) { const j = rnd[len + i] % (i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    return chars.join('');
  }
  function fillGenerated(inputId) {
    const i = $(inputId); i.value = generate(); i.type = 'text'; i.dispatchEvent(new Event('input'));
    document.querySelector(`[data-eye=${inputId}] use`).setAttribute('href', '#i-eyeoff');
  }
  $('f-gen').addEventListener('click', () => fillGenerated('f-pass'));
  $('e-gen').addEventListener('click', () => fillGenerated('e-pass'));

  /* ---------- dialogs ---------- */
  function resetPw(inputId) { const i = $(inputId); i.value = ''; i.type = 'password'; document.querySelector(`[data-eye=${inputId}] use`).setAttribute('href', '#i-eye'); i.dispatchEvent(new Event('input')); }

  $('add-btn').addEventListener('click', () => {
    $('add-form').reset(); resetPw('f-pass'); $('f-error').textContent = '';
    $('dlg-add').showModal(); $('f-account').focus();
  });
  $('add-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const body = { accountName: $('f-account').value.trim(), userName: $('f-user').value.trim(), password: $('f-pass').value };
    if (!body.accountName || !body.userName || !body.password) { $('f-error').textContent = 'Fill in all three fields.'; return; }
    guard(async () => {
      try {
        const d = await api('/entries', { method: 'POST', body });
        $('dlg-add').close(); await loadEntries();
        toast(d.issues.length ? `Saved, but the password is ${d.strength.toLowerCase()}. ${d.issues[0]}.` : 'Login saved.');
      } catch (err) { if (err.status === 400) $('f-error').textContent = err.message; else throw err; }
    });
  });

  function openEdit(x) {
    editId = x.id; $('e-label').textContent = `${x.accountName} · ${x.userName}`;
    resetPw('e-pass'); $('e-error').textContent = ''; $('dlg-edit').showModal(); $('e-pass').focus();
  }
  $('edit-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const password = $('e-pass').value;
    if (!password) { $('e-error').textContent = 'Enter a new password.'; return; }
    guard(async () => {
      try {
        const d = await api(`/entries/${editId}`, { method: 'PUT', body: { password } });
        $('dlg-edit').close(); await loadEntries();
        toast(d.issues.length ? `Updated, but the password is ${d.strength.toLowerCase()}.` : 'Password updated.');
      } catch (err) { if (err.status === 400) $('e-error').textContent = err.message; else throw err; }
    });
  });

  function openDelete(x) { delId = x.id; $('del-label').textContent = `${x.accountName} · ${x.userName} will be removed permanently.`; $('dlg-del').showModal(); }
  $('del-confirm').addEventListener('click', () => guard(async () => {
    await api(`/entries/${delId}`, { method: 'DELETE' });
    $('dlg-del').close(); await loadEntries(); toast('Login deleted.');
  }));

  document.querySelectorAll('dialog').forEach((d) => d.addEventListener('click', (e) => {
    if (e.target === d || e.target.closest('[data-close]')) d.close();
  }));

  $('lock-btn').addEventListener('click', () => lock('Vault locked.'));

  /* ---------- start ---------- */
  (async () => {
    if (!token) return showAuth();
    try { await loadEntries(); showVault(); } catch { lock(); }
  })();
})();
