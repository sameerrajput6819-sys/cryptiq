'use strict';
/* CRYPTIQ — backend integration (loaded after script.js).
   PRIVACY: this file never reads the tested-password fields (#pw, #pwA, #pwB). The only analysis data it can send
   is three numbers taken from `cur` (length, pattern-adjusted bits, strength category), and only when the user
   presses "Save". Nothing here logs to the console, builds URLs from user input, or echoes values into errors.
   Shared helpers from script.js: $, el, cur, level, fmtBits, QUIZ, setAttackScenarios. */
(() => {
  let csrf = '', user = null, tips = [], lastQuiz = null;

  class ApiErr extends Error { constructor(msg, status) { super(msg); this.status = status; } }

  const say = (node, msg, kind) => { node.textContent = msg; node.classList.toggle('ok', kind === 'ok'); node.classList.toggle('err', kind === 'err'); };
  const when = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString(); };

  async function api(path, { method = 'GET', body, retried = false } = {}) {
    const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
    if (method !== 'GET') { opts.headers['Content-Type'] = 'application/json'; opts.headers['X-CSRF-Token'] = csrf; }
    if (body !== undefined) opts.body = JSON.stringify(body);
    let res;
    try { res = await fetch('/api' + path, opts); }
    catch (_) { throw new ApiErr('Could not reach the server. Is the backend running?', 0); }
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
    if (res.status === 403 && method !== 'GET' && !retried && data && /security token/i.test(data.error || '')) { // expired security token: fetch a fresh one, retry once
      await loadSession();
      return api(path, { method, body, retried: true });
    }
    if (!res.ok) throw new ApiErr((data && data.error) || `Request failed (${res.status}).`, res.status);
    return data;
  }

  /* ---------- Session / account ---------- */
  async function loadSession() { const d = await api('/session'); csrf = d.csrf_token; setUser(d.user); }

  function setUser(u) {
    user = u;
    $('#authOut').hidden = !!u; $('#authIn').hidden = !u;
    if (u) { $('#whoName').textContent = u.username; $('#whoEmail').textContent = u.email; loadHistory(); }
    else { $('#histAnalyses').replaceChildren(); $('#histQuiz').replaceChildren(); $('#quizSummary').textContent = ''; $('#histMsg').textContent = ''; }
    renderQuizSave(); updateSavePreview();
  }

  function showTab(login) {
    $('#loginForm').hidden = !login; $('#regForm').hidden = login;
    $('#tabLogin').setAttribute('aria-pressed', login); $('#tabReg').setAttribute('aria-pressed', !login);
    say($('#authMsg'), '');
  }

  async function submitAuth(e, path, build, busy, done) {
    e.preventDefault();
    const f = e.target, btn = f.querySelector('button[type=submit]'), msg = $('#authMsg');
    let body;
    try { body = build(f.elements); } catch (err) { say(msg, err.message, 'err'); return; }
    btn.disabled = true; say(msg, busy);
    try {
      const d = await api(path, { method: 'POST', body });
      csrf = d.csrf_token; f.reset(); setUser(d.user); say(msg, done(d.user), 'ok');
    } catch (err) { say(msg, err.message, 'err'); }
    finally { btn.disabled = false; }
  }

  async function logout() {
    const msg = $('#authMsg');
    try { const d = await api('/logout', { method: 'POST' }); csrf = d.csrf_token; setUser(null); say(msg, 'You have been logged out.', 'ok'); }
    catch (err) { say(msg, err.message, 'err'); }
  }

  /* ---------- Saved data ---------- */
  async function loadHistory() {
    const msg = $('#histMsg'); say(msg, 'Loading your saved data…');
    try {
      const d = await api('/history');
      const A = $('#histAnalyses'), Q = $('#histQuiz');
      A.replaceChildren(...(d.analyses.length ? d.analyses.map(a => li(`${a.password_length} characters · ≈${fmtBits(a.estimated_entropy)} bits · ${a.strength_category}`, when(a.analysis_date)))
        : [li('No saved reports yet.', '')]));
      Q.replaceChildren(...(d.quiz_results.length ? d.quiz_results.map(q => li(`${q.score} of ${q.total_questions} correct`, when(q.completed_at)))
        : [li('No saved quiz results yet.', '')]));
      const best = d.quiz_results.reduce((m, q) => Math.max(m, q.score / q.total_questions), 0);
      $('#quizSummary').textContent = d.quiz_results.length ? `${d.quiz_results.length} attempt${d.quiz_results.length > 1 ? 's' : ''} · best ${Math.round(best * 100)}%` : '';
      say(msg, '');
    } catch (err) { say(msg, err.message, 'err'); }
  }
  function li(a, b) { const x = el('li', ''); x.append(el('span', '', a), el('span', '', b)); return x; }

  /* ---------- Save analysis report (numbers only) ---------- */
  const category = a => level(a)[0].replace(/\s*\(.*\)$/, ''); // "Very strong (by this model)" -> "Very strong"
  function updateSavePreview() {
    const b = $('#saveBtn'), p = $('#savePreview');
    if (!cur) { b.disabled = true; p.textContent = 'Analyze a password above to enable saving.'; return; }
    b.disabled = false;
    p.textContent = `Would save: ${cur.L} characters · ≈${fmtBits(cur.eff)} bits (pattern-adjusted estimate) · ${category(cur)}.` + (user ? '' : ' Log in to save.');
  }
  async function saveReport() {
    const msg = $('#saveMsg'), btn = $('#saveBtn');
    if (!cur) { say(msg, 'Analyze a password first.', 'err'); return; }
    if (!user) { msg.classList.add('err'); msg.replaceChildren('Log in or register to save reports. ', Object.assign(el('a', '', 'Go to Account'), { href: '#account' })); return; }
    const payload = { password_length: cur.L, estimated_entropy: Math.round(cur.eff * 100) / 100, strength_category: category(cur) };
    btn.disabled = true; say(msg, 'Saving…');
    try { await api('/analyses', { method: 'POST', body: payload }); say(msg, 'Report saved. Only the numbers were sent; your password was not.', 'ok'); loadHistory(); }
    catch (err) { say(msg, err.message, 'err'); }
    finally { btn.disabled = !cur; }
  }

  /* ---------- Quiz score saving ---------- */
  function renderQuizSave() {
    const area = $('#quizSave'); if (!area || !lastQuiz) return;
    area.replaceChildren();
    const msg = el('p', 'verdict'); msg.setAttribute('aria-live', 'polite');
    if (!user) { area.append(el('p', 'note', 'Want to keep your score? '), Object.assign(el('a', '', 'Log in or register'), { href: '#account' })); return; }
    const btn = el('button', 'btn', lastQuiz.saved ? 'Score saved' : 'Save my score'); btn.type = 'button'; btn.disabled = lastQuiz.saved;
    btn.onclick = async () => {
      btn.disabled = true; say(msg, 'Saving…');
      try {
        await api('/quiz-results', { method: 'POST', body: { score: lastQuiz.score, total_questions: lastQuiz.total } });
        lastQuiz.saved = true; btn.textContent = 'Score saved'; say(msg, 'Score saved to your account.', 'ok'); loadHistory();
      } catch (err) { btn.disabled = false; say(msg, err.message, 'err'); }
    };
    area.append(btn, msg);
  }
  document.addEventListener('quiz:done', e => {
    lastQuiz = { score: e.detail.score, total: e.detail.total, saved: false };
    const area = el('div', 'savebox'); area.id = 'quizSave'; $('#quizBox').append(area); renderQuizSave();
  });

  /* ---------- Attack scenarios (from MySQL, with built-in fallback) ---------- */
  async function loadScenarios() {
    const st = $('#scenStatus');
    try {
      const d = await api('/scenarios');
      if (!d.scenarios.length) throw new ApiErr('No scenarios found.', 0);
      setAttackScenarios(d.scenarios.map(s => ({ id: 'db' + s.scenario_id, label: s.scenario_name, rate: s.guesses_per_second,
        note: `${s.guesses_per_second.toLocaleString()} ${s.guesses_per_second === 1 ? 'guess' : 'guesses'}/s`, description: s.description || '' })));
      $('#fixedNote').textContent = 'Reference scenarios loaded from the database, independent of the Attack Lab sliders. Guessing rates are illustrative assumptions, not measurements: actual speeds depend on hardware, the hashing algorithm and rate limits. Times are averages (half the effective search space) and are not guaranteed real-world cracking times.';
      say(st, `Loaded ${d.scenarios.length} scenarios from the database.`, 'ok');
    } catch (err) { say(st, `Using built-in reference speeds (${err.message})`, ''); }
  }

  /* ---------- Security tips (from MySQL) ---------- */
  function renderTips() {
    const box = $('#tipsList'), c = $('#tipCat').value, list = tips.filter(t => !c || t.category === c);
    if (!list.length) { box.replaceChildren(el('p', 'note', 'No tips in this category.')); return; }
    box.replaceChildren(...list.map(t => {
      const d = el('details'), s = el('summary', '', t.title), meta = el('p', '');
      if (t.category) meta.append(el('span', 'tag', t.category));
      if (t.difficulty_level) meta.append(el('span', 'tag', t.difficulty_level));
      d.append(s, meta, el('p', '', t.content)); return d;
    }));
  }
  async function loadTips() {
    const box = $('#tipsList'), sel = $('#tipCat');
    box.replaceChildren(el('p', 'note', 'Loading tips…'));
    try {
      tips = (await api('/tips')).tips;
      const cats = [...new Set(tips.map(t => t.category).filter(Boolean))].sort();
      sel.replaceChildren(Object.assign(el('option', '', 'All categories'), { value: '' }), ...cats.map(x => Object.assign(el('option', '', x), { value: x })));
      sel.disabled = false; renderTips();
    } catch (err) {
      const retry = el('button', 'btn', 'Try again'); retry.type = 'button'; retry.onclick = loadTips;
      box.replaceChildren(el('p', 'note', `Could not load tips: ${err.message}`), retry);
    }
  }

  /* ---------- Wiring ---------- */
  $('#tabLogin').addEventListener('click', () => showTab(true));
  $('#tabReg').addEventListener('click', () => showTab(false));
  $('#loginForm').addEventListener('submit', e => submitAuth(e, '/login',
    f => ({ email: f.email.value, password: f.password.value }), 'Signing in…', u => `Welcome back, ${u.username}.`));
  $('#regForm').addEventListener('submit', e => submitAuth(e, '/register', f => {
    if (f.password.value !== f.confirm.value) throw new Error('The two account passwords do not match.');
    return { username: f.username.value, email: f.email.value, password: f.password.value };
  }, 'Creating account…', u => `Account created. Welcome, ${u.username}.`));
  $('#logoutBtn').addEventListener('click', logout);
  $('#histRefresh').addEventListener('click', loadHistory);
  $('#saveBtn').addEventListener('click', saveReport);
  $('#tipCat').addEventListener('change', renderTips);
  document.addEventListener('analysis:update', () => { say($('#saveMsg'), ''); updateSavePreview(); });

  updateSavePreview();
  loadScenarios(); loadTips();
  loadSession().catch(err => say($('#authMsg'), `Account features are unavailable: ${err.message}`, 'err'));
})();
