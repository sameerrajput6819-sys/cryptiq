'use strict';
/* CRYPTIQ — all analysis happens in memory. The password is never stored, logged, or put in a URL.
   The only network call is the optional breach check, which sends a 5-char SHA-1 prefix. */
const $ = s => document.querySelector(s);
const LOG10_2 = Math.log10(2), YEAR = 31557600;
/* ---------- Engine (merged from passwordEngine.js) ---------- */
const ATTACKS = [
  { id: 'onlineLimited', label: 'Online, rate-limited', note: '5 guesses/min', rate: 5 / 60 },
  { id: 'onlineApi', label: 'Online, high-speed API', note: '1,000 guesses/s', rate: 1e3 },
  { id: 'offlineFast', label: 'Offline, fast hash (MD5/NTLM, GPU)', note: '100 billion guesses/s', rate: 1e11 },
  { id: 'offlineSlow', label: 'Offline, slow hash (bcrypt/Argon2)', note: '10,000 guesses/s', rate: 1e4 },
];

const PATTERN_WORDS = ['password', 'passw0rd', 'welcome', 'admin', 'letmein', 'monkey', 'dragon', 'qwerty', 'iloveyou', 'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow', 'summer', 'winter', 'spring', 'autumn', 'login', 'hello', 'freedom', 'whatever', 'trustno', 'superman', 'batman', 'michael', 'jessica', 'charlie', 'mustang', 'secret', 'computer', 'internet', 'service', 'google', 'pass'];
const ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'].flatMap(r => [r, [...r].reverse().join('')]);
const DICT_BITS = Math.log2(20000); // assumed size of an attacker's word list incl. simple rules

function poolSize(p) {
  let n = 0;
  if (/[a-z]/.test(p)) n += 26;
  if (/[A-Z]/.test(p)) n += 26;
  if (/\d/.test(p)) n += 10;
  if (/[ -\/:-@\[-`{-~]/.test(p)) n += 33;
  if (/[^\x00-\x7F]/.test(p)) n += 100;
  return n;
}

/** Finds predictable chunks. Each chunk is priced at the bits an attacker would need to guess it. */
function findPatterns(p) {
  const chars = [...p], lower = chars.join('').toLowerCase().replace(/[@4]/g, 'a').replace(/0/g, 'o').replace(/3/g, 'e').replace(/[$5]/g, 's').replace(/1/g, 'l');
  const used = new Array(chars.length).fill(false), found = [];
  const take = (i, len, label, bits) => {
    if (used.slice(i, i + len).some(Boolean)) return;
    used.fill(true, i, i + len); found.push({ label, len, bits });
  };
  for (const m of p.matchAll(/(?:19|20)\d\d/g)) take(m.index, 4, 'Contains a year', Math.log2(130));
  PATTERN_WORDS.forEach(w => { let i = -1; while ((i = lower.indexOf(w, i + 1)) >= 0) take(i, w.length, `Contains common word “${w.length > 3 ? w : '…'}”`, DICT_BITS); });
  const low = p.toLowerCase();
  ROWS.forEach(r => { for (let l = Math.min(r.length, 10); l >= 4; l--) for (let s = 0; s + l <= r.length; s++) { let i = -1; const sub = r.slice(s, s + l); while ((i = low.indexOf(sub, i + 1)) >= 0) take(i, l, 'Keyboard walk (e.g. qwerty)', 6); } });
  for (let i = 0; i < chars.length - 2;) { // sequences like 1234 / abcd / 4321
    const d = low.charCodeAt(i + 1) - low.charCodeAt(i); let j = i + 1;
    if (Math.abs(d) === 1) { while (j + 1 < chars.length && low.charCodeAt(j + 1) - low.charCodeAt(j) === d) j++; if (j - i + 1 >= 3) { take(i, j - i + 1, 'Sequential characters (e.g. 1234, abcd)', 5); i = j + 1; continue; } }
    i++;
  }
  for (const m of p.matchAll(/(.)\1{2,}/gs)) take(m.index, m[0].length, 'Repeated characters (e.g. aaaa)', 3 + Math.log2(m[0].length));
  return { found, free: used.filter(u => !u).length };
}

async function fetchBreachCount(password, { timeoutMs = 8000 } = {}) {
  if (typeof password !== 'string' || !password) throw new Error('Enter a password first.');
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable (use https or localhost).');
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const prefix = hash.slice(0, 5), suffix = hash.slice(5); // only `prefix` is ever sent
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' }, signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit' });
    if (!res.ok) throw new Error('Breach service returned an error.');
    for (const line of (await res.text()).split('\n')) {
      const [s, c] = line.trim().split(':');
      if (s === suffix) return parseInt(c, 10) || 0; // padded decoy rows have count 0
    }
    return 0;
  } catch (e) { throw new Error(e.name === 'AbortError' ? 'Breach check timed out.' : 'Breach service could not be reached.'); }
  finally { clearTimeout(t); }
}

function crackScenarios(bits) { return ATTACKS.map(a => ({ ...a, avg: avgLog(bits, a.rate), full: bits * LOG10_2 - Math.log10(a.rate) })); }
const WORDS = 'able acid aged arch atom bake barn bell bird blue bolt bone brew calm cave chef city clay cold cork crab dawn deer dish dove drum dust echo elm fern fish flag fog frog gate gold hawk hill iron jade kite lake lamp leaf lime lion moon moss nest oak opal owl palm pear pine rain reef rose sand seal silk snow star tide twig vine wolf wren yarn zinc amber anvil birch cedar cliff comet coral daisy delta ember falcon fjord glade harbor island jungle lagoon maple meadow nectar orchid pebble quartz ripple saddle thistle valley willow zephyr'.split(' ');
const SETS = { l: 'abcdefghijklmnopqrstuvwxyz', u: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', d: '0123456789', s: '!@#$%^&*()-_=+[]{};:,.?/' };
const RM = matchMedia('(prefers-reduced-motion: reduce)');
document.documentElement.classList.add('js');
let cur = null; // latest analysis result (numbers only, never the password)

/* ---------- Analysis ---------- */
function analyze(p) {
  const L = [...p].length, N = poolSize(p), perChar = Math.log2(N || 1), raw = L * perChar;
  const { found, free } = findPatterns(p);
  const eff = Math.max(1, free * perChar + found.reduce((s, f) => s + f.bits, 0)); // predictable chunks priced at attacker guess cost
  const weak = [...new Set(found.map(f => f.label))];
  if (L < 8) weak.unshift('Too short (under 8 characters)'); else if (L < 12) weak.push('Short: 12+ characters is better');
  if (N <= 26 || N === 10) weak.push('Uses only one character type');
  if (found.length && free === 0) weak.push('Entirely predictable: built only from known patterns');
  let score = eff < 28 ? 0 : eff < 36 ? 1 : eff < 60 ? 2 : eff < 80 ? 3 : 4;
  if (free === 0 && found.length) score = Math.min(score, 1);
  const word = found.some(f => /common word/.test(f.label));
  const dictGuesses = word && free <= 3 ? Math.round(2 ** Math.min(eff, 40)) : 0;
  const cats = ['a-z', 'A-Z', '0-9', 'symbols'].filter((_, i) => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/][i].test(p));
  return { L, N, raw, adj: eff, pred: L - free, rank: dictGuesses ? 1 : 0, dictGuesses, eff, cats, weak, score };
}
const LEVELS = [['Very weak', 12, 'var(--rd)'], ['Weak', 38, '#fb923c'], ['Fair', 62, 'var(--am)'], ['Strong', 82, '#a3e635'], ['Very strong (by this model)', 100, 'var(--em)']];
function level(a) { return LEVELS[a.dictGuesses ? 0 : a.score]; }
function tipsFor(a) {
  const t = [];
  if (a.dictGuesses) t.push('This matches a common word or pattern. Digits, capitals or symbol swaps on top of a common word are tried early by attackers.');
  if (a.L < 12) t.push('Increase length: aim for 14+ random characters or 5+ random words.');
  if (a.pred >= Math.max(2, a.L / 4)) t.push('Avoid repeats and sequences like “aaa”, “1234” or keyboard runs.');
  t.push('Avoid names, birthdays and other personal information.');
  t.push('Use a unique password for every site: reuse defeats even a strong password.');
  t.push('Prefer a generated random password or a long random passphrase, stored in a password manager, with multifactor authentication on.');
  t.push('Symbol substitutions (a→@) alone do not make a predictable password secure.');
  return t;
}
function fmtBits(b) { return b < 10 ? b.toFixed(1) : String(Math.round(b)); }


function tween(el, to) {
  const from = +el.dataset.v || 0; el.dataset.v = to;
  if (RM.matches) { el.textContent = fmtBits(to); return; }
  const t0 = performance.now();
  (function f(t) { const k = Math.min(1, (t - t0) / 400); el.textContent = fmtBits(from + (to - from) * k); if (k < 1 && +el.dataset.v === to) requestAnimationFrame(f); })(t0);
}
function flagsFor(a) {
  const f = [];
  if (a.dictGuesses) f.push('Common pattern');
  if (a.L < 8) f.push('Very short'); else if (a.L < 12) f.push('Short');
  if (a.pred >= Math.max(2, a.L / 4)) f.push('Repeats or sequences');
  if (a.cats.length === 1) f.push('One character type');
  return f;
}
const avgLog = (bits, rate) => (bits - 1) * LOG10_2 - Math.log10(rate); // log10 seconds, average = half the space
function timeRow(name, l) {
  if (l === null) return { name, label: 'n/a', w: 0, c: 'transparent' };
  return { name, label: fmtTime(l), w: Math.max(3, Math.min(100, (Math.max(l, 0) + 1) / 20 * 100)), c: l < Math.log10(86400) ? 'var(--rd)' : l < Math.log10(YEAR) ? 'var(--am)' : 'var(--em)' };
}
function drawBars(box, rows) { // updates existing bars in place so width transitions animate
  if (box.children.length !== rows.length) box.replaceChildren(...rows.map(() => { const b = document.createElement('div'); b.className = 'bar'; b.append(document.createElement('span'), Object.assign(document.createElement('div'), { innerHTML: '<i></i>' }), document.createElement('span')); return b; }));
  rows.forEach((r, i) => { const [a, d, c] = box.children[i].children; a.textContent = r.name; c.textContent = r.label; d.firstChild.style.width = r.w + '%'; d.firstChild.style.background = r.c; });
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

function render() {
  const p = $('#pw').value;
  const tips = $('#tips');
  if (!p) {
    cur = null;
    $('#meter').style.width = '0'; $('#meterBox').setAttribute('aria-valuenow', 0);
    $('#verdict').textContent = 'Start typing to see a live analysis.'; $('#verdict').style.color = '';
    ['#sLen', '#sRaw', '#sAdj'].forEach(s => $(s).textContent = '0'); $('#sCats').textContent = '–';
    $('#scaleFill').style.width = '0'; $('#eBits').textContent = '0'; ['#sRaw', '#sAdj', '#eBits'].forEach(s => $(s).dataset.v = 0); $('#flags').replaceChildren(); $('#eExp').textContent = '0';
    tips.innerHTML = '<li>Suggestions will appear here based on your password.</li>';
    $('#breachOut').textContent = '';
  } else {
    const a = cur = analyze(p), [name, pct, col] = level(a);
    $('#meter').style.width = pct + '%'; $('#meter').style.background = col; $('#meterBox').setAttribute('aria-valuenow', pct);
    $('#verdict').textContent = name + (a.dictGuesses ? ' (resembles a common password)' : ''); $('#verdict').style.color = col;
    $('#sLen').textContent = a.L; $('#sCats').textContent = a.cats.join(' ') || '–';
    tween($('#sRaw'), a.raw); tween($('#sAdj'), a.eff);
    $('#scaleFill').style.width = Math.min(100, a.eff / 128 * 100) + '%';
    tween($('#eBits'), a.eff); $('#eExp').textContent = Math.round(a.eff);
    tips.replaceChildren(...tipsFor(a).map(x => Object.assign(document.createElement('li'), { textContent: x })));
    $('#breachOut').textContent = '';
    const fl = a.weak;
    $('#flags').replaceChildren(...(fl.length ? fl.map(x => el('span', 'flag', x)) : [el('span', 'flag good', 'No obvious weakness found by these heuristics')]));
  }
  updateLab();
}

/* ---------- Time formatting: works in log10(seconds) so huge values never overflow ---------- */
function fmtTime(l) {
  if (l < 0) return 'under 1 second';
  const y = l - Math.log10(YEAR);
  if (y > 12) return 'over 1 trillion years';
  if (y >= 0) {
    const v = 10 ** y;
    if (v >= 1e9) return (v / 1e9).toFixed(1) + ' billion years';
    if (v >= 1e6) return (v / 1e6).toFixed(1) + ' million years';
    if (v >= 1e3) return Math.round(v).toLocaleString() + ' years';
    return v.toFixed(1) + (v < 1.05 ? ' year' : ' years');
  }
  const s = 10 ** l;
  for (const [n, d] of [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]]) {
    if (s >= d) { const v = s / d; return (v >= 10 ? Math.round(v) : v.toFixed(1)) + ' ' + n + (v >= 1.05 ? 's' : ''); }
  }
}
function fmtProb(bitsLog2) { // probability = 2^bitsLog2
  const p = 2 ** bitsLog2 * 100;
  if (p >= 100) return '100%'; if (p < 1e-6) return 'below 0.000001%';
  return p >= 1 ? p.toFixed(1) + '%' : p.toPrecision(2) + '%';
}

/* ---------- Attack lab ---------- */
const DEFAULTS = { onRate: 100, onLock: 5, offExp: 10, dictSize: 1e9, reuse: false };
function updateLabCore() {
  const exp = +$('#offExp').value;
  $('#offLabel').textContent = '10' + String(exp).replace(/\d/g, d => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d]);
  const box = $('#results'), chart = $('#chart');
  if (!cur) { box.replaceChildren(el('p', 'note', 'Type a password in the analyzer to run the simulations.')); chart.replaceChildren(); return; }
  const bits = cur.eff, onRate = Math.max(1e-9, (+$('#onRate').value || 1) / 3600), lock = Math.max(0, +$('#onLock').value || 0);
  const offRate = 10 ** exp, dict = Math.max(1, +$('#dictSize').value || 1), reuse = $('#reuse').checked;
  const avg = (rate) => (bits - 1) * LOG10_2 - Math.log10(rate); // log10 of average seconds (half the space)
  const rows = [];
  const online = avg(onRate);
  const onFull = bits * LOG10_2 - Math.log10(onRate);
  rows.push({ name: 'Online guessing', l: lock ? null : online,
    h: lock ? `Lockout: ≈ ${fmtProb(Math.log2(lock) - bits)} success chance` : fmtTime(online) + ' average (no lockout)',
    d: lock ? `The attacker gets about ${lock} guesses before lockout. An average-time figure would ignore the lockout, so it is not shown. Without any lockout: average ${fmtTime(online)}, full search ${fmtTime(onFull)}.` : `Average = half the space at ${(onRate * 3600).toLocaleString()} attempts/hour. Full search ${fmtTime(onFull)}.` });
  const offline = avg(offRate);
  rows.push({ name: 'Offline (stolen hash)', l: offline, h: fmtTime(offline) + ' average',
    d: `Average is half the space; full search (worst case) takes ${fmtTime(bits * LOG10_2 - exp)}. Uses your chosen speed and treats every guess as equally likely.` });
  const dl = cur.dictGuesses ? Math.log10(cur.dictGuesses / offRate) : Math.log10(dict / offRate);
  rows.push({ name: 'Dictionary', l: dl, h: cur.dictGuesses ? 'found in ' + fmtTime(dl) : 'list exhausted in ' + fmtTime(dl),
    d: cur.dictGuesses ? `Contains a common word with little else (this check uses a small sample word list); expected within about ${cur.dictGuesses.toLocaleString()} guesses. Predictable words and substitutions are guessed far earlier than the uniform model suggests.`
      : 'Not in the small built-in sample list, so it survives this list. Real dictionaries are larger and add rules, and this check cannot see every pattern.' });
  const stuff = reuse ? Math.log10(1 / onRate) : null;
  rows.push({ name: 'Credential stuffing', l: stuff, h: reuse ? 'a few seconds per site once leaked' : 'not applicable if unique',
    d: reuse ? 'A leaked username-password pair is simply replayed on other services. Strength is irrelevant; this is not brute force.' : 'A unique password stays contained: a leak elsewhere gives the attacker nothing to replay here.' });
  box.innerHTML = rows.map(r => `<div class="res"><small>${r.name}</small><b>${r.h}</b><small>${r.d}</small></div>`).join('');
  drawBars(chart, rows.map(r => timeRow(r.name, r.l)));
}
function fixedGrid() {
  const box = $('#fixed');
  if (!cur) { box.replaceChildren(el('p', 'note', 'Type a password in the analyzer to see these scenarios.')); return; }
  box.replaceChildren(...crackScenarios(cur.eff).map(s => { const d = el('div', 'res'); d.append(el('small', '', s.label), el('b', '', fmtTime(s.avg) + ' average'), el('small', '', `${s.note} · full search ${fmtTime(s.full)}`)); return d; }));
}
function updateLab() { updateLabCore(); fixedGrid(); timeline(); viz(); arena(); }
let tlRun = 0;
function timeline() {
  const box = $('#tlList'); if (!cur) { box.replaceChildren(el('li', '', 'Type a password in the analyzer to see the timeline.')); $('#tlPlay').disabled = true; return; }
  $('#tlPlay').disabled = false;
  const base = cur.eff * LOG10_2 - +$('#offExp').value;
  box.replaceChildren(...[[.01, '1% of the space'], [.5, 'Average (50%)'], [1, 'Full search (100%)']].map(([f, t]) => el('li', '', `${t}: ${fmtTime(base + Math.log10(f))}`)));
}
function playTimeline() {
  if (!cur) return; const id = ++tlRun, base = cur.eff * LOG10_2 - +$('#offExp').value, fill = $('#tlFill'), clock = $('#tlClock');
  const show = f => { fill.style.width = f * 100 + '%'; clock.textContent = `Simulated ${Math.round(f * 100)}% of the space searched: ${fmtTime(base + Math.log10(Math.max(f, 1e-9)))} elapsed. No guesses are made.`; };
  if (RM.matches) { show(1); return; }
  const t0 = performance.now(); fill.style.transition = 'none';
  (function f(t) { if (id !== tlRun) return; const k = Math.min(1, (t - t0) / 4000); show(k); if (k < 1) requestAnimationFrame(f); })(t0);
}
function viz() {
  const box = $('#viz');
  if (!cur) { box.replaceChildren(el('p', 'note', 'Type a password in the analyzer to see its search space.')); return; }
  const mk = (name, bits, note, c) => ({ name, label: `≈ 10^${(bits * LOG10_2).toFixed(1)} (2^${fmtBits(bits)})${note || ''}`, w: Math.max(2, Math.min(100, bits / 128 * 100)), c: c || 'var(--cy)' });
  const rows = [mk('Alphabet model', cur.raw), mk('Pattern-adjusted', cur.adj)];
  if (cur.dictGuesses) rows.push(mk('Dictionary guesses', Math.log2(cur.dictGuesses), ' guessable', 'var(--rd)'));
  rows.push(mk('Ref: 8 random lowercase', 8 * Math.log2(26), '', 'var(--vi)'), mk('Ref: 16 random printable', 16 * Math.log2(94), '', 'var(--vi)'));
  drawBars(box, rows);
}
function arena() {
  const [a, b] = ['#pwA', '#pwB'].map(s => $(s).value), cmp = $('#arenaCmp'), why = $('#arenaWhy');
  if (!a && !b) { cmp.replaceChildren(el('p', 'note', 'Enter two passwords to compare them.')); $('#arenaChart').replaceChildren(); why.replaceChildren(el('li', '', 'Reasons will appear here.')); return; }
  const A = a ? analyze(a) : null, B = b ? analyze(b) : null;
  const offRate = 10 ** +$('#offExp').value, onRate = Math.max(1e-9, (+$('#onRate').value || 1) / 3600);
  const v = (X, f) => X ? f(X) : '–';
  const M = [['Length', X => X.L], ['Character types', X => X.cats.join(' ')], ['Alphabet-model bits', X => fmtBits(X.raw)], ['Pattern-adjusted bits', X => fmtBits(X.eff)], ['Predictable characters', X => X.pred], ['Common-pattern match', X => X.rank ? 'Yes' : 'No'], ['Offline average', X => fmtTime(avgLog(X.eff, offRate))]];
  const kids = [el('span', 'h', ''), el('span', 'h', 'A'), el('span', 'h', 'B')];
  M.forEach(([n, f]) => kids.push(el('span', 'h', n), el('b', '', v(A, f)), el('b', '', v(B, f))));
  cmp.replaceChildren(...kids);
  drawBars($('#arenaChart'), [['A offline average', A, offRate], ['B offline average', B, offRate], ['A online avg (no lockout)', A, onRate], ['B online avg (no lockout)', B, onRate]].map(([n, X, r]) => X ? timeRow(n, avgLog(X.eff, r)) : { name: n, label: 'empty', w: 0, c: 'transparent' }));
  const R = [];
  if (A && B) {
    const d = A.eff - B.eff;
    R.push(Math.abs(d) < 0.5 ? 'Both have about the same pattern-adjusted entropy under this model.' : `${d > 0 ? 'A' : 'B'} has ${Math.abs(d).toFixed(1)} more pattern-adjusted bits, so roughly ${Math.abs(d) > 40 ? 'over a trillion' : (2 ** Math.abs(d)).toLocaleString(undefined, { maximumFractionDigits: 0 })} times more guesses are needed.`);
    if (A.L !== B.L) R.push(`${A.L > B.L ? 'A' : 'B'} is longer (${Math.max(A.L, B.L)} vs ${Math.min(A.L, B.L)} characters), and each character adds bits.`);
    if (!!A.rank !== !!B.rank) R.push(`${A.rank ? 'A' : 'B'} resembles a common password, so attackers try it early; its strength is capped regardless of length or symbols.`);
    if (A.pred !== B.pred) R.push(`${A.pred > B.pred ? 'A' : 'B'} has more repeated or sequential characters, which lowers its adjusted score.`);
    R.push('Both use identical assumptions. Real strength depends on how each password was chosen, which this model only approximates.');
  } else R.push('Enter both passwords to compare them.');
  why.replaceChildren(...R.map(t => el('li', '', t)));
}
function resetLab() {
  $('#onRate').value = DEFAULTS.onRate; $('#onLock').value = DEFAULTS.onLock; $('#offExp').value = DEFAULTS.offExp;
  $('#offPreset').value = '10'; $('#dictSize').value = DEFAULTS.dictSize; $('#reuse').checked = DEFAULTS.reuse; updateLab();
}

/* ---------- Generator (Web Crypto, rejection sampling to avoid modulo bias) ---------- */
function rnd(n) {
  const max = Math.floor(2 ** 32 / n) * n, a = new Uint32Array(1);
  do { crypto.getRandomValues(a); } while (a[0] >= max);
  return a[0] % n;
}
function shuffle(arr) { for (let i = arr.length - 1; i > 0; i--) { const j = rnd(i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; } return arr; }
function generate() {
  const out = $('#gOut'), info = $('#gInfo'), n = +$('#gLen').value;
  if (!window.crypto || !crypto.getRandomValues) { out.textContent = 'Secure random generation is not supported in this browser.'; return; }
  if ($('#gMode').value === 'phrase') {
    out.textContent = Array.from({ length: n }, () => WORDS[rnd(WORDS.length)]).join('-');
    info.textContent = `Entropy: ${n} words × log₂(${WORDS.length}) ≈ ${(n * Math.log2(WORDS.length)).toFixed(0)} bits, assuming an attacker knows this word list.`;
    return;
  }
  const on = Object.keys(SETS).filter(k => $('#g' + k).checked);
  if (!on.length) { out.textContent = 'Select at least one character type.'; info.textContent = ''; return; }
  const all = on.map(k => SETS[k]).join(''), chars = on.map(k => SETS[k][rnd(SETS[k].length)]); // one from each chosen type
  while (chars.length < n) chars.push(all[rnd(all.length)]);
  out.textContent = shuffle(chars).slice(0, n).join('');
  info.textContent = `Entropy ≈ ${(n * Math.log2(all.length)).toFixed(0)} bits (length × log₂(${all.length}); valid because choices are uniformly random).`;
}
function setGenMode() {
  const ph = $('#gMode').value === 'phrase', r = $('#gLen');
  r.min = ph ? 4 : 8; r.max = ph ? 10 : 64; r.value = ph ? 5 : 16;
  $('#gSets').style.display = ph ? 'none' : ''; syncLen(); generate();
}
function syncLen() { $('#gLenVal').textContent = $('#gLen').value + ($('#gMode').value === 'phrase' ? ' words' : ' characters'); }

/* ---------- Breach check: SHA-1 locally, send only a 5-character prefix ---------- */
async function breachCheck() {
  const out = $('#breachOut'), p = $('#pw').value; out.style.color = '';
  if (!p) { out.textContent = 'Enter a password first.'; return; }
  out.textContent = 'Checking…'; $('#breachBtn').disabled = true;
  try {
    const count = await fetchBreachCount(p);
    if ($('#pw').value !== p) return; // password changed while waiting
    if (count > 0) { out.style.color = 'var(--rd)'; out.textContent = `⚠ Found in known breach data (${count.toLocaleString()} times). Do not use this password anywhere.`; }
    else { out.style.color = 'var(--am)'; out.textContent = 'Not found in this dataset. That does not prove the password is safe: it may be new, guessable, or reused.'; }
  } catch (e) { out.style.color = 'var(--rd)'; out.textContent = e.message; }
  finally { $('#breachBtn').disabled = false; }
}

/* ---------- Wiring ---------- */
$('#pw').addEventListener('input', render);
$('#toggle').addEventListener('click', e => {
  const show = $('#pw').type === 'password'; $('#pw').type = show ? 'text' : 'password';
  e.target.textContent = show ? 'Hide' : 'Show'; e.target.setAttribute('aria-pressed', show);
});
$('#clear').addEventListener('click', () => { $('#pw').value = ''; $('#pw').focus(); render(); });
$('#breachBtn').addEventListener('click', breachCheck);
['onRate', 'onLock', 'dictSize', 'reuse'].forEach(id => $('#' + id).addEventListener('input', updateLab));
$('#offExp').addEventListener('input', () => { $('#offPreset').value = [...$('#offPreset').options].some(o => o.value === $('#offExp').value) ? $('#offExp').value : '10'; updateLab(); });
$('#offPreset').addEventListener('change', () => { $('#offExp').value = $('#offPreset').value; updateLab(); });
$('#resetLab').addEventListener('click', resetLab);
$('#tlPlay').addEventListener('click', playTimeline);
['#pwA', '#pwB'].forEach(s => $(s).addEventListener('input', arena));
$('#gMode').addEventListener('change', setGenMode);
$('#gLen').addEventListener('input', () => { syncLen(); generate(); });
$('#gSets').addEventListener('change', generate);
$('#gRegen').addEventListener('click', generate);
$('#gCopy').addEventListener('click', async e => {
  const b = e.target, t = $('#gOut').textContent;
  try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; } catch (_) { b.textContent = 'Copy failed'; }
  setTimeout(() => b.textContent = 'Copy', 1500);
});
$('#gUse').addEventListener('click', () => { $('#pw').value = $('#gOut').textContent; render(); $('#analyzer').scrollIntoView(); });
$('#burger').addEventListener('click', e => { const o = $('#menu').classList.toggle('open'); e.target.setAttribute('aria-expanded', o); });
$('#menu').addEventListener('click', () => { $('#menu').classList.remove('open'); $('#burger').setAttribute('aria-expanded', 'false'); });
/* ---------- Challenge mode ---------- */
const QUIZ = [
  { q: 'Which change adds the most strength to a randomly generated password?', o: ['Adding one symbol', 'Making it longer', 'Capitalizing the first letter', 'Swapping a for @'], a: 1, e: 'Each extra random character multiplies the search space. Predictable tweaks add very little.' },
  { q: 'What is credential stuffing?', o: ['Guessing every combination', 'Replaying leaked username-password pairs on other sites', 'Stuffing a hash with extra data', 'Guessing a lockout code'], a: 1, e: 'It exploits reuse, so even a strong password fails once it leaks. Use a unique password per site.' },
  { q: 'Why should sites use a salted, slow hash?', o: ['To make logins faster', 'To let admins read passwords', 'To stop precomputed tables and slow offline guessing', 'To shorten passwords'], a: 2, e: 'Unique salts force attackers to crack each account separately, and slow hashes cut guesses per second.' },
  { q: 'What does this site\'s breach check send over the network?', o: ['The password', 'The full SHA-1 hash', 'The first 5 characters of the SHA-1 hash', 'Nothing, ever'], a: 2, e: 'Only a 5-character prefix is sent (k-anonymity); matching happens in your browser.' },
  { q: 'When is H = L × log₂(N) a valid entropy estimate?', o: ['For any password', 'When characters are chosen uniformly at random', 'Only for passwords with symbols', 'Only for dictionary words'], a: 1, e: 'Human-chosen passwords are predictable, so the formula overstates their strength.' }
];
let qi = 0, qs = 0;
function quiz() {
  const box = $('#quizBox'); box.replaceChildren();
  if (qi >= QUIZ.length) {
    const r = el('button', 'btn primary', 'Restart'); r.type = 'button'; r.onclick = () => { qi = 0; qs = 0; quiz(); };
    box.append(el('h3', '', `Complete: ${qs} of ${QUIZ.length} correct`), el('p', 'note', qs === QUIZ.length ? 'Perfect score.' : qs >= 3 ? 'Solid. Review the explanations you missed.' : 'Worth another round: check the Security guide.'), r); r.focus(); return;
  }
  const Q = QUIZ[qi], bar = el('div', 'meter'), fill = document.createElement('i'); fill.style.width = (qi / QUIZ.length * 100) + '%'; fill.style.background = 'var(--cy)'; bar.append(fill);
  bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-label', 'Quiz progress'); bar.setAttribute('aria-valuemin', 0); bar.setAttribute('aria-valuemax', QUIZ.length); bar.setAttribute('aria-valuenow', qi);
  const exp = el('div', 'qexp'); exp.hidden = true; exp.setAttribute('role', 'status');
  const next = el('button', 'btn primary', qi + 1 === QUIZ.length ? 'Finish' : 'Next'); next.type = 'button'; next.hidden = true; next.onclick = () => { qi++; quiz(); };
  box.append(el('p', 'note', `Question ${qi + 1} of ${QUIZ.length} · Score ${qs}`), bar, el('h3', '', Q.q));
  const btns = Q.o.map((t, i) => { const b = el('button', 'btn qopt', t); b.type = 'button'; b.onclick = () => {
    btns.forEach((x, k) => { x.disabled = true; if (k === Q.a) x.classList.add('ok'); });
    if (i === Q.a) qs++; else b.classList.add('bad');
    exp.textContent = (i === Q.a ? 'Correct. ' : 'Not quite. ') + Q.e; exp.hidden = false; next.hidden = false; next.focus();
  }; return b; });
  box.append(...btns, exp, next);
}
if ('IntersectionObserver' in window) {
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: .08 });
  document.querySelectorAll('.sec > h2, .sec > .card').forEach(n => { n.classList.add('rv'); io.observe(n); });
}
render(); generate(); quiz();
