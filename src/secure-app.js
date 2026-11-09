/**
 * secure-app.js — the FIXED version of LabShop for WEB404 Practical 5.
 *
 * Same routes and same database as vulnerable-app.js, but every query now uses
 * PARAMETERIZED STATEMENTS (bound placeholders), so user input can never change the
 * structure of the SQL. Run the identical attack payloads against this build
 * (port 3001) and watch them fail.
 *
 * Defences demonstrated (module 2.1.3 & 2.7):
 *   1. Parameterized queries / prepared statements  (primary fix)
 *   2. Input validation & allow-listing              (defence in depth)
 *   3. Generic error messages (no SQL/stack leakage) (stops error-based SQLi + info disclosure)
 */
'use strict';

const http = require('node:http');
const { openDatabase } = require('./db');
const { esc, page } = require('./views/layout');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 3001;
const db = openDatabase();

const OPT = { banner: 'secure' };

function send(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(data).entries())));
  });
}

function home() {
  return page('LabShop — Home (secure)', `
    <div class="card">
      <h1>LabShop (secure build)</h1>
      <p>Identical features to the vulnerable build, but hardened. Replay the same payloads
         from the attack guide here — they are now treated as literal data, not SQL.</p>
      <ul>
        <li><a href="/login">/login</a></li>
        <li><a href="/products?category=peripherals">/products?category=</a></li>
        <li><a href="/profile?id=1">/profile?id=</a></li>
      </ul>
    </div>`, OPT);
}

function loginForm(extra = '') {
  return page('Login (secure)', `
    <div class="card">
      <h1>Member login</h1>
      <form method="POST" action="/login">
        <label for="u">Username</label>
        <input type="text" id="u" name="username" autocomplete="off">
        <label for="p">Password</label>
        <input type="password" id="p" name="password" autocomplete="off">
        <button type="submit">Sign in</button>
      </form>
      ${extra}
      <div class="hint">Fix: <code>WHERE username = ? AND password = ?</code> with bound values.
        <code>admin' --</code> now logs in as nobody — it is searched for a user literally named
        <code>admin' --</code>.</div>
    </div>`, OPT);
}

function handleLogin(body) {
  const username = body.username ?? '';
  const password = body.password ?? '';

  // FIX #1: parameterized query. Placeholders are bound as data, never parsed as SQL.
  const stmt = db.prepare(
    `SELECT id, username, role, email FROM users WHERE username = ? AND password = ?`
  );

  let resultHtml;
  try {
    const row = stmt.get(username, password); // note: real apps store a password HASH and verify it
    resultHtml = row
      ? `<p class="ok">✓ Authenticated as <strong>${esc(row.username)}</strong> (role: ${esc(row.role)})</p>`
      : `<p class="err">✗ Invalid username or password.</p>`; // same message either way (no user enumeration)
  } catch (_) {
    // FIX #3: generic error, nothing about SQL or the backend leaks to the client.
    resultHtml = `<p class="err">✗ Something went wrong. Please try again.</p>`;
  }
  return loginForm(resultHtml);
}

function handleProducts(query) {
  const category = (query.get('category') ?? '').trim();

  // FIX #2: validate/allow-list where the set of valid values is known and small.
  const ALLOWED = new Set(['peripherals', 'displays', 'accessories']);
  let resultHtml = '';
  let note = '';

  if (category && !ALLOWED.has(category)) {
    note = `<p class="err">Rejected: "${esc(category)}" is not a known category.</p>`;
  } else if (category) {
    // FIX #1: parameterized even after validation (defence in depth).
    const rows = db.prepare(
      `SELECT id, name, price FROM products WHERE category = ?`
    ).all(category);
    resultHtml = rows.length
      ? `<table><tr><th>id</th><th>name</th><th>price</th></tr>
         ${rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.price)}</td></tr>`).join('')}</table>`
      : `<p class="err">No products found.</p>`;
  }

  return page('Products (secure)', `
    <div class="card">
      <h1>Browse products</h1>
      <form method="GET" action="/products">
        <label for="c">Category</label>
        <input type="text" id="c" name="category" value="${esc(category)}">
        <button type="submit">Search</button>
      </form>
      ${note}${resultHtml}
      <div class="hint">UNION / boolean / time payloads here either fail the allow-list or are
        bound as a literal category string that matches no rows.</div>
    </div>`, OPT);
}

function handleProfile(query) {
  const raw = (query.get('id') ?? '').trim();

  // FIX #2: strict type validation — an id must be a positive integer, full stop.
  let resultHtml;
  if (!/^\d+$/.test(raw)) {
    resultHtml = `<p class="err">Invalid user id.</p>`;
  } else {
    // FIX #1: parameterized.
    const row = db.prepare(
      `SELECT id, username, role, email FROM users WHERE id = ?`
    ).get(Number(raw));
    resultHtml = row
      ? `<table><tr><th>id</th><th>username</th><th>role</th><th>email</th></tr>
         <tr><td>${esc(row.id)}</td><td>${esc(row.username)}</td><td>${esc(row.role)}</td><td>${esc(row.email)}</td></tr></table>`
      : `<p class="err">No such user.</p>`;
  }

  return page('Profile lookup (secure)', `
    <div class="card">
      <h1>User profile lookup</h1>
      <form method="GET" action="/profile">
        <label for="id">User ID</label>
        <input type="text" id="id" name="id" value="${esc(raw)}">
        <button type="submit">Look up</button>
      </form>
      ${resultHtml}
      <div class="hint"><code>0 OR 1=1</code> fails the integer check before any query runs.</div>
    </div>`, OPT);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    const { pathname, searchParams } = url;
    if (pathname === '/' && req.method === 'GET') return send(res, 200, home());
    if (pathname === '/login' && req.method === 'GET') return send(res, 200, loginForm());
    if (pathname === '/login' && req.method === 'POST') return send(res, 200, handleLogin(await readBody(req)));
    if (pathname === '/products' && req.method === 'GET') return send(res, 200, handleProducts(searchParams));
    if (pathname === '/profile' && req.method === 'GET') return send(res, 200, handleProfile(searchParams));
    return send(res, 404, page('Not found', '<div class="card"><h1>404</h1></div>', OPT));
  } catch (_) {
    send(res, 500, page('Error', '<div class="card"><p class="err">Internal error.</p></div>', OPT));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n  ✓  SECURE app running at http://${HOST}:${PORT}  (local only)`);
  console.log('     Replay the same payloads here to confirm they fail.\n');
});
