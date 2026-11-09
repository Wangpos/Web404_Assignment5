/**
 * vulnerable-app.js — INTENTIONALLY INSECURE web app for WEB404 Practical 5.
 *
 *  >>> DO NOT DEPLOY. Binds to 127.0.0.1 only. For a local teaching lab. <<<
 *
 * Every SQL statement here is built by concatenating untrusted input directly into
 * the query string. That is the bug the whole practical is about. The secure
 * counterpart (secure-app.js) fixes each one with parameterized queries.
 *
 * Covers the SQLi types from the module (2.1.1 / 2.1.2):
 *   - Authentication bypass        -> /login
 *   - Error-based (verbose errors) -> any broken payload
 *   - UNION-based (in-band)        -> /products?category=
 *   - Boolean-based blind          -> /products?category=  (rows vs no rows)
 *   - Time-based blind             -> /products?category=  (sleep())
 *   - Numeric injection            -> /profile?id=
 */
'use strict';

const http = require('node:http');
const { openDatabase } = require('./db');
const { esc, page } = require('./views/layout');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 3000;
const db = openDatabase();

// --- helpers ---------------------------------------------------------------

function send(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => {
      const params = new URLSearchParams(data);
      resolve(Object.fromEntries(params.entries()));
    });
  });
}

// Shows the exact SQL that was run — a teaching aid so you can see the injection.
function sqlBox(sql) {
  return `<p><strong>SQL executed:</strong></p><pre>${esc(sql)}</pre>`;
}

// --- routes ----------------------------------------------------------------

function home() {
  return page('LabShop — Home', `
    <div class="card">
      <h1>LabShop (vulnerable build)</h1>
      <p>A deliberately insecure shop used to practise SQL injection for WEB404 Practical 5.</p>
      <p>Try these injectable entry points:</p>
      <ul>
        <li><a href="/login">/login</a> — authentication bypass &amp; error-based</li>
        <li><a href="/products?category=peripherals">/products?category=</a> — UNION, boolean-blind, time-based</li>
        <li><a href="/profile?id=1">/profile?id=</a> — numeric injection</li>
      </ul>
      <div class="hint">Seed accounts (for reference): admin / S3cr3t_Adm1n!2024, alice / password123,
      bob / qwerty, carol / Winter!2024. The point of the lab is to reach these <em>without</em> knowing them.</div>
    </div>`);
}

function loginForm(extra = '') {
  return page('Login', `
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
      <div class="hint">Vulnerable query:
        <code>SELECT * FROM users WHERE username='&lt;u&gt;' AND password='&lt;p&gt;'</code>.
        Classic bypass: username <code>admin' --</code> (any password), or
        <code>' OR '1'='1</code> in both fields.</div>
    </div>`);
}

function handleLogin(body) {
  const username = body.username ?? '';
  const password = body.password ?? '';

  // VULNERABLE: string concatenation of untrusted input into the query.
  const sql = `SELECT id, username, role, email, api_token
               FROM users
               WHERE username='${username}' AND password='${password}'`;

  let resultHtml;
  try {
    const rows = db.prepare(sql).all();
    if (rows.length > 0) {
      const u = rows[0];
      resultHtml = `
        <p class="ok">✓ Authenticated as <strong>${esc(u.username)}</strong> (role: ${esc(u.role)})</p>
        <p>Rows returned by the query: ${rows.length}. Account data exposed to the session:</p>
        <table>
          <tr><th>id</th><th>username</th><th>role</th><th>email</th><th>api_token</th></tr>
          ${rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.username)}</td><td>${esc(r.role)}</td><td>${esc(r.email)}</td><td>${esc(r.api_token)}</td></tr>`).join('')}
        </table>`;
    } else {
      resultHtml = `<p class="err">✗ Invalid credentials.</p>`;
    }
  } catch (err) {
    // VULNERABLE: verbose error disclosure (error-based SQLi aid).
    resultHtml = `<p class="err">✗ Database error:</p><pre>${esc(err.message)}</pre>`;
  }

  return loginForm(sqlBox(sql) + resultHtml);
}

function handleProducts(query) {
  const category = query.get('category') ?? '';

  // VULNERABLE: concatenated into a 3-column SELECT (id, name, price).
  const sql = `SELECT id, name, price
               FROM products
               WHERE category='${category}'`;

  let resultHtml;
  try {
    const rows = db.prepare(sql).all();
    const body = rows.length
      ? `<table><tr><th>col1 (id)</th><th>col2 (name)</th><th>col3 (price)</th></tr>
         ${rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.price)}</td></tr>`).join('')}</table>`
      : `<p class="err">No products found for that category.</p>`;
    resultHtml = `<p>Rows returned: <strong>${rows.length}</strong> ${body}`;
  } catch (err) {
    resultHtml = `<p class="err">✗ Database error:</p><pre>${esc(err.message)}</pre>`;
  }

  return page('Products', `
    <div class="card">
      <h1>Browse products</h1>
      <form method="GET" action="/products">
        <label for="c">Category</label>
        <input type="text" id="c" name="category" value="${esc(category)}">
        <button type="submit">Search</button>
      </form>
      ${sqlBox(sql)}
      ${resultHtml}
      <div class="hint">
        3 columns are selected, so a UNION needs 3 columns. Try:<br>
        <code>peripherals' UNION SELECT id, username || ':' || password, api_token FROM users --</code><br>
        Boolean oracle: <code>peripherals' AND 1=1 --</code> vs <code>peripherals' AND 1=2 --</code><br>
        Time oracle: <code>peripherals' AND sleep(3) --</code>
      </div>
    </div>`);
}

function handleProfile(query) {
  const id = query.get('id') ?? '';

  // VULNERABLE: numeric context, no quotes — classic numeric injection.
  const sql = `SELECT id, username, role, email FROM users WHERE id = ${id}`;

  let resultHtml;
  try {
    const rows = db.prepare(sql).all();
    resultHtml = rows.length
      ? `<table><tr><th>id</th><th>username</th><th>role</th><th>email</th></tr>
         ${rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.username)}</td><td>${esc(r.role)}</td><td>${esc(r.email)}</td></tr>`).join('')}</table>`
      : `<p class="err">No such user.</p>`;
  } catch (err) {
    resultHtml = `<p class="err">✗ Database error:</p><pre>${esc(err.message)}</pre>`;
  }

  return page('Profile lookup', `
    <div class="card">
      <h1>User profile lookup</h1>
      <form method="GET" action="/profile">
        <label for="id">User ID</label>
        <input type="text" id="id" name="id" value="${esc(id)}">
        <button type="submit">Look up</button>
      </form>
      ${sqlBox(sql)}
      ${resultHtml}
      <div class="hint">Numeric context (no quotes). Try <code>0 OR 1=1</code> to dump every user,
        or <code>1 UNION SELECT name, value, 'x', 'y' FROM app_secrets</code> (match 4 columns).</div>
    </div>`);
}

// --- server ----------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    const { pathname, searchParams } = url;

    if (pathname === '/' && req.method === 'GET') return send(res, 200, home());
    if (pathname === '/login' && req.method === 'GET') return send(res, 200, loginForm());
    if (pathname === '/login' && req.method === 'POST') {
      const body = await readBody(req);
      return send(res, 200, handleLogin(body));
    }
    if (pathname === '/products' && req.method === 'GET') return send(res, 200, handleProducts(searchParams));
    if (pathname === '/profile' && req.method === 'GET') return send(res, 200, handleProfile(searchParams));

    return send(res, 404, page('Not found', '<div class="card"><h1>404</h1></div>'));
  } catch (err) {
    send(res, 500, page('Error', `<div class="card"><pre>${esc(err.stack || err.message)}</pre></div>`));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n  ⚠  VULNERABLE app running at http://${HOST}:${PORT}  (local only)`);
  console.log('     Routes: /  /login  /products?category=  /profile?id=');
  console.log('     Stop with Ctrl+C.\n');
});
