/**
 * layout.js — tiny HTML helpers shared by the vulnerable and secure apps.
 * Pure string templating; no framework, keeps the lab dependency-free.
 */
'use strict';

// Escape user data for SAFE rendering (used by the secure app and for labels).
// Note: this prevents XSS on output; it is NOT a defence against SQL injection.
function esc(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function page(title, bodyHtml, { banner = 'vuln' } = {}) {
  const bannerText = banner === 'vuln'
    ? '⚠ VULNERABLE BUILD — intentionally insecure. Local lab only.'
    : '✓ SECURE BUILD — parameterized queries & input validation.';
  const bannerColor = banner === 'vuln' ? '#b00020' : '#1b7f3b';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  body { margin: 0; color: #1a1a1a; background: #f5f6f8; }
  .banner { background: ${bannerColor}; color: #fff; padding: 8px 16px; font-weight: 600; font-size: 14px; }
  header { background: #22272e; color: #fff; padding: 14px 20px; }
  header a { color: #9ad; margin-right: 16px; text-decoration: none; font-size: 14px; }
  main { max-width: 860px; margin: 24px auto; padding: 0 16px; }
  .card { background: #fff; border: 1px solid #e2e4e8; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  h1 { font-size: 20px; } h2 { font-size: 16px; }
  label { display: block; margin: 10px 0 4px; font-size: 14px; font-weight: 600; }
  input[type=text], input[type=password] { width: 100%; max-width: 420px; padding: 8px 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
  button { margin-top: 14px; padding: 9px 18px; border: 0; border-radius: 6px; background: #2d6cdf; color: #fff; font-size: 14px; cursor: pointer; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }
  th, td { border: 1px solid #e2e4e8; padding: 8px 10px; text-align: left; }
  th { background: #f0f2f5; }
  .ok { color: #1b7f3b; font-weight: 600; }
  .err { color: #b00020; }
  .hint { font-size: 13px; color: #555; background: #fff8e1; border: 1px solid #ffe08a; border-radius: 6px; padding: 10px 12px; margin-top: 12px; }
  code, pre { font-family: ui-monospace, Menlo, Consolas, monospace; }
  pre { background: #0d1117; color: #c9d1d9; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
  .pill { display: inline-block; background: #eef; border-radius: 999px; padding: 2px 10px; font-size: 12px; margin-left: 8px; }
</style>
</head>
<body>
  <div class="banner">${bannerText}</div>
  <header>
    <strong>LabShop</strong> <span class="pill">WEB404 Practical 5</span><br>
    <nav style="margin-top:8px;">
      <a href="/">Home</a>
      <a href="/login">Login</a>
      <a href="/products?category=peripherals">Products</a>
      <a href="/profile?id=1">Profile lookup</a>
    </nav>
  </header>
  <main>${bodyHtml}</main>
</body>
</html>`;
}

module.exports = { esc, page };
