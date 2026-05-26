import os
import secrets
import sqlite3

from flask import (Flask, g, redirect, render_template, request,
                   session, url_for)

from db import get_db, init_db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = "super-insecure-secret-do-not-use"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = os.path.join(BASE_DIR, "data", "database.db")

with app.app_context():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    if not os.path.exists(DB_PATH):
        init_db()


@app.before_request
def set_nonce():
    g.csp_nonce = secrets.token_hex(16)


@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'nonce-{g.csp_nonce}' https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.0/purify.min.js; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none'; "
        f"connect-src 'self' https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.0/;"
    )
    return response


@app.context_processor
def inject_nonce():
    return {"csp_nonce": g.csp_nonce}


# ── helpers ───────────────────────────────────────────────────────────────────

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    db.close()
    return user


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(query).fetchone()
    db.close()

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return redirect(url_for("dashboard"))

    return render_template("login.html", error="Invalid credentials.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("register.html", error="All fields required.")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
            (username, password),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return render_template("register.html", error="Username already taken.")
    db.close()

    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATED ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ?", (user["id"],)
    ).fetchall()
    db.close()

    admin_flag = "REDACTED" if user["role"] == "admin" else None
    return render_template("dashboard.html", user=user, notes=notes, admin_flag=admin_flag)

@app.route("/check-user")
def check_user():
    username = request.args.get("username", "")
    msg = None

    if username:
        db = get_db()
        row = db.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not row:
            msg = "User not found."
        else:
            stored_username = row[0]
            raw_query = (
                f"SELECT COUNT(*) FROM notes WHERE user_id = "
                f"(SELECT id FROM users WHERE username = '{stored_username}')"
            )
            try:
                count = db.execute(raw_query).fetchone()[0]
                msg = f"User '{username}' has {count} note(s)."
            except Exception:
                msg = "User not found."

        db.close()

    return render_template("check_user.html", msg=msg)

@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("new_note.html", user=user)

    title   = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        return render_template("new_note.html", user=user, error="Title and content required.")

    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (user["id"], title, content),
    )
    db.commit()
    db.close()

    return redirect(url_for("dashboard"))

@app.route("/search")
def search():
    user = current_user()
    q = request.args.get("q", "")
    results = []

    if q:
        db = get_db()
        results = db.execute(
            "SELECT * FROM notes WHERE title LIKE ?", (f"%{q}%",)
        ).fetchall()
        db.close()

    return render_template("search.html", user=user, query=q, results=results)

@app.route("/notes/<int:note_id>")
def view_note(note_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    db.close()

    if not note:
        return render_template("error.html", user=user, msg="Note not found."), 404

    return render_template("view_note.html", user=user, note=note)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)