"""College Management Portal - minimal secure web app (Flask + SQLite)."""
import os, re, sqlite3, secrets, hmac, logging, sys, time
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, abort,
                   render_template_string, flash)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Configuration management (no secrets in code; env vars) ----------
PROD = os.environ.get("APP_ENV", "production") == "production"
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if PROD:
        sys.exit("SECRET_KEY environment variable is required in production")
    SECRET_KEY = secrets.token_hex(32)
DB_PATH = os.environ.get("DB_PATH", "portal.db")
MAX_FAILS, LOCK_SECONDS, IDLE_SECONDS = 5, 300, 900

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,          # session management
    SESSION_COOKIE_SECURE=PROD,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=IDLE_SECONDS),
    MAX_CONTENT_LENGTH=16 * 1024,          # limit request size
    DEBUG=False,
)

# ---------- Auditing & logging ----------
log = logging.getLogger("audit")
log.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
for h in (logging.StreamHandler(), RotatingFileHandler("audit.log", maxBytes=1_000_000, backupCount=3)):
    h.setFormatter(fmt); log.addHandler(h)

def audit(event, **kw):
    uid = session.get("uid", "-")
    log.info("event=%s user=%s ip=%s %s", event, uid, request.remote_addr,
             " ".join(f"{k}={v}" for k, v in kw.items()))

# ---------- Database (parameterized queries only) ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','faculty','admin')),
      fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS marks(
      id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id),
      subject TEXT NOT NULL, score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
      added_by INTEGER NOT NULL);
    """)
    if not c.execute("SELECT 1 FROM users").fetchone():
        pw = os.environ.get("DEMO_PASSWORD") or secrets.token_urlsafe(10)
        for u, n, r in [("admin", "Administrator", "admin"),
                        ("faculty1", "Prof. Rao", "faculty"),
                        ("student1", "Asha Patil", "student")]:
            c.execute("INSERT INTO users(username,name,pw_hash,role) VALUES(?,?,?,?)",
                      (u, n, generate_password_hash(pw), r))   # cryptography: salted hash
        if not os.environ.get("DEMO_PASSWORD"):
            print(f"[setup] seeded users admin/faculty1/student1 with password: {pw}")
    c.commit(); c.close()

# ---------- Input validation ----------
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
NAME_RE = re.compile(r"^[A-Za-z .'-]{2,60}$")
SUBJECT_RE = re.compile(r"^[A-Za-z0-9 &-]{2,40}$")
def strong_pw(p):
    return (len(p) >= 10 and re.search(r"[a-z]", p) and re.search(r"[A-Z]", p)
            and re.search(r"\d", p))

# ---------- Session, CSRF, authentication & authorization ----------
def csrf_token():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    return session["csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def guard():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not hmac.compare_digest(sent, session.get("csrf", "x")):
            audit("csrf_fail", path=request.path); abort(400)
    if "uid" in session:                                   # idle timeout
        now = time.time()
        if now - session.get("last", now) > IDLE_SECONDS:
            audit("session_timeout"); session.clear()
            flash("Session expired. Please log in again."); return redirect(url_for("login"))
        session["last"] = now; session.permanent = True

@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    if PROD: r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    r.headers.pop("Server", None)
    return r

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login"))
            if roles and session["role"] not in roles:
                audit("authz_denied", path=request.path); abort(403)
            return f(*a, **k)
        return w
    return deco

# ---------- Templates (Jinja autoescaping prevents XSS) ----------
BASE = """<!doctype html><title>College Portal</title>
<style>body{font-family:sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem}
input,select,button{padding:6px;margin:3px 0}table{border-collapse:collapse}
td,th{border:1px solid #999;padding:4px 10px}.m{color:#b00}</style>
<h2>College Management Portal</h2>
{% if session.uid %}<p>{{ session.name }} ({{ session.role }}) |
<a href="{{ url_for('dashboard') }}">Home</a> |
<form method="post" action="{{ url_for('logout') }}" style="display:inline">
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><button>Logout</button></form></p>{% endif %}
{% for m in get_flashed_messages() %}<p class="m">{{ m }}</p>{% endfor %}
"""
def page(body, **ctx):
    return render_template_string(BASE + body, **ctx)

# ---------- Routes ----------
@app.route("/")
def index(): return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone() \
            if USERNAME_RE.match(u) else None
        if row and row["locked_until"] > time.time():
            audit("login_locked", username=u); flash("Account temporarily locked."); return page(LOGIN)
        if row and check_password_hash(row["pw_hash"], p):
            db().execute("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (row["id"],)); db().commit()
            session.clear()                                  # prevent session fixation
            session.update(uid=row["id"], name=row["name"], role=row["role"], last=time.time())
            audit("login_ok"); return redirect(url_for("dashboard"))
        if row:
            fails = row["fails"] + 1
            lock = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            db().execute("UPDATE users SET fails=?, locked_until=? WHERE id=?",
                         (0 if lock else fails, lock, row["id"])); db().commit()
        audit("login_fail", username=u[:30])
        flash("Invalid username or password.")               # generic message
    return page(LOGIN)

LOGIN = """<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="username" placeholder="username" maxlength="30" required><br>
<input name="password" type="password" placeholder="password" required><br>
<button>Login</button></form>"""

@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    audit("logout"); session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required()
def dashboard():
    return page("""<ul>
    {% if session.role=='student' %}<li><a href="{{ url_for('view_marks', uid=session.uid) }}">My marks</a></li>{% endif %}
    {% if session.role=='faculty' %}<li><a href="{{ url_for('add_marks') }}">Add marks</a></li>{% endif %}
    {% if session.role=='admin' %}<li><a href="{{ url_for('users') }}">Manage users</a></li>{% endif %}
    </ul>""")

@app.route("/marks/<int:uid>")
@login_required()
def view_marks(uid):
    # Parameter-manipulation defence: students may only read their own record
    if session["role"] == "student" and uid != session["uid"]:
        audit("idor_blocked", target=uid); abort(403)
    if session["role"] == "admin": abort(403)
    s = db().execute("SELECT name FROM users WHERE id=? AND role='student'", (uid,)).fetchone()
    if not s: abort(404)
    rows = db().execute("SELECT subject,score FROM marks WHERE student_id=?", (uid,)).fetchall()
    audit("marks_viewed", target=uid)
    return page("<h3>Marks: {{ n }}</h3><table><tr><th>Subject</th><th>Score</th></tr>"
                "{% for r in rows %}<tr><td>{{ r.subject }}</td><td>{{ r.score }}</td></tr>{% endfor %}</table>",
                n=s["name"], rows=rows)

@app.route("/marks/add", methods=["GET", "POST"])
@login_required("faculty")
def add_marks():
    studs = db().execute("SELECT id,name FROM users WHERE role='student'").fetchall()
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        try:
            sid, score = int(request.form["student_id"]), int(request.form["score"])
        except (KeyError, ValueError):
            abort(400)
        if (not SUBJECT_RE.match(subject) or not 0 <= score <= 100
                or sid not in [s["id"] for s in studs]):
            flash("Invalid input."); return redirect(url_for("add_marks"))
        db().execute("INSERT INTO marks(student_id,subject,score,added_by) VALUES(?,?,?,?)",
                     (sid, subject, score, session["uid"])); db().commit()
        audit("marks_added", student=sid, subject=subject); flash("Marks saved.")
        return redirect(url_for("add_marks"))
    return page("""<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <select name="student_id">{% for s in studs %}<option value="{{ s.id }}">{{ s.name }}</option>{% endfor %}</select><br>
    <input name="subject" placeholder="subject" maxlength="40" required><br>
    <input name="score" type="number" min="0" max="100" required><br><button>Save</button></form>""", studs=studs)

@app.route("/admin/users", methods=["GET", "POST"])
@login_required("admin")
def users():
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("username", "name", "role")}
        pw = request.form.get("password", "")
        if (not USERNAME_RE.match(f["username"]) or not NAME_RE.match(f["name"])
                or f["role"] not in ("student", "faculty") or not strong_pw(pw)):
            flash("Invalid input (password: 10+ chars with upper, lower, digit)."); return redirect(url_for("users"))
        try:
            db().execute("INSERT INTO users(username,name,pw_hash,role) VALUES(?,?,?,?)",
                         (f["username"], f["name"], generate_password_hash(pw), f["role"])); db().commit()
            audit("user_created", username=f["username"], role=f["role"]); flash("User created.")
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        return redirect(url_for("users"))
    rows = db().execute("SELECT username,name,role FROM users").fetchall()
    return page("""<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <input name="username" placeholder="username" required><input name="name" placeholder="full name" required><br>
    <input name="password" type="password" placeholder="password" required>
    <select name="role"><option>student</option><option>faculty</option></select><button>Add user</button></form>
    <table><tr><th>User</th><th>Name</th><th>Role</th></tr>
    {% for r in rows %}<tr><td>{{ r.username }}</td><td>{{ r.name }}</td><td>{{ r.role }}</td></tr>{% endfor %}</table>""", rows=rows)

# ---------- Exception management (generic messages, details only in logs) ----------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def client_err(e):
    return page("<p>Error {{ c }}: request could not be completed.</p>", c=e.code), e.code

@app.errorhandler(Exception)
def server_err(e):
    log.exception("unhandled error path=%s", request.path)
    return page("<p>Something went wrong.</p>"), 500

init_db()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
