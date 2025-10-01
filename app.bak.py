# ─────────────────────────────────────────────────────────────
# Challenge WestPistards — MVP Flask
# Nouveautés dans ce canevas :
#  • Thème clair + logo sur l’en-tête (static/logo.png)
#  • Admin : upload d’un « plan de compétition » (image ou PDF) à la création d’une manche
#  • Public : lien « Voir le plan » sur la page de la manche (+ aperçu si c’est une image)
#  • Classement : rang, écart au meilleur, % du meilleur (sur chronos validés)
#  • Admin : créer / clôturer / rouvrir / supprimer manche, valider / supprimer chrono
# Lancement rapide :
#   1) python3 -m venv .venv && source .venv/bin/activate
#   2) python3 -m pip install --upgrade pip setuptools wheel
#   3) python3 -m pip install "flask>=3.0" "werkzeug>=3.0"
#   4) export ADMIN_EMAILS="westpistards@gmail.com,tonemail@example.com"
#   5) python3 app.py
#   6) Ouvrir http://127.0.0.1:5000
# ─────────────────────────────────────────────────────────────

from flask import Flask, g, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, sqlite3, re, time
from datetime import datetime

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), "chronos.db")

app = Flask(__name__)
app.config.update(SECRET_KEY=APP_SECRET)

# ─────────── Uploads & statiques ───────────
BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PLAN_DIR = os.path.join(UPLOAD_DIR, "plans")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(PLAN_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# 16 Mo max par upload
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024)
ALLOWED_PLAN_EXT = {"png", "jpg", "jpeg", "gif", "webp", "pdf"}

# ─────────── Helpers DB ───────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ─────────── Initialisation DB ───────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    is_closed INTEGER NOT NULL DEFAULT 0,
    closed_at TEXT,
    plan_path TEXT,
    plan_name TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chronos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    manche_id INTEGER NOT NULL,
    millis INTEGER NOT NULL,
    youtube_url TEXT,
    date_run TEXT,
    comment TEXT,
    approved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (manche_id) REFERENCES manches(id),
    UNIQUE(user_id, manche_id)
);
"""

with sqlite3.connect(DB_PATH) as conn:
    conn.executescript(SCHEMA)

# Migrations légères (ajoute les colonnes manquantes sans casser les données)
with sqlite3.connect(DB_PATH) as conn:
    conn.row_factory = sqlite3.Row
    def ensure_col(table: str, col: str, ddl: str) -> None:
        cur = conn.execute("PRAGMA table_info(%s)" % table)
        cols = [row[1] for row in cur.fetchall()]
        if col not in cols:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, ddl))
            conn.commit()
    ensure_col("users", "is_admin", "INTEGER NOT NULL DEFAULT 0")
    ensure_col("chronos", "approved", "INTEGER NOT NULL DEFAULT 0")
    ensure_col("chronos", "date_run", "TEXT")
    ensure_col("chronos", "comment", "TEXT")
    ensure_col("manches", "is_closed", "INTEGER NOT NULL DEFAULT 0")
    ensure_col("manches", "closed_at", "TEXT")
    ensure_col("manches", "plan_path", "TEXT")
    ensure_col("manches", "plan_name", "TEXT")

# ─────────── Utilitaires ───────────
YOUTUBE_RE = re.compile(r"^(https?://)?(www\.)?(youtube\.com|youtu\.be)/.+", re.IGNORECASE)

def parse_chrono_to_millis(txt: str) -> int:
    txt = txt.strip()
    if not txt:
        raise ValueError("Chrono vide")
    if ":" in txt:
        mm, rest = txt.split(":", 1)
        mm = int(mm)
        if "." in rest:
            ss, mmm = rest.split(".", 1)
            ss = int(ss)
            mmm = int((mmm + "000")[:3])
        else:
            ss = int(rest)
            mmm = 0
        total = (mm * 60 + ss) * 1000 + mmm
    else:
        if "." in txt:
            ss, mmm = txt.split(".", 1)
            total = int(ss) * 1000 + int((mmm + "000")[:3])
        else:
            total = int(txt) * 1000
    if total <= 0:
        raise ValueError("Chrono invalide")
    return total

def format_millis(ms: int) -> str:
    s, mmm = divmod(ms, 1000)
    mm, ss = divmod(s, 60)
    return f"{mm:02d}:{ss:02d}.{mmm:03d}"

def format_delta(ms: int) -> str:
    sign = "+" if ms >= 0 else "-"
    ms = abs(ms)
    s, mmm = divmod(ms, 1000)
    return f"{sign}{s}.{mmm:03d}s"

app.jinja_env.globals['format_millis'] = format_millis
app.jinja_env.globals['format_delta'] = format_delta

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PLAN_EXT

def is_image_path(path: str) -> bool:
    return bool(path and path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")))

app.jinja_env.globals['is_image'] = is_image_path

# Auth helpers

def is_admin_email(email: str) -> bool:
    env = os.environ.get("ADMIN_EMAILS", "")
    allowed = {e.strip().lower() for e in env.split(",") if e.strip()}
    return email.strip().lower() in allowed


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    u = db.execute("SELECT id, name, email, is_admin, created_at FROM users WHERE id=?", (uid,)).fetchone()
    return u


def require_auth():
    if not session.get("user_id"):
        flash("Connecte-toi d'abord.", "warning")
        return redirect(url_for("login"))


def require_admin():
    u = current_user()
    if not u:
        return require_auth()
    if not u["is_admin"]:
        flash("Accès admin requis.", "danger")
        return redirect(url_for("home"))
    return u

# ─────────── Routes ───────────
@app.route("/")
def home():
    db = get_db()
    manches = db.execute(
        """
        SELECT m.id, m.label, m.is_closed, m.plan_path,
               COUNT(CASE WHEN c.approved=1 THEN 1 END) AS nb_chronos,
               MIN(CASE WHEN c.approved=1 THEN c.millis END) AS meilleur
        FROM manches m
        LEFT JOIN chronos c ON c.manche_id = m.id
        GROUP BY m.id
        ORDER BY m.created_at DESC
        """
    ).fetchall()
    return render_template("home.html", manches=manches, user=current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("Tous les champs sont obligatoires.", "danger")
        else:
            try:
                isadm = 1 if is_admin_email(email) else 0
                db = get_db()
                db.execute(
                    "INSERT INTO users(name, email, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
                    (name, email, generate_password_hash(password), isadm, datetime.utcnow().isoformat()),
                )
                db.commit()
                flash("Compte créé, connecte-toi !", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Cet email est déjà utilisé.", "danger")
    return render_template("register.html", user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        u = db.execute("SELECT id, password_hash FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u["password_hash"], password):
            # synchroniser le flag admin avec l'env à chaque connexion
            db.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin_email(email) else 0, u["id"]))
            db.commit()
            session["user_id"] = u["id"]
            flash("Bienvenue !", "success")
            return redirect(url_for("home"))
        flash("Identifiants invalides.", "danger")
    return render_template("login.html", user=current_user())

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("À bientôt !", "success")
    return redirect(url_for("home"))

@app.route("/profil")
def profil():
    u = current_user()
    if not u:
        return require_auth()
    db = get_db()
    chronos = db.execute(
        """
        SELECT c.id, c.millis, c.youtube_url, c.date_run, c.comment, c.created_at, c.approved,
               m.label, m.id as manche_id
        FROM chronos c JOIN manches m ON m.id = c.manche_id
        WHERE c.user_id = ?
        ORDER BY c.created_at DESC
        """,
        (u["id"],),
    ).fetchall()
    return render_template("profil.html", user=u, chronos=chronos)

@app.route("/manche/<int:manche_id>")
def manche_detail(manche_id):
    db = get_db()
    manche = db.execute("SELECT id, label, is_closed, plan_path, plan_name FROM manches WHERE id=?", (manche_id,)).fetchone()
    if not manche:
        flash("Manche introuvable", "warning")
        return redirect(url_for("home"))
    rows = db.execute(
        """
        SELECT u.name, c.millis, c.youtube_url, c.date_run, c.comment, c.created_at
        FROM chronos c JOIN users u ON u.id = c.user_id
        WHERE c.manche_id = ? AND c.approved = 1
        ORDER BY c.millis ASC
        """,
        (manche_id,),
    ).fetchall()
    leaderboard = []
    if rows:
        best_ms = rows[0]["millis"]
        for idx, r in enumerate(rows, start=1):
            delta = r["millis"] - best_ms
            percent = (r["millis"] / best_ms) * 100.0 if best_ms else None
            d = dict(r)
            d.update(rank=idx, delta_ms=delta, percent=percent)
            leaderboard.append(d)
    return render_template("manche.html", manche=manche, leaderboard=leaderboard)

@app.route("/chrono/ajouter", methods=["GET", "POST"])
def add_chrono():
    u = current_user()
    if not u:
        return require_auth()
    db = get_db()
    if request.method == "POST":
        label = request.form.get("manche_label", "").strip()
        chrono_txt = request.form.get("chrono", "").strip()
        youtube_url = request.form.get("youtube_url", "").strip()
        date_run = request.form.get("date_run", "").strip() or None
        comment = request.form.get("comment", "").strip() or None
        try:
            ms = parse_chrono_to_millis(chrono_txt)
        except Exception:
            flash("Format de chrono invalide. Ex: 01:23.456", "danger")
            return redirect(url_for("add_chrono"))
        if youtube_url and not YOUTUBE_RE.match(youtube_url):
            flash("Lien YouTube invalide.", "danger")
            return redirect(url_for("add_chrono"))
        # upsert de la manche
        cur = db.execute("SELECT id, is_closed FROM manches WHERE label=?", (label,))
        row = cur.fetchone()
        if row:
            if row["is_closed"]:
                flash("Cette manche est clôturée par un admin. Impossible d'ajouter ou modifier un chrono.", "danger")
                return redirect(url_for("add_chrono"))
            manche_id = row["id"]
        else:
            # seuls les admins peuvent créer une manche
            if not u["is_admin"]:
                flash("Cette manche n'existe pas. Seuls les admins peuvent en créer une.", "danger")
                return redirect(url_for("add_chrono"))
            db.execute(
                "INSERT INTO manches(label, created_at) VALUES (?, ?)",
                (label, datetime.utcnow().isoformat()),
            )
            db.commit()
            manche_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        # upsert du chrono (un par manche/pilote)
        try:
            db.execute(
                """
                INSERT INTO chronos(user_id, manche_id, millis, youtube_url, date_run, comment, approved, created_at)
                VALUES (?,?,?,?,?,?,0,?)
                ON CONFLICT(user_id, manche_id) DO UPDATE SET
                    millis=excluded.millis,
                    youtube_url=excluded.youtube_url,
                    date_run=excluded.date_run,
                    comment=excluded.comment,
                    approved=0,
                    created_at=excluded.created_at
                """,
                (u["id"], manche_id, ms, youtube_url or None, date_run, comment, datetime.utcnow().isoformat()),
            )
            db.commit()
            flash("Chrono enregistré (en attente de validation)", "success")
            return redirect(url_for("manche_detail", manche_id=manche_id))
        except Exception:
            db.rollback()
            flash("Erreur d'enregistrement.", "danger")
    # GET
    manches = db.execute("SELECT id, label, is_closed FROM manches ORDER BY created_at DESC").fetchall()
    return render_template("add_chrono.html", user=u, manches=manches)

# ─────────── Admin : validation chronos ───────────
@app.route("/admin")
def admin_panel():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    db = get_db()
    rows = db.execute(
        """
        SELECT c.id, c.millis, c.youtube_url, c.date_run, c.comment, c.created_at,
               u.name as pilote, u.email,
               m.label as manche
        FROM chronos c
        JOIN users u ON u.id = c.user_id
        JOIN manches m ON m.id = c.manche_id
        WHERE c.approved = 0
        ORDER BY c.created_at ASC
        """
    ).fetchall()
    return render_template("admin.html", user=u, rows=rows)

@app.route("/admin/approve", methods=["POST"])
def admin_approve():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    cid = request.form.get("chrono_id")
    db = get_db()
    db.execute("UPDATE chronos SET approved=1 WHERE id=?", (cid,))
    db.commit()
    flash("Chrono validé.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/chronos/delete", methods=["POST"])
def admin_chronos_delete():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    cid = request.form.get("chrono_id")
    db = get_db()
    db.execute("DELETE FROM chronos WHERE id=?", (cid,))
    db.commit()
    flash("Chrono supprimé.", "warning")
    return redirect(request.referrer or url_for("admin_panel"))

# ─────────── Admin : Manches (créer / clore / rouvrir / supprimer) ───────────
@app.route("/admin/manches")
def admin_manches():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    db = get_db()
    manches = db.execute(
        """
        SELECT m.id, m.label, m.is_closed, m.closed_at, m.plan_path, m.plan_name, m.created_at,
               COUNT(CASE WHEN c.approved=1 THEN 1 END) AS nb_chronos,
               MIN(CASE WHEN c.approved=1 THEN c.millis END) AS meilleur
        FROM manches m
        LEFT JOIN chronos c ON c.manche_id = m.id
        GROUP BY m.id
        ORDER BY m.created_at DESC
        """
    ).fetchall()
    return render_template("admin_manches.html", user=u, manches=manches)

@app.route("/admin/manches/create", methods=["POST"])
def admin_manches_create():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    label = request.form.get("label", "").strip()
    if not label:
        flash("Nom de manche requis.", "danger")
        return redirect(url_for("admin_manches"))
    plan_file = request.files.get("plan")
    plan_path = None
    plan_name = None
    if plan_file and plan_file.filename:
        fname = plan_file.filename
        if not allowed_file(fname):
            flash("Format de plan non accepté (image ou PDF).", "danger")
            return redirect(url_for("admin_manches"))
        safe = secure_filename(fname)
        unique = f"{int(time.time())}_{safe}"
        save_path = os.path.join(PLAN_DIR, unique)
        plan_file.save(save_path)
        plan_path = save_path
        plan_name = fname
    db = get_db()
    try:
        db.execute(
            "INSERT INTO manches(label, plan_path, plan_name, created_at) VALUES (?,?,?,?)",
            (label, plan_path, plan_name, datetime.utcnow().isoformat()),
        )
        db.commit()
        flash("Manche créée.", "success")
    except sqlite3.IntegrityError:
        flash("Ce nom de manche existe déjà.", "warning")
    return redirect(url_for("admin_manches"))

@app.route("/admin/manches/toggle", methods=["POST"])
def admin_manches_toggle():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    mid = request.form.get("manche_id")
    db = get_db()
    m = db.execute("SELECT is_closed FROM manches WHERE id=?", (mid,)).fetchone()
    if not m:
        flash("Manche introuvable.", "danger")
        return redirect(url_for("admin_manches"))
    if m["is_closed"]:
        db.execute("UPDATE manches SET is_closed=0, closed_at=NULL WHERE id=?", (mid,))
        flash("Manche rouverte.", "success")
    else:
        db.execute("UPDATE manches SET is_closed=1, closed_at=? WHERE id=?", (datetime.utcnow().isoformat(), mid))
        flash("Manche clôturée.", "warning")
    db.commit()
    return redirect(url_for("admin_manches"))

@app.route("/admin/manches/delete", methods=["POST"])
def admin_manches_delete():
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    mid = request.form.get("manche_id")
    db = get_db()
    # supprimer plan fichier si présent
    m = db.execute("SELECT plan_path FROM manches WHERE id=?", (mid,)).fetchone()
    try:
        if m and m["plan_path"] and os.path.exists(m["plan_path"]):
            os.remove(m["plan_path"])
    except Exception:
        pass
    db.execute("DELETE FROM chronos WHERE manche_id=?", (mid,))
    db.execute("DELETE FROM manches WHERE id=?", (mid,))
    db.commit()
    flash("Manche supprimée (et ses chronos).", "warning")
    return redirect(url_for("admin_manches"))

@app.route("/admin/manche/<int:manche_id>/chronos")
def admin_manche_chronos(manche_id):
    u = require_admin()
    if not isinstance(u, sqlite3.Row):
        return u
    db = get_db()
    manche = db.execute("SELECT id, label FROM manches WHERE id=?", (manche_id,)).fetchone()
    if not manche:
        flash("Manche introuvable.", "danger")
        return redirect(url_for("admin_manches"))
    rows = db.execute(
        """
        SELECT c.id, u.name as pilote, u.email, c.millis, c.approved, c.youtube_url, c.date_run, c.comment, c.created_at
        FROM chronos c JOIN users u ON u.id=c.user_id
        WHERE c.manche_id=?
        ORDER BY c.millis ASC
        """,
        (manche_id,),
    ).fetchall()
    best_ms_row = db.execute("SELECT MIN(millis) AS best FROM chronos WHERE manche_id=? AND approved=1", (manche_id,)).fetchone()
    best_ms = best_ms_row["best"] if best_ms_row and best_ms_row["best"] is not None else None
    chronos = []
    rank = 0
    for r in rows:
        r = dict(r)
        if r["approved"]:
            rank += 1
        delta = (r["millis"] - best_ms) if (best_ms is not None and r["approved"]) else None
        percent = (r["millis"]/best_ms*100.0) if (best_ms and r["approved"]) else None
        r.update(rank=(rank if r["approved"] else None), delta_ms=delta, percent=percent)
        chronos.append(r)
    return render_template("admin_manche_chronos.html", user=u, manche=manche, chronos=chronos)

# Plan public
@app.route("/plan/<int:manche_id>")
def plan_view(manche_id):
    db = get_db()
    m = db.execute("SELECT plan_path, plan_name FROM manches WHERE id=?", (manche_id,)).fetchone()
    if not m or not m["plan_path"]:
        flash("Aucun plan disponible pour cette manche.", "warning")
        return redirect(url_for("manche_detail", manche_id=manche_id))
    return send_file(m["plan_path"], as_attachment=False, download_name=m["plan_name"] or os.path.basename(m["plan_path"]))

# ─────────── Templates Jinja ───────────
TEMPLATES = {
"base.html": r"""
<!doctype html>
<html lang=fr>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ title or 'Challenge WestPistards' }}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:#f6f8fb; --card:#ffffff; --border:#e5e7eb; --muted:#4b5563;
      --text:#111827; --pri:#2563eb; --accent:#6366f1; --danger:#dc2626; --ok:#16a34a;
    }
    *{ box-sizing:border-box; }
    body { margin:0; font-family:Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); }
    a { color: var(--pri); text-decoration: none; }
    .container { max-width: 980px; margin: 0 auto; padding: 24px; }
    header { display:flex; align-items:center; justify-content:space-between; margin-bottom:24px; }
    .brand { font-weight:700; letter-spacing:.3px; display:flex; align-items:center; gap:10px; color:var(--text); }
    .brand img.logo{ height:36px; width:auto; }
    .nav a{ margin-left:16px; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:20px; box-shadow:0 10px 30px rgba(0,0,0,.05); }
    .grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap:16px; }
    .btn { display:inline-block; padding:10px 14px; border-radius:12px; border:1px solid var(--border); background:#fff; }
    .btn.primary { background:linear-gradient(135deg, var(--pri), var(--accent)); color:#fff; font-weight:700; border:none; }
    .flash { padding:10px 12px; border-radius:12px; margin:10px 0; font-size:14px; }
    .flash.success { background:#ecfdf5; border:1px solid #10b981; }
    .flash.danger { background:#fef2f2; border:1px solid var(--danger); }
    .flash.warning { background:#fffbeb; border:1px solid #f59e0b; }
    table { width:100%; border-collapse: collapse; }
    th, td { padding:10px; border-bottom:1px solid var(--border); text-align:left; }
    input, select { width:100%; background:#fff; border:1px solid var(--border); color:var(--text); padding:10px; border-radius:12px; }
    label { font-size:14px; color: var(--muted); margin-bottom:6px; display:block; }
    form .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; align-items:end; }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; background:#eef2ff; border:1px solid #c7d2fe; color:#3730a3; font-size:12px; }
    .badge.ok { background:#ecfdf5; border-color:#a7f3d0; color:#065f46; }
    .badge.wait { background:#fff7ed; border-color:#fed7aa; color:#9a3412; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <a href="/">
          <img src="{{ url_for('static', filename='logo.png') }}" alt="logo" class="logo" onerror="this.style.display='none'"/>
          Challenge WestPistards
        </a>
      </div>
      <nav class="nav">
        {% if user %}
          <a href="{{ url_for('profil') }}">Mon profil</a>
          <a class="btn" href="{{ url_for('add_chrono') }}">Ajouter un chrono</a>
          <a href="{{ url_for('logout') }}">Se déconnecter</a>
          {% if user['is_admin'] %} <a href="{{ url_for('admin_panel') }}">Admin</a> <a href="{{ url_for('admin_manches') }}">Gérer les manches</a>{% endif %}
        {% else %}
          <a href="{{ url_for('login') }}">Connexion</a>
          <a class="btn" href="{{ url_for('register') }}">Inscription</a>
        {% endif %}
      </nav>
    </header>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="flash {{ cat }}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <main>
      {% block content %}{% endblock %}
    </main>
  </div>
</body>
</html>
""",

"home.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1 style="margin-top:0">Manches</h1>
    {% if manches %}
      <div class="grid">
        {% for m in manches %}
          <div class="card">
            <h3 style="margin:0 0 6px 0">{{ m['label'] }} {% if m['is_closed'] %}<span class="badge">clôturée</span>{% endif %}</h3>
            <div style="font-size:14px;color:var(--muted)">
              {{ m['nb_chronos'] or 0 }} chrono(s) —
              {% if m['meilleur'] %}
                meilleur: {{ format_millis(m['meilleur']) }}
              {% else %}
                pas encore de chrono
              {% endif %}
            </div>
            <div style="margin-top:12px; display:flex; gap:8px">
              <a class="btn" href="{{ url_for('manche_detail', manche_id=m['id']) }}">Voir classement</a>
              {% if m['plan_path'] %}
                <a class="btn" href="{{ url_for('plan_view', manche_id=m['id']) }}" target="_blank">📄 Plan</a>
              {% endif %}
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <p>Aucune manche pour le moment. {% if user %}<a href="{{ url_for('add_chrono') }}">Ajoute un chrono</a>{% endif %}</p>
    {% endif %}
  </div>
{% endblock %}
""",

"register.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Créer un compte</h1>
    <form method="post">
      <label>Nom du pilote</label>
      <input name="name" required>
      <div class="row">
        <div>
          <label>Email</label>
          <input name="email" type="email" required>
        </div>
        <div>
          <label>Mot de passe</label>
          <input name="password" type="password" minlength="6" required>
        </div>
      </div>
      <p style="color:var(--muted);font-size:14px;margin-top:6px">Les emails listés dans <code>ADMIN_EMAILS</code> auront un accès admin.</p>
      <div style="margin-top:12px"><button class="btn primary">Créer</button></div>
    </form>
  </div>
{% endblock %}
""",

"login.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Connexion</h1>
    <form method="post">
      <div class="row">
        <div>
          <label>Email</label>
          <input name="email" type="email" required>
        </div>
        <div>
          <label>Mot de passe</label>
          <input name="password" type="password" required>
        </div>
      </div>
      <div style="margin-top:12px"><button class="btn primary">Se connecter</button></div>
    </form>
  </div>
{% endblock %}
""",

"profil.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Mon profil</h1>
    <p style="color:var(--muted)">{{ user['name'] }} — {{ user['email'] }} {% if user['is_admin'] %}<span class="badge ok">admin</span>{% endif %}</p>
    <h3>Mes chronos</h3>
    {% if chronos %}
      <table>
        <thead><tr><th>Manche</th><th>Chrono</th><th>Vidéo</th><th>Statut</th><th>Date tour</th><th>Note</th></tr></thead>
        <tbody>
          {% for c in chronos %}
            <tr>
              <td><a href="{{ url_for('manche_detail', manche_id=c['manche_id']) }}">{{ c['label'] }}</a></td>
              <td>{{ format_millis(c['millis']) }}</td>
              <td>{% if c['youtube_url'] %}<a href="{{ c['youtube_url'] }}" target="_blank">YouTube</a>{% else %}—{% endif %}</td>
              <td>{% if c['approved'] %}<span class="badge ok">validé</span>{% else %}<span class="badge wait">en attente</span>{% endif %}</td>
              <td>{{ c['date_run'] or c['created_at'][:10] }}</td>
              <td>{{ c['comment'] or '—' }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>Pas encore de chrono. <a href="{{ url_for('add_chrono') }}">Ajoute ton premier chrono</a>.</p>
    {% endif %}
  </div>
{% endblock %}
""",

"add_chrono.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Ajouter / Mettre à jour un chrono</h1>
    <form method="post">
      <label>Choisir une manche existante</label>
      <select name="manche_label">
        {% for m in manches %}
          <option value="{{ m['label'] }}" {% if m['is_closed'] %}disabled{% endif %}>{{ m['label'] }}{% if m['is_closed'] %} (clôturée){% endif %}</option>
        {% endfor %}
      </select>
      <p style="color:var(--muted);margin:6px 0">…ou saisis un nouveau nom de manche ci-dessous (réservé aux admins) :</p>
      <input name="manche_label" placeholder="Ex: Manche 1 — Circuit Paul Ricard" required>

      <div class="row" style="margin-top:12px">
        <div>
          <label>Chrono (mm:ss.mmm)</label>
          <input name="chrono" placeholder="01:23.456" required>
        </div>
        <div>
          <label>Lien YouTube (optionnel)</label>
          <input name="youtube_url" placeholder="https://youtu.be/…">
        </div>
      </div>
      <div class="row" style="margin-top:12px">
        <div>
          <label>Date du tour (optionnel)</label>
          <input name="date_run" type="date">
        </div>
        <div>
          <label>Note (optionnel)</label>
          <input name="comment" placeholder="Pneus / météo / config…">
        </div>
      </div>
      <div style="margin-top:12px"><button class="btn primary">Enregistrer</button></div>
    </form>
  </div>
{% endblock %}
""",

"manche.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>{{ manche['label'] }} {% if manche['is_closed'] %}<span class="badge">clôturée</span>{% endif %}</h1>
    {% if manche['plan_path'] %}
      <div style="margin:8px 0">
        <a class="btn" href="{{ url_for('plan_view', manche_id=manche['id']) }}" target="_blank">📄 Voir le plan</a>
      </div>
      {% if is_image(manche['plan_path']) %}
        <img src="{{ url_for('plan_view', manche_id=manche['id']) }}" alt="Plan de la manche" style="max-width:100%;border:1px solid var(--border);border-radius:12px;margin-bottom:12px" />
      {% endif %}
    {% endif %}

    {% if leaderboard %}
      <table>
        <thead><tr><th>#</th><th>Pilote</th><th>Chrono</th><th>Écart</th><th>% du meilleur</th><th>Vidéo</th><th>Date tour</th><th>Note</th></tr></thead>
        <tbody>
          {% for row in leaderboard %}
            <tr>
              <td><strong>{{ row['rank'] }}</strong></td>
              <td>{{ row['name'] }}</td>
              <td><strong>{{ format_millis(row['millis']) }}</strong></td>
              <td>{% if row['rank'] == 1 %}—{% else %}{{ format_delta(row['delta_ms']) }}{% endif %}</td>
              <td>{% if row['percent'] %}{{ '%.2f'|format(row['percent']) }}%{% else %}—{% endif %}</td>
              <td>{% if row['youtube_url'] %}<a href="{{ row['youtube_url'] }}" target="_blank">Voir</a>{% else %}—{% endif %}</td>
              <td>{{ row['date_run'] or row['created_at'][:10] }}</td>
              <td>{{ row['comment'] or '—' }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>Pas encore de chrono validé pour cette manche.</p>
    {% endif %}
  </div>
{% endblock %}
""",

"admin.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Panneau d'admin — Validation des chronos</h1>
    {% if rows %}
      <table>
        <thead><tr><th>Pilote</th><th>Email</th><th>Manche</th><th>Chrono</th><th>Vidéo</th><th>Date</th><th>Note</th><th>Actions</th></tr></thead>
        <tbody>
          {% for c in rows %}
          <tr>
            <td>{{ c['pilote'] }}</td>
            <td style="color:var(--muted)">{{ c['email'] }}</td>
            <td>{{ c['manche'] }}</td>
            <td><strong>{{ format_millis(c['millis']) }}</strong></td>
            <td>{% if c['youtube_url'] %}<a href="{{ c['youtube_url'] }}" target="_blank">Voir</a>{% else %}—{% endif %}</td>
            <td>{{ c['date_run'] or c['created_at'][:10] }}</td>
            <td>{{ c['comment'] or '—' }}</td>
            <td>
              <form method="post" action="{{ url_for('admin_approve') }}" style="display:inline">
                <input type="hidden" name="chrono_id" value="{{ c['id'] }}" />
                <button class="btn ok" type="submit">Valider</button>
              </form>
              <form method="post" action="{{ url_for('admin_chronos_delete') }}" style="display:inline" onsubmit="return confirm('Supprimer ce chrono ?');">
                <input type="hidden" name="chrono_id" value="{{ c['id'] }}" />
                <button class="btn danger" type="submit">Supprimer</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>Aucun chrono en attente.</p>
    {% endif %}
  </div>
{% endblock %}
""",

"admin_manches.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Gestion des manches</h1>
    <form method="post" action="{{ url_for('admin_manches_create') }}" enctype="multipart/form-data" style="margin-bottom:16px">
      <label>Créer une nouvelle manche</label>
      <div class="row">
        <div><input name="label" placeholder="Ex: Manche 3 — Magny-Cours" required></div>
        <div>
          <label>Plan (image ou PDF)</label>
          <input type="file" name="plan" accept="image/*,.pdf">
        </div>
        <div><button class="btn primary" type="submit">Créer</button></div>
      </div>
    </form>

    <table>
      <thead><tr><th>Manche</th><th>Statut</th><th>Plan</th><th>Chronos validés</th><th>Meilleur</th><th>Créée</th><th>Clôturée</th><th>Actions</th></tr></thead>
      <tbody>
        {% for m in manches %}
        <tr>
          <td>{{ m['label'] }}</td>
          <td>{% if m['is_closed'] %}<span class="badge">clôturée</span>{% else %}<span class="badge ok">ouverte</span>{% endif %}</td>
          <td>{% if m['plan_path'] %}<a href="{{ url_for('plan_view', manche_id=m['id']) }}" target="_blank">Voir</a>{% else %}—{% endif %}</td>
          <td>{{ m['nb_chronos'] or 0 }}</td>
          <td>{% if m['meilleur'] %}{{ format_millis(m['meilleur']) }}{% else %}—{% endif %}</td>
          <td>{{ m['created_at'][:19].replace('T',' ') }}</td>
          <td>{% if m['closed_at'] %}{{ m['closed_at'][:19].replace('T',' ') }}{% else %}—{% endif %}</td>
          <td>
            <a class="btn" href="{{ url_for('admin_manche_chronos', manche_id=m['id']) }}">Chronos</a>
            <form method="post" action="{{ url_for('admin_manches_toggle') }}" style="display:inline">
              <input type="hidden" name="manche_id" value="{{ m['id'] }}">
              {% if m['is_closed'] %}
              <button class="btn ok" type="submit">Rouvrir</button>
              {% else %}
              <button class="btn danger" type="submit">Clôturer</button>
              {% endif %}
            </form>
            <form method="post" action="{{ url_for('admin_manches_delete') }}" style="display:inline" onsubmit="return confirm('Supprimer définitivement cette manche et tous ses chronos ?');">
              <input type="hidden" name="manche_id" value="{{ m['id'] }}">
              <button class="btn danger" type="submit">Supprimer</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
""",

"admin_manche_chronos.html": r"""
{% extends 'base.html' %}
{% block content %}
  <div class="card">
    <h1>Chronos — {{ manche['label'] }}</h1>
    {% if chronos %}
      <table>
        <thead><tr><th>#</th><th>Pilote</th><th>Email</th><th>Chrono</th><th>Statut</th><th>Écart</th><th>% du meilleur</th><th>Vidéo</th><th>Date</th><th>Note</th><th>Actions</th></tr></thead>
        <tbody>
          {% for c in chronos %}
          <tr>
            <td>{% if c['rank'] %}{{ c['rank'] }}{% else %}—{% endif %}</td>
            <td>{{ c['pilote'] }}</td>
            <td style="color:var(--muted)">{{ c['email'] }}</td>
            <td><strong>{{ format_millis(c['millis']) }}</strong></td>
            <td>{% if c['approved'] %}<span class="badge ok">validé</span>{% else %}<span class="badge wait">en attente</span>{% endif %}</td>
            <td>{% if c['delta_ms'] is not none %}{{ format_delta(c['delta_ms']) }}{% else %}—{% endif %}</td>
            <td>{% if c['percent'] is not none %}{{ '%.2f'|format(c['percent']) }}%{% else %}—{% endif %}</td>
            <td>{% if c['youtube_url'] %}<a href="{{ c['youtube_url'] }}" target="_blank">Voir</a>{% else %}—{% endif %}</td>
            <td>{{ c['date_run'] or c['created_at'][:10] }}</td>
            <td>{{ c['comment'] or '—' }}</td>
            <td>
              {% if not c['approved'] %}
              <form method="post" action="{{ url_for('admin_approve') }}" style="display:inline">
                <input type="hidden" name="chrono_id" value="{{ c['id'] }}" />
                <button class="btn ok" type="submit">Valider</button>
              </form>
              {% endif %}
              <form method="post" action="{{ url_for('admin_chronos_delete') }}" style="display:inline" onsubmit="return confirm('Supprimer ce chrono ?');">
                <input type="hidden" name="chrono_id" value="{{ c['id'] }}" />
                <button class="btn danger" type="submit">Supprimer</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>Aucun chrono pour cette manche.</p>
    {% endif %}
    <p style="margin-top:12px"><a class="btn" href="{{ url_for('admin_manches') }}">← Retour gestion manches</a></p>
  </div>
{% endblock %}
"""
}

# Écrire les templates s'ils n'existent pas encore
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
for name, content in TEMPLATES.items():
    p = os.path.join(TEMPLATES_DIR, name)
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)

if __name__ == "__main__":
    app.run(debug=True)
