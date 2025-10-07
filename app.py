import os, sqlite3
from contextlib import closing
from flask import Flask, request, redirect, url_for, render_template, flash, session, send_from_directory, abort, Response
from werkzeug.routing import BuildError

# === auth_fallback_import ===
try:
    from flask_login import login_required, current_user
except Exception:
    from functools import wraps
    from flask import session
    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # permite acesso se usuário estiver logado via sessão; senão, redireciona para login
            if not session.get('username'):
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapper
    class _User:
        def __init__(self):
            self.username = session.get('username')
            self.is_authenticated = bool(self.username)
            self.is_admin = session.get('role') == 'admin'
    class _CurrentUserProxy:
        @property
        def username(self): 
            from flask import session
            return session.get('username')
        @property
        def is_authenticated(self):
            from flask import session
            return bool(session.get('username'))
        @property
        def is_admin(self):
            from flask import session
            return session.get('role') == 'admin'
    current_user = _CurrentUserProxy()
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# === DigitalOcean-safe persistence bootstrap ===
def _choose_data_dir():
    path = os.getenv("DATA_DIR", "/var/data")
    try:
        os.makedirs(path, exist_ok=True)
        # test write
        with open(os.path.join(path, ".write_test"), "w") as f:
            f.write("ok")
        os.remove(os.path.join(path, ".write_test"))
    except Exception:
        path = "/tmp/splice-data"
        os.makedirs(path, exist_ok=True)
    return path

DATA_DIR = _choose_data_dir()
DB_FILE  = os.getenv("DATABASE_FILE", "splice.db")
DB_PATH  = os.getenv("DB_PATH", os.path.join(DATA_DIR, DB_FILE))
UPLOAD_FOLDER  = os.getenv("UPLOAD_FOLDER", os.path.join(DATA_DIR, "uploads"))
WORKMAP_FOLDER = os.getenv("WORKMAP_FOLDER", os.path.join(DATA_DIR, "workmaps"))
BACKUP_DIR     = os.path.join(DATA_DIR, "backups")
for _p in (UPLOAD_FOLDER, WORKMAP_FOLDER, BACKUP_DIR):
    os.makedirs(_p, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
max_len_mb = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "20"))
app.config["MAX_CONTENT_LENGTH"] = max_len_mb * 1024 * 1024

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def user_has_access_to_map(user_id, work_map_id):
    with closing(get_db()) as db:
        row = db.execute(
            "SELECT 1 FROM user_work_map_access WHERE user_id=? AND work_map_id=?",
            (user_id, work_map_id)
        ).fetchone()
        return row is not None

def get_user_accessible_maps(user_id):
    with closing(get_db()) as db:
        return db.execute(
            "SELECT wm.* FROM work_maps wm JOIN user_work_map_access a ON a.work_map_id = wm.id WHERE a.user_id=? ORDER BY wm.uploaded_at DESC",
            (user_id,)
        ).fetchall()

def init_db():
    with closing(get_db()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_name TEXT NOT NULL,
                fusion_count INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                FOREIGN KEY(record_id) REFERENCES records(id)
            );
        """)
        cols = db.execute("PRAGMA table_info(users)").fetchall()
        colnames = {c[1] for c in cols}
        if "is_admin" not in colnames:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;")
        db.commit()

    # AUGMENTED: create default admin
    with closing(get_db()) as db:
        cur = db.cursor()
        row = cur.execute("SELECT id FROM users WHERE username=?", ("admin",)).fetchone()
        if not row:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", generate_password_hash("admin123"))
            )
            db.commit()

    

    # AUGMENTED: create default admin
    with closing(get_db()) as db:
        cur = db.cursor()
        row = cur.execute("SELECT id FROM users WHERE username=?", ("admin",)).fetchone()
        if not row:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", generate_password_hash("admin123"))
            )
            db.commit()



    # AUGMENTED: work maps and record status
    with closing(get_db()) as db:
        cur = db.cursor()
        # Create tables if not exist
        cur.execute("""
            CREATE TABLE IF NOT EXISTS work_maps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_work_map_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                work_map_id INTEGER NOT NULL,
                UNIQUE(user_id, work_map_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(work_map_id) REFERENCES work_maps(id)
            );
        """)
        # Add columns to records if missing
        cols = {row[1] for row in cur.execute("PRAGMA table_info(records)").fetchall()}
        if 'status' not in cols:
            cur.execute("ALTER TABLE records ADD COLUMN status TEXT DEFAULT 'draft'")
        if 'work_map_id' not in cols:
            cur.execute("ALTER TABLE records ADD COLUMN work_map_id INTEGER REFERENCES work_maps(id)")
        db.commit()


# === SCHEMA GUARD: ensure required tables/columns exist even on old DBs ===

# ====== Healthcheck & Backup utilities ======
def is_writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        testfile = os.path.join(path, ".write_test")
        with open(testfile, "w") as f:
            f.write("ok")
        os.remove(testfile)
        return True
    except Exception as e:
        try:
            print("Writable check failed for", path, "->", e)
        except Exception:
            pass
        return False
os.makedirs(BACKUP_DIR, exist_ok=True)

def backup_db():
    # Use SQLite online backup API for consistency
    try:
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(BACKUP_DIR, f"app-{ts}.db")
        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(dest)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        print("Backup created ->", dest)
        return dest
    except Exception as e:
        print("Backup failed:", e)
        raise

SCHEMA_OK = False

def ensure_schema():
    global SCHEMA_OK
    if SCHEMA_OK:
        return
    try:
        with closing(get_db()) as db:
            cur = db.cursor()
            # --- Base tables (idempotent)
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_name TEXT,
                fusion_count INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
            # --- Feature tables
            cur.execute("""CREATE TABLE IF NOT EXISTS work_maps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS user_work_map_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                work_map_id INTEGER NOT NULL,
                UNIQUE(user_id, work_map_id)
            )""")
            # --- Add columns to records if missing
            cols = {row[1] for row in cur.execute("PRAGMA table_info(records)").fetchall()}
            if 'status' not in cols:
                cur.execute("ALTER TABLE records ADD COLUMN status TEXT DEFAULT 'draft'")
            if 'work_map_id' not in cols:
                cur.execute("ALTER TABLE records ADD COLUMN work_map_id INTEGER")
            db.commit()
        SCHEMA_OK = True
    except Exception as e:
        print("ensure_schema warning:", e)

try:
    DB_PATH
except NameError:
    DB_PATH = 'database.db'

# === auto_db_init ===
import sqlite3 as _sqlite3

def init_db():
    conn = _sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # maps
    cur.execute("""CREATE TABLE IF NOT EXISTS maps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        is_active INTEGER DEFAULT 1
    );""")
    # devices
    cur.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id INTEGER,
        code TEXT,
        address TEXT,
        ports INTEGER,
        feet INTEGER,
        splicer TEXT,
        status TEXT,
        lat REAL,
        lng REAL,
        created_by TEXT,
        updated_by TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT,
        FOREIGN KEY(map_id) REFERENCES maps(id)
    );""")
    # device_users
    cur.execute("""CREATE TABLE IF NOT EXISTS device_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        username TEXT,
        UNIQUE(device_id, username)
    );""")
    # device_tasks
    cur.execute("""CREATE TABLE IF NOT EXISTS device_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        task_type TEXT NOT NULL,
        notes TEXT,
        status TEXT DEFAULT 'pending',
        created_by TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );""")
    # device_photos
    cur.execute("""CREATE TABLE IF NOT EXISTS device_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        caption TEXT,
        created_by TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );""")
    conn.commit()
    conn.close()

# Run at import time
try:
    init_db()
except Exception as _e:
    # Safe fallback: ignore to avoid crashing startup; routes will try again if needed
    pass


try:
    _ensure_devices_schema()
except Exception:
    pass

@app.route('/admin/devices', methods=['GET','POST'])
@login_required
def admin_devices():
    if not is_admin(current_user):
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if request.method == 'POST':
        code = request.form.get('code')
        map_id = request.form.get('map_id') or None
        address = request.form.get('address')
        ports = request.form.get('ports') or None
        feet = request.form.get('feet') or None
        splicer = request.form.get('splicer')
        status = request.form.get('status')
        lat = request.form.get('lat') or None
        lng = request.form.get('lng') or None
        cur.execute("INSERT INTO devices (map_id, code, address, ports, feet, splicer, status, lat, lng, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (map_id, code, address, ports, feet, splicer, status, lat, lng, current_user.username))
        conn.commit()
    cur.execute("SELECT id, name FROM maps WHERE is_active=1")
    maps = cur.fetchall()
    cur.execute("SELECT id, code, map_id, address, status FROM devices ORDER BY id DESC")
    devices = cur.fetchall()
    conn.close()
    return render_template('admin_devices.html', maps=maps, devices=devices)

@app.route('/map/<int:map_id>')
@login_required
def map_view(map_id):
    return render_template('map_view.html', map_id=map_id)

@app.route('/api/maps/<int:map_id>/devices')
@login_required
def api_devices_for_map(map_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, code, address, ports, feet, splicer, status, lat, lng FROM devices WHERE (map_id=? OR ? IS NULL)", (map_id, map_id))
    rows = cur.fetchall()
    conn.close()
    items = []
    for r in rows:
        items.append(dict(id=r[0], code=r[1], address=r[2], ports=r[3], feet=r[4], splicer=r[5], status=r[6], lat=r[7], lng=r[8]))
    return jsonify(items)

@app.route('/device/<int:device_id>', methods=['GET','POST'])
@login_required
def device_edit(device_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if request.method == 'POST':
        allowed = is_admin(current_user)
        if not allowed:
            cur.execute("SELECT COUNT(*) FROM device_users WHERE device_id=? AND username=?", (device_id, current_user.username))
            allowed = cur.fetchone()[0] > 0
        if not allowed:
            conn.close()
            abort(403)
        fields = ['code','address','ports','feet','splicer','status','lat','lng','map_id']
        updates = ', '.join([f"{f}=?" for f in fields])
        values = [request.form.get(f) for f in fields]
        values.extend([current_user.username, device_id])
        cur.execute(f"UPDATE devices SET {updates}, updated_by=?, updated_at=datetime('now') WHERE id=?", values)
        conn.commit()
    cur.execute("SELECT id, map_id, code, address, ports, feet, splicer, status, lat, lng FROM devices WHERE id=?", (device_id,))
    row = cur.fetchone()
    cur.execute("SELECT id, name FROM maps WHERE is_active=1")
    maps = cur.fetchall()
    cur.execute("SELECT username FROM device_users WHERE device_id=?", (device_id,))
    assigned = [r[0] for r in cur.fetchall()]
    conn.close()
    if not row:
        abort(404)
    device = dict(id=row[0], map_id=row[1], code=row[2], address=row[3], ports=row[4], feet=row[5], splicer=row[6], status=row[7], lat=row[8], lng=row[9])
    return render_template('device_edit.html', device=device, maps=maps, assigned=assigned, tasks=get_tasks(device_id), photos=get_photos(device_id))
@app.route('/admin/devices/<int:device_id>/assign', methods=['POST'])
@login_required
def assign_user_to_device(device_id):
    if not is_admin(current_user):
        abort(403)
    username = request.form.get('username')
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO device_users (device_id, username) VALUES (?,?)", (device_id, username))
    conn.commit()
    conn.close()
    return redirect(url_for('device_edit', device_id=device_id))


# === maps_and_tasks_patch ===
import csv
from io import TextIOWrapper
from flask import send_file


try:
    _ensure_tasks_schema()
except Exception:
    pass

# List maps (id, name) and link to /map/<id>
@app.route('/maps')
@login_required
def list_maps():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, description FROM maps WHERE is_active=1 ORDER BY id DESC")
    maps = cur.fetchall()
    conn.close()
    return render_template('maps.html', maps=maps)

# Device tasks view + quick add from device page
@app.route('/device/<int:device_id>/tasks', methods=['POST'])
@login_required
def device_add_task(device_id):
    # Anyone with edit permission (or admin) can add task
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    allowed = 1 if is_admin(current_user) else 0
    if not allowed:
        cur.execute("SELECT COUNT(*) FROM device_users WHERE device_id=? AND username=?", (device_id, current_user.username))
        allowed = 1 if cur.fetchone()[0] > 0 else 0
    if not allowed:
        conn.close()
        abort(403)
    task_type = request.form.get('task_type')
    notes = request.form.get('notes')
    cur.execute("INSERT INTO device_tasks (device_id, task_type, notes, created_by) VALUES (?,?,?,?)",
                (device_id, task_type, notes, current_user.username))
    conn.commit()
    conn.close()
    return redirect(url_for('device_edit', device_id=device_id))

@app.route('/device/<int:device_id>/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def device_toggle_task(device_id, task_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # permission
    allowed = 1 if is_admin(current_user) else 0
    if not allowed:
        cur.execute("SELECT COUNT(*) FROM device_users WHERE device_id=? AND username=?", (device_id, current_user.username))
        allowed = 1 if cur.fetchone()[0] > 0 else 0
    if not allowed:
        conn.close()
        abort(403)
    # toggle
    cur.execute("SELECT status FROM device_tasks WHERE id=? AND device_id=?", (task_id, device_id))
    row = cur.fetchone()
    if row:
        new_status = 'done' if row[0] != 'done' else 'pending'
        cur.execute("UPDATE device_tasks SET status=? WHERE id=?", (new_status, task_id))
        conn.commit()
    conn.close()
    return redirect(url_for('device_edit', device_id=device_id))

# CSV import on admin devices
@app.route('/admin/devices/import', methods=['POST'])
@login_required
def admin_devices_import():
    if not is_admin(current_user):
        abort(403)
    if 'file' not in request.files:
        flash('Selecione um CSV', 'warning')
        return redirect(url_for('admin_devices'))
    f = request.files['file']
    stream = TextIOWrapper(f.stream, encoding='utf-8')
    reader = csv.DictReader(stream)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    count = 0
    for row in reader:
        code = row.get('code') or row.get('codigo') or row.get('device')
        address = row.get('address')
        ports = row.get('ports')
        feet = row.get('feet')
        splicer = row.get('splicer')
        status = row.get('status')
        lat = row.get('lat') or row.get('latitude')
        lng = row.get('lng') or row.get('longitude')
        map_id = row.get('map_id') or row.get('map')
        cur.execute("INSERT INTO devices (map_id, code, address, ports, feet, splicer, status, lat, lng, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (map_id, code, address, ports, feet, splicer, status, lat, lng, current_user.username))
        count += 1
    conn.commit()
    conn.close()
    flash(f'Importados {count} dispositivos do CSV.', 'success')
    return redirect(url_for('admin_devices'))


# === maps_photos_reports_patch ===
import os, csv, sqlite3, secrets
from flask import send_file, make_response
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

    return render_template('admin_maps.html', maps=maps)

# --- Device photos upload (max 6) ---
@app.route('/device/<int:device_id>/upload', methods=['POST'])
@login_required
def device_upload_photos(device_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # permission: admin or assigned
    allowed = 1 if is_admin(current_user) else 0
    if not allowed:
        cur.execute("SELECT COUNT(*) FROM device_users WHERE device_id=? AND username=?", (device_id, current_user.username))
        allowed = 1 if cur.fetchone()[0] > 0 else 0
    if not allowed:
        conn.close(); abort(403)

    files = request.files.getlist('photos')
    captions = request.form.getlist('captions')
    # count existing
    cur.execute("SELECT COUNT(*) FROM device_photos WHERE device_id=?", (device_id,))
    existing = cur.fetchone()[0]
    remaining = max(0, 6 - existing)
    saved = 0
    for i, f in enumerate(files[:remaining]):
        if f and allowed_file(f.filename):
            filename = secure_filename(f.filename)
            ext = filename.rsplit('.',1)[1].lower()
            newname = f"{device_id}_{secrets.token_hex(6)}.{ext}"
            path = os.path.join(UPLOAD_FOLDER, newname)
            f.save(path)
            caption = captions[i] if i < len(captions) else None
            cur.execute("INSERT INTO device_photos (device_id, filename, caption, created_by) VALUES (?,?,?,?)",
                        (device_id, newname, caption, current_user.username))
            saved += 1
    conn.commit(); conn.close()
    flash(f'Upload concluído: {saved} arquivo(s).', 'success')
    return redirect(url_for('device_edit', device_id=device_id))

@app.route('/device/<int:device_id>/photo/<int:photo_id>/delete', methods=['POST'])
@login_required
def device_delete_photo(device_id, photo_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    allowed = 1 if is_admin(current_user) else 0
    if not allowed:
        cur.execute("SELECT COUNT(*) FROM device_users WHERE device_id=? AND username=?", (device_id, current_user.username))
        allowed = 1 if cur.fetchone()[0] > 0 else 0
    if not allowed:
        conn.close(); abort(403)
    cur.execute("SELECT filename FROM device_photos WHERE id=? AND device_id=?", (photo_id, device_id))
    row = cur.fetchone()
    if row:
        filepath = os.path.join(UPLOAD_FOLDER, row[0])
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass
        cur.execute("DELETE FROM device_photos WHERE id=?", (photo_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('device_edit', device_id=device_id))

# --- Reports by map ---
@app.route('/map/<int:map_id>/report')
@login_required
def map_report(map_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, description FROM maps WHERE id=?", (map_id,))
    map_row = cur.fetchone()
    cur.execute("SELECT id, code, address, ports, feet, splicer, status, lat, lng FROM devices WHERE (map_id=? OR ? IS NULL) ORDER BY id", (map_id, map_id))
    devices = cur.fetchall()
    # totals
    total = len(devices)
    done = 0
    for d in devices:
        st = (d[6] or '').lower()
        if st in ('feito','ok','done','completed','concluido','concluído'):
            done += 1
    pend = total - done
    conn.close()
    return render_template('map_report.html', map_row=map_row, devices=devices, total=total, done=done, pend=pend)

@app.route('/map/<int:map_id>/report.csv')
@login_required
def map_report_csv(map_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM maps WHERE id=?", (map_id,))
    m = cur.fetchone()
    cur.execute("SELECT id, code, address, ports, feet, splicer, status, lat, lng FROM devices WHERE (map_id=? OR ? IS NULL) ORDER BY id", (map_id, map_id))
    rows = cur.fetchall()
    conn.close()
    headers = ['id','code','address','ports','feet','splicer','status','lat','lng']
    import io
    si = io.StringIO()
    si.write('map_id,map_name\n')
    si.write(f"{map_id},{(m[1] if m else '')}\n\n")
    si.write(','.join(headers)+'\n')
    for r in rows:
        line = [str(r[0]), r[1] or '', r[2] or '', str(r[3] or ''), str(r[4] or ''), r[5] or '', r[6] or '', str(r[7] or ''), str(r[8] or '')]
        si.write(','.join([c.replace(',', ' ') for c in line]) + '\n')
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = f'attachment; filename=map_{map_id}_report.csv'
    output.headers['Content-Type'] = 'text/csv'
    return output


# === helpers_tasks_photos ===
import sqlite3 as _sqlite3

def get_tasks(device_id):
    try:
        conn = _sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, task_type, notes, status FROM device_tasks WHERE device_id=? ORDER BY id DESC", (device_id,))
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

def get_photos(device_id):
    try:
        conn = _sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, filename, caption FROM device_photos WHERE device_id=? ORDER BY id DESC", (device_id,))
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

@app.route('/admin/db/init')
@login_required
def admin_db_init():
    if not is_admin(current_user):
        abort(403)
    try:
        init_db()
        flash('Banco verificado/criado com sucesso.', 'success')
    except Exception as e:
        flash(f'Erro ao inicializar DB: {e}', 'danger')
    return redirect(url_for('admin_maps') if 'admin_maps' in globals() else url_for('index'))


# --- Home redirects to dashboard ---


# --- Safe home: dashboard -> login -> plain message ---
@app.route('/')
def home():
    try:
        return redirect(url_for('dashboard'))
    except BuildError:
        try:
            return redirect(url_for('login'))
        except BuildError:
            return "<h3>App online</h3><p>Crie a rota 'dashboard' ou 'login'.</p>", 200

@app.route('/health')
def health():
    return 'ok', 200
