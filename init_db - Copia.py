
import os, sqlite3
from contextlib import closing
from werkzeug.security import generate_password_hash

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "app.db"))
os.makedirs(DATA_DIR, exist_ok=True)

def get_db():
    return sqlite3.connect(DB_PATH)

with closing(get_db()) as db:
    c=db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_name TEXT,
        fusion_count INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'draft',
        work_map_id INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS work_maps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS user_work_map_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        work_map_id INTEGER NOT NULL,
        UNIQUE(user_id, work_map_id)
    )""")
    if not c.execute("SELECT id FROM users WHERE username=?",( "admin",)).fetchone():
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?,?,1)",
                  ("admin", generate_password_hash("admin123")))
    db.commit()
print("OK: schema criado e admin garantido em", DB_PATH)
