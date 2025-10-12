# -*- coding: utf-8 -*-
# Ferramentas de persistência para Render.
# - Garante /var/data
# - Define variáveis de ambiente padrão para SQLite
# - Cria o arquivo do banco se não existir
import os, pathlib

def ensure_persist(default_dir='/var/data', default_db='splice.db'):
    try:
        data_dir = os.getenv('DATA_DIR', default_dir)
        db_file = os.getenv('DATABASE_FILE', os.getenv('DB_FILE', default_db))
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, db_file)
        # URLs SQLite comuns
        if db_path.startswith('/'):
            sqlite_url = 'sqlite:///' + db_path
        else:
            sqlite_url = 'sqlite:///' + os.path.abspath(db_path)
        # Popular variáveis comuns usadas por apps Flask
        os.environ.setdefault('DATA_DIR', data_dir)
        os.environ.setdefault('DB_FILE', db_file)
        os.environ.setdefault('DB_PATH', db_path)
        os.environ.setdefault('DATABASE_URL', sqlite_url)
        os.environ.setdefault('SQLALCHEMY_DATABASE_URI', sqlite_url)
        # Cria arquivo do DB se não existir (touch)
        if not os.path.exists(db_path):
            pathlib.Path(db_path).touch()
        return data_dir, db_file, db_path, sqlite_url
    except Exception as e:
        os.environ['SPLICE_PERSIST_ERROR'] = str(e)
        return None, None, None, None
