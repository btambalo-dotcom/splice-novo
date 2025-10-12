# -*- coding: utf-8 -*-
from flask import Blueprint, jsonify
import os

monitor_bp = Blueprint('monitor_bp', __name__)

@monitor_bp.get('/healthz.json')
def healthz():
    ok = True
    notes = {}
    try:
        data_dir = os.getenv('DATA_DIR', '/var/data')
        os.makedirs(data_dir, exist_ok=True)
        notes['disk'] = 'ok'
    except Exception as e:
        ok = False
        notes['disk'] = f'error: {e}'
    try:
        db_path = os.getenv('DB_PATH') or os.path.join(os.getenv('DATA_DIR', '/var/data'), os.getenv('DB_FILE','splice.db'))
        if db_path and os.path.exists(db_path):
            notes['db'] = 'ok'
        else:
            notes['db'] = 'missing'
    except Exception as e:
        ok = False
        notes['db'] = f'error: {e}'
    return jsonify({'ok': ok, 'checks': notes})

@monitor_bp.get('/db.json')
def db_info():
    data_dir = os.getenv('DATA_DIR', '/var/data')
    db_file = os.getenv('DB_FILE', 'splice.db')
    db_path = os.getenv('DB_PATH') or os.path.join(data_dir, db_file)
    db_url  = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    return jsonify({
        'DATABASE_FILE': db_file,
        'DATABASE_URL': db_url,
        'DATA_DIR': data_dir,
        'db_exists': bool(db_path and os.path.exists(db_path)),
        'db_path': db_path,
        'dir_listing': [d for d in os.listdir(data_dir) if os.path.isdir(os.path.join(data_dir, d))] if os.path.exists(data_dir) else []
    })
